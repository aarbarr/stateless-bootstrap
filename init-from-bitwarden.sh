#!/usr/bin/env bash
set -euo pipefail

# ─── Bitwarden CLI detection ──────────────────────────────────────────────────

if command -v bw >/dev/null 2>&1; then
  BW_CMD="bw"
elif command -v flatpak >/dev/null 2>&1 && flatpak info com.bitwarden.desktop >/dev/null 2>&1; then
  BW_CMD="flatpak run --command=bw com.bitwarden.desktop"
else
  echo "Bitwarden CLI not found." >&2
  exit 1
fi

# ─── Login + session checks ───────────────────────────────────────────────────

if ! $BW_CMD login --check >/dev/null 2>&1; then
  echo "Not logged in. Run: $BW_CMD login" >&2
  exit 1
fi

if [[ -z "${BW_SESSION:-}" ]]; then
  echo "BW_SESSION is not set." >&2
  echo "Run: export BW_SESSION=\"\$($BW_CMD unlock --raw)\"" >&2
  exit 1
fi

# ─── CLI args ─────────────────────────────────────────────────────────────────

MODE_FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
  --mode)
    MODE_FILTER="$2"
    shift 2
    ;;
  --help | -h)
    cat <<EOF
Usage: $(basename "$0") [--mode file|ssh-agent|gpg-import|aws-vault-import]

Materialize secrets from the Bitwarden 'stateless' folder onto this workstation.
Each item must have a custom field 'mode' set to one or more (comma-separated) of:
  file               body=notes; requires fields 'path' + 'permissions'
  ssh-agent          body=notes; staged to tmpfs and ssh-add'd
  gpg-import         body=notes; piped into gpg --import
  aws-vault-import   body=notes (aws_access_key_id=... / aws_secret_access_key=...);
                     profile name is taken from the [profile.name] section header
                     in the notes; pushed into aws-vault (pass backend)

Multi-mode example: mode=file,aws-vault-import runs both handlers on the same item.
Useful for AWS credentials that other tooling still expects at the on-disk path,
while also wanting them available via aws-vault. Handlers run in the order listed
in the mode field. The --mode filter, when set, runs only that one handler (other
modes on matching items are skipped).
EOF
    exit 0
    ;;
  *)
    echo "Unknown arg: $1" >&2
    exit 2
    ;;
  esac
done

# ─── Resolve 'stateless' folder ID ────────────────────────────────────────────

FOLDER_ID=$($BW_CMD list folders --session "$BW_SESSION" |
  jq -r '.[] | select(.name=="stateless") | .id')

[[ -n "$FOLDER_ID" ]] || {
  echo "Bitwarden folder 'stateless' not found." >&2
  exit 1
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

field() {
  jq -r --arg n "$1" '(.fields // []) | .[] | select(.name==$n) | .value' <<<"$2"
}

materialize_file() {
  local item="$1" name path perm notes
  name=$(jq -r '.name' <<<"$item")
  path=$(field path "$item")
  perm=$(field permissions "$item")
  notes=$(jq -r '.notes // ""' <<<"$item")

  if [[ -z "$path" || -z "$perm" ]]; then
    echo "  ✗ missing 'path' or 'permissions' field" >&2
    return 1
  fi

  path="${path/#\~/$HOME}"
  mkdir -p "$(dirname "$path")"
  printf '%b\n' "$notes" >"$path"
  chmod "$perm" "$path"
  echo "  ✓ wrote $path ($perm)"
}

load_ssh() {
  local item="$1" name notes ssh_rc=0
  name=$(jq -r '.name' <<<"$item")
  notes=$(jq -r '.notes // ""' <<<"$item")

  ssh-add -l >/dev/null 2>&1 || ssh_rc=$?
  if [[ $ssh_rc -eq 2 ]]; then
    echo "  ✗ no ssh-agent reachable. Start one in your shell first:" >&2
    echo "      eval \"\$(ssh-agent -s)\"" >&2
    return 1
  fi

  # ssh-add reads passphrases from /dev/tty correctly (with echo disabled)
  # only when given a path. Reading the key from stdin breaks the noecho
  # handling in some environments (observed in docker exec). Stage on
  # tmpfs (/dev/shm — RAM-only) and remove immediately after.
  local key_path
  key_path=$(mktemp /dev/shm/.ssh-key.XXXXXX) || {
    echo "  ✗ failed to create tempfile in /dev/shm" >&2
    return 1
  }
  chmod 600 "$key_path"
  printf '%b\n' "$notes" >"$key_path"
  ssh-add "$key_path"
  local rc=$?
  shred -u "$key_path" 2>/dev/null || rm -f "$key_path"
  [[ $rc -eq 0 ]] || return $rc
  echo "  ✓ loaded into ssh-agent"
}

import_gpg() {
  local item="$1" name notes
  name=$(jq -r '.name' <<<"$item")
  notes=$(jq -r '.notes // ""' <<<"$item")

  mkdir -p "$HOME/.gnupg"
  chmod 700 "$HOME/.gnupg"

  printf '%b\n' "$notes" | gpg --batch --yes --import
  echo "  ✓ imported into gpg keyring"

  # Set ultimate ownertrust on every primary secret key in the keyring.
  # gpg --import does NOT restore trustdb.gpg (it's a per-host derived file),
  # so without this step encrypt operations like `pass insert` fail with
  # "Unusable public key — There is no assurance this key belongs to the
  # named user". Decrypt works without trust; encrypt does not.
  local fpr count=0
  while IFS= read -r fpr; do
    [[ -z "$fpr" ]] && continue
    echo "$fpr:6:" | gpg --import-ownertrust 2>/dev/null
    count=$((count + 1))
  done < <(gpg --list-secret-keys --with-colons | awk -F: '
    /^sec:/  { primary=1; next }
    /^ssb:/  { primary=0 }
    /^fpr:/ && primary { print $10; primary=0 }
  ')
  echo "  ✓ set ultimate trust on $count primary key(s)"
}

import_aws_vault() {
  local item="$1" name notes profile access_key_id secret_access_key

  name=$(jq -r '.name' <<<"$item")
  notes=$(jq -r '.notes // ""' <<<"$item")

  # Extract the profile name from the first [section] header in the notes.
  # The Bitwarden notes for AWS credentials items are already in canonical
  # credentials-file format (one [profile.name] section + key=value lines)
  # because the same notes also drive mode=file materialization. The
  # section name IS the profile name — no separate Bitwarden field needed.
  profile=$(awk '
    /^\[[^]]+\]/ {
      sub(/^\[/, ""); sub(/\].*$/, "")
      print; exit
    }
  ' <<<"$notes")

  if [[ -z "$profile" ]]; then
    echo "  ✗ no [section] header in notes; profile name cannot be determined" >&2
    return 1
  fi

  # Idempotency: skip if entry is already in pass. aws-vault `add` errors
  # on existing profiles (no --update flag), so checking pass first avoids
  # noisy failures on re-run. To rotate keys: `pass rm aws-vault/<profile>`
  # then re-run.
  if pass show "aws-vault/${profile}" >/dev/null 2>&1; then
    echo "  • already in pass (aws-vault/${profile}), skipping"
    return 0
  fi

  # Parse keys from notes. Accept either the canonical credentials-file
  # format (with [section] header — same content as the old mode=file
  # path uses) or a bare key=value format. Section headers are ignored;
  # we take the first matching keys.
  access_key_id=$(awk '
    /^[[:space:]]*aws_access_key_id[[:space:]]*=/ {
      sub(/^[[:space:]]*aws_access_key_id[[:space:]]*=[[:space:]]*/, "")
      sub(/[[:space:]]+$/, "")
      print; exit
    }
  ' <<<"$notes")
  secret_access_key=$(awk '
    /^[[:space:]]*aws_secret_access_key[[:space:]]*=/ {
      sub(/^[[:space:]]*aws_secret_access_key[[:space:]]*=[[:space:]]*/, "")
      sub(/[[:space:]]+$/, "")
      print; exit
    }
  ' <<<"$notes")

  if [[ -z "$access_key_id" || -z "$secret_access_key" ]]; then
    echo "  ✗ aws_access_key_id and/or aws_secret_access_key not found in notes" >&2
    return 1
  fi

  # Push to aws-vault non-interactively. Values flow via env vars only
  # (read by aws-vault internally) — never argv. Stdin closed as
  # belt-and-suspenders in case aws-vault decides to prompt despite the
  # env vars being set.
  AWS_ACCESS_KEY_ID="$access_key_id" \
    AWS_SECRET_ACCESS_KEY="$secret_access_key" \
    aws-vault add --env --no-add-config "$profile" </dev/null
  unset access_key_id secret_access_key

  echo "  ✓ added to aws-vault (pass: aws-vault/${profile})"
}

# ─── Main loop ────────────────────────────────────────────────────────────────

echo "Materializing items from Bitwarden folder 'stateless'..."

while IFS= read -r item; do
  mode=$(field mode "$item")
  name=$(jq -r '.name' <<<"$item")

  # Item-level filter: skip the item entirely if MODE_FILTER (when set) isn't
  # in its comma-separated mode list. Tolerates whitespace around the commas.
  if [[ -n "$MODE_FILTER" ]]; then
    case ",${mode// /}," in
    *",${MODE_FILTER},"*) ;;
    *) continue ;;
    esac
  fi

  echo
  echo "▸ $name  [mode=${mode:-?}]"

  if [[ -z "$mode" ]]; then
    echo "  ✗ no 'mode' field" >&2
    exit 1
  fi

  # Dispatch each comma-separated mode handler in order. Per-mode filter:
  # when MODE_FILTER is set, only run that specific handler.
  IFS=',' read -ra item_modes <<<"$mode"
  for m in "${item_modes[@]}"; do
    m="${m// /}"
    if [[ -n "$MODE_FILTER" && "$m" != "$MODE_FILTER" ]]; then
      continue
    fi
    case "$m" in
    file) materialize_file "$item" ;;
    ssh-agent) load_ssh "$item" ;;
    gpg-import) import_gpg "$item" ;;
    aws-vault-import) import_aws_vault "$item" ;;
    *)
      echo "  ✗ unknown mode '$m' in '$mode'" >&2
      exit 1
      ;;
    esac
  done
done < <($BW_CMD list items --folderid "$FOLDER_ID" --session "$BW_SESSION" | jq -c '.[]')

echo "Done."
