#!/usr/bin/env bash
set -euo pipefail

# Shred a staged SSH key on every exit path: normal end, set -e abort, Ctrl-C.
# Without this, an interrupted or failed ssh-add left the key in /dev/shm.
SSH_KEY_TMP=""
cleanup_key() {
  if [[ -n "$SSH_KEY_TMP" && -e "$SSH_KEY_TMP" ]]; then
    shred -u "$SSH_KEY_TMP" 2>/dev/null || rm -f "$SSH_KEY_TMP"
  fi
  SSH_KEY_TMP=""
}
trap cleanup_key EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  echo "  (if unlock fails with 'decryption operation failed':" >&2
  echo "   $BW_CMD logout; export BW_SESSION=\"\$($BW_CMD login --raw)\")" >&2
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
while also wanting them available via aws-vault. Handlers run by mode, in dependency
order, regardless of item order in Bitwarden:
  file -> gpg-import -> ssh-agent -> aws-vault-import
(aws-vault's pass backend needs the GPG key imported first.) A failing item is
reported and the run continues; the script exits non-zero if anything failed.
The --mode filter, when set, runs only that one handler (other modes on
matching items are skipped).
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

FOLDER_ID=$(BW_SESSION="$BW_SESSION" $BW_CMD list folders |
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
  mkdir -p "$(dirname "$path")" || return 1
  printf '%b\n' "$notes" >"$path" || return 1
  chmod "$perm" "$path" || return 1
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
  SSH_KEY_TMP=$(mktemp /dev/shm/.ssh-key.XXXXXX) || {
    echo "  ✗ failed to create tempfile in /dev/shm" >&2
    return 1
  }
  local rc=0
  { chmod 600 "$SSH_KEY_TMP" && printf '%b\n' "$notes" >"$SSH_KEY_TMP"; } || rc=$?
  [[ $rc -eq 0 ]] && { ssh-add "$SSH_KEY_TMP" || rc=$?; }
  cleanup_key
  [[ $rc -eq 0 ]] || return $rc
  echo "  ✓ loaded into ssh-agent"
}

import_gpg() {
  local item="$1" name notes
  name=$(jq -r '.name' <<<"$item")
  notes=$(jq -r '.notes // ""' <<<"$item")

  mkdir -p "$HOME/.gnupg" || return 1
  chmod 700 "$HOME/.gnupg" || return 1

  printf '%b\n' "$notes" | gpg --batch --yes --import || return 1
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

  # Check prerequisites up front. Without this, a missing `pass` made the
  # idempotency check below read "command not found" as "not stored yet".
  local cmd
  for cmd in pass aws-vault; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "  ✗ '$cmd' not installed" >&2
      return 1
    fi
  done
  if [[ ! -f "${PASSWORD_STORE_DIR:-$HOME/.password-store}/.gpg-id" ]]; then
    echo "  ✗ pass store not initialized. Run: pass init <gpg-key-fingerprint>" >&2
    return 1
  fi

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
    aws-vault add --env --no-add-config "$profile" </dev/null || {
    unset access_key_id secret_access_key
    return 1
  }
  unset access_key_id secret_access_key

  echo "  ✓ added to aws-vault (pass: aws-vault/${profile})"
}

# ─── Main loop ────────────────────────────────────────────────────────────────

# Handlers run grouped by mode in dependency order, not in Bitwarden's item
# order: aws-vault-import needs pass, which needs the GPG key from gpg-import.
MODE_ORDER=(file gpg-import ssh-agent aws-vault-import)

# Handler failures are collected rather than aborting, so one bad item doesn't
# stop the rest. Note: set -e is suspended inside a function called with ||,
# so each handler must return non-zero on its own failures.
failed=()

echo "Materializing items from Bitwarden folder 'stateless'..."

mapfile -t ITEMS < <(BW_SESSION="$BW_SESSION" $BW_CMD list items --folderid "$FOLDER_ID" | jq -c '.[]')

# Validate every item's mode field before running anything.
for item in "${ITEMS[@]}"; do
  mode=$(field mode "$item")
  name=$(jq -r '.name' <<<"$item")
  if [[ -z "$mode" ]]; then
    echo "  ✗ $name: no 'mode' field" >&2
    failed+=("$name [no mode]")
    continue
  fi
  IFS=',' read -ra item_modes <<<"$mode"
  for m in "${item_modes[@]}"; do
    m="${m// /}"
    case " ${MODE_ORDER[*]} " in
    *" $m "*) ;;
    *)
      echo "  ✗ $name: unknown mode '$m' in '$mode'" >&2
      failed+=("$name [unknown mode '$m']")
      ;;
    esac
  done
done

for m in "${MODE_ORDER[@]}"; do
  if [[ -n "$MODE_FILTER" && "$m" != "$MODE_FILTER" ]]; then
    continue
  fi
  for item in "${ITEMS[@]}"; do
    mode=$(field mode "$item")
    # Match $m in the comma-separated mode list, tolerating whitespace.
    case ",${mode// /}," in
    *",$m,"*) ;;
    *) continue ;;
    esac
    name=$(jq -r '.name' <<<"$item")

    echo
    echo "▸ $name  [$m]"
    case "$m" in
    file) materialize_file "$item" || failed+=("$name [$m]") ;;
    gpg-import) import_gpg "$item" || failed+=("$name [$m]") ;;
    ssh-agent) load_ssh "$item" || failed+=("$name [$m]") ;;
    aws-vault-import) import_aws_vault "$item" || failed+=("$name [$m]") ;;
    esac
  done
done

echo
if ((${#failed[@]})); then
  echo "Done with ${#failed[@]} failure(s):" >&2
  printf '  ✗ %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "Done."
