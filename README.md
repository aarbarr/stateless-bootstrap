# Stateless Workstation Bootstrap

Recovery procedure for a fresh or replacement workstation. This repo
contains the materialization script and an encrypted private runbook.
The script imports your GPG keys from Bitwarden — once it has run,
you can decrypt the private README and continue.

## Bootstrap

### 0 — System packages

```bash
# Debian-based
sudo apt update && sudo apt install -y \
  git curl wget gnupg pinentry-curses pass openssh-client \
  unzip jq jp zsh neovim podman

# Fedora-based
sudo dnf install -y \
  git curl wget gnupg2 pinentry pass openssh-clients \
  unzip jq jp zsh neovim podman

# Arch-based
sudo pacman -S --needed \
  git curl wget gnupg pinentry pass openssh \
  unzip jq jp zsh neovim podman
```

Install Distrobox via installer script:

``` bash
curl -s https://raw.githubusercontent.com/89luca89/distrobox/main/install | sudo sh
```

Install Bitwarden CLI:

```bash
curl -Lo /tmp/bw.zip 'https://vault.bitwarden.com/download/?app=cli&platform=linux'
unzip /tmp/bw.zip -d /tmp/bw
sudo install -m 0755 /tmp/bw/bw /usr/local/bin/bw
```

### 1 — Clone this repo

```bash
mkdir ~/tmp
git clone https://github.com/aarbarr/stateless-bootstrap.git ~/tmp/stateless-bootstrap
cd ~/tmp/stateless-bootstrap
```

### 3 — Unlock Bitwarden

```bash
bw login
export BW_SESSION="$(bw unlock --raw)"
```

### 4 — Start ssh-agent and set GPG TTY

```bash
# Ensure UTF-8 in minimal environments (noop if already set).
export LANG=C.UTF-8 LC_ALL=C.UTF-8

eval "$(ssh-agent -s)"
export GPG_TTY=$(tty)

# Pre-add GitHub's host key so subsequent SSH clones don't
# interactively prompt for fingerprint acceptance mid-procedure.
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keyscan -t ed25519,rsa github.com >> ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
```

### 5 — Materialize secrets

```bash
./init-from-bitwarden.sh
```

Loads your SSH private key into the agent, imports GPG keys (with
ultimate ownertrust set), and writes `file`-mode items to disk.

### 6 — Decrypt the private runbook

```bash
gpg -d README.private.md.gpg > ~/tmp/runbook.md
less ~/tmp/runbook.md
shred -u ~/tmp/runbook.md
```

You'll be prompted for your GPG passphrase. The decrypted runbook
contains the rest of the recovery procedure that should be followed
from here on.

## Maintenance

### 1 - Decrypting the private README

To edit the runbook, decrypt to a working file:

```bash
gpg -d README.private.md.gpg > README.private.md
```

The plaintext is `.gitignore`d so it can't be accidentally committed.

### 2 - Encrypting the private README

After editing, encrypt to your primary GPG key and remove the plaintext:

```bash
gpg --yes -e README.private.md
```
