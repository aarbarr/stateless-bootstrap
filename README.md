# Stateless Workstation Bootstrap

Recovery procedure for a fresh or replacement workstation. This repo
contains the materialization script and an encrypted private runbook.
The script imports your GPG keys from Bitwarden — once it has run,
you can decrypt the private README and continue.

## Bootstrap

### 1 — Clone this repo

```bash
mkdir -p ~/tmp
git clone https://github.com/aarbarr/stateless-bootstrap.git ~/tmp/stateless-bootstrap
cd ~/tmp/stateless-bootstrap
```

### 2 — Install tools and run the Bitwarden import

```bash
brew update && brew install bitwarden-cli pass aws-vault
bw logout
export BW_SESSION="$(bw login --raw)"
./init-from-bitwarden.sh
```

### 3 — Decrypt the private runbook

```bash
gpg README.private.md.gpg
```

You'll be prompted for your GPG passphrase. The decrypted runbook
contains the rest of the recovery procedure that should be followed
from here on out.

## Maintenance

### 1 — Decrypting the private README

To edit the runbook, decrypt to a working file:

```bash
gpg README.private.md.gpg
```

The plaintext is `.gitignore`d so it can't be accidentally committed.

### 2 — Encrypting the private README

After editing, encrypt to your primary GPG key and remove the plaintext:

```bash
gpg --yes -e README.private.md
rm README.private.md
```
