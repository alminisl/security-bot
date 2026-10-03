#!/usr/bin/env bash
# Installs Trivy from its official apt repository, pinned to its signing key.
#
# Trivy is what gives Sentinel CVE data: without it the Vulnerability Scanner
# reports itself unavailable and the audit covers configuration only.
#
# Run from a real terminal, since sudo needs a TTY to prompt:
#   sudo bash deploy/install-trivy.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This needs root. Run: sudo bash $0" >&2
  exit 1
fi

keyring=/usr/share/keyrings/trivy.gpg
list=/etc/apt/sources.list.d/trivy.list

echo "==> installing prerequisites"
apt-get install -y --no-install-recommends wget gnupg ca-certificates

echo "==> fetching the Trivy signing key"
tmpkey=$(mktemp)
trap 'rm -f "$tmpkey"' EXIT
wget -qO "$tmpkey" https://get.trivy.dev/deb/public.key
# Fail loudly rather than writing an empty keyring, which would leave apt
# unable to verify the repo and the cause hard to spot later.
if [[ ! -s "$tmpkey" ]]; then
  echo "key download produced an empty file; aborting" >&2
  exit 1
fi
gpg --dearmor < "$tmpkey" > "$keyring"
chmod 0644 "$keyring"

echo "==> adding the repository, pinned to that key"
echo "deb [signed-by=$keyring] https://get.trivy.dev/deb generic main" > "$list"

echo "==> updating package lists"
# Only this repo, so a failure elsewhere does not mask the result.
apt-get update -o Dir::Etc::sourcelist="$list" \
               -o Dir::Etc::sourceparts="-" \
               -o APT::Get::List-Cleanup="0"

echo "==> installing trivy"
apt-get install -y trivy

echo
trivy --version
echo
echo "Done. Trivy is installed and pinned with signed-by, so Sentinel's package"
echo "auditor will not flag it as an unsigned repository."
echo "Next: ./sentinel scan   (the first run downloads a ~700MB CVE database)"
