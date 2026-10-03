#!/usr/bin/env bash
# Installs the Sentinel user units: a daily audit plus the dashboard.
# Runs as your own user — no root needed, since Docker access comes from your
# docker group membership.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

echo "building sentinel…"
(cd "$repo" && go build -o sentinel ./cmd/sentinel)

mkdir -p "$units"
for u in sentinel-scan.service sentinel-scan.timer sentinel-web.service; do
  sed "s|%h/Projects/security-bot|$repo|g" "$repo/deploy/$u" > "$units/$u"
  echo "installed $units/$u"
done

systemctl --user daemon-reload
systemctl --user enable --now sentinel-scan.timer
systemctl --user enable --now sentinel-web.service

# Without this, user units stop when you log out.
if ! loginctl show-user "$USER" 2>/dev/null | grep -q 'Linger=yes'; then
  echo
  echo "note: enable lingering so the timer runs while you are logged out:"
  echo "  sudo loginctl enable-linger $USER"
fi

echo
systemctl --user list-timers sentinel-scan.timer --no-pager || true
echo
echo "dashboard: http://127.0.0.1:7777"
