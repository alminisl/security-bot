#!/usr/bin/env bash
# Installs the Sentinel user units: a daily audit plus the dashboard.
# Runs as your own user — no root needed, since Docker access comes from your
# docker group membership.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

echo "building sentinel…"
(cd "$repo" && go build -o sentinel ./cmd/sentinel)

# If this host is on a tailnet, offer to bind the dashboard there so it is
# reachable from your other devices without exposing it to the LAN.
addr="${SENTINEL_ADDR:-}"
if [[ -z "$addr" ]] && command -v tailscale >/dev/null 2>&1; then
  ts_ip="$(tailscale ip -4 2>/dev/null | head -1 || true)"
  if [[ -n "$ts_ip" ]]; then
    echo
    echo "this host is on a tailnet as $ts_ip"
    read -r -p "bind the dashboard to the tailnet instead of localhost? [y/N] " yn
    [[ "$yn" =~ ^[Yy]$ ]] && addr="$ts_ip:7777"
  fi
fi
addr="${addr:-127.0.0.1:7777}"

mkdir -p "$units"
for u in sentinel-scan.service sentinel-scan.timer sentinel-web.service; do
  sed -e "s|%h/Projects/security-bot|$repo|g" \
      -e "s|^Environment=SENTINEL_ADDR=.*|Environment=SENTINEL_ADDR=$addr|" \
      "$repo/deploy/$u" > "$units/$u"
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
echo "dashboard: http://$addr"
