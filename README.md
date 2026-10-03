# Sentinel

A security auditor for a self-hosted Docker machine. It inspects your running
containers, the host and the network, rates each area out of 100, and serves the
result as a dashboard. It runs on a schedule and tells you what changed.

Built as a proof of concept against a box running 35 containers across 16
compose projects.

```
sentinel scan      # audit now, print a summary
sentinel serve     # dashboard on http://127.0.0.1:7777
```

## What it checks

Seven agents run on every scan. Each one owns a slice of the system and reports
findings plus suggested actions.

| Agent | What it looks at |
|---|---|
| **Container Auditor** | Privileged mode, Docker socket mounts, writable binds of host paths, host networking, dangerous capabilities, LAN-exposed ports, `no-new-privileges`, root users, memory limits, unpinned tags |
| **Secret Scanner** | Credentials in container environments, compose and `.env` files readable by other local users |
| **Update Watcher** | Local image digests against the registry — without pulling. Knows whether Watchtower already manages a container |
| **Drift Watcher** | Baselines the system and reports change: files appearing in sensitive paths inside containers, image digests swapping under a running container, containers appearing |
| **Vulnerability Scanner** | CVEs in image contents, via Trivy. Optional — reports itself unavailable rather than failing |
| **Machine Auditor** | Pending security updates, reboot-required, unattended-upgrades, firewall, SSH config, Docker daemon config, disk headroom |
| **Network Auditor** | Every listening socket, which are LAN-reachable, unauthenticated services, and newly opened ports since the last scan |

### On "is my system compromised?"

It cannot answer that, and neither can anything else. What the Drift Watcher
does is establish a baseline and report deviation from it: a new binary in
`/usr/bin` inside a container, an image digest that changed when you did not
change it, a port that opened on its own. That catches realistic compromises.
It is not a guarantee, and this README will not pretend otherwise.

## Scoring

Each project, the machine and the network get a rating out of 100. Two
properties were deliberate:

- **Repeat occurrences cost less.** The sixth container mounting the Docker
  socket does not add as much risk as the first. Scoring each equally rated this
  machine at 3/100 and made the number useless.
- **The curve never bottoms out.** Fixing something always moves the rating, so
  it stays a signal rather than a verdict.

Low and informational findings barely move the number. They are there for when
you want them, not to drown the things that matter.

## Reacting fast

The dashboard opens with a **React now** band: critical and high findings only,
newest first. Everything else is below it.

Each finding carries a prepared command. Most are diagnostic — they show you
what to look at. A few are marked safe to apply, and the dashboard will run
those for you if you started it with `--enable-fixes`.

Notifications for new critical and high findings go to `notify-send` and, if you
set `--webhook`, to any JSON endpoint — ntfy, Gotify, Home Assistant:

```sh
sentinel scan --notify --webhook https://ntfy.sh/your-topic
```

Only **new** findings notify. A daily repeat of something you already know about
trains you to ignore the channel.

## The auditor's note

Each scan opens with a few sentences of prose summarising what matters. It is
written by a local [ollama](https://ollama.com) model, so your container
inventory and findings never leave the machine. If ollama is not running, the
scan falls back to a factual summary — it is never a hard dependency.

```sh
sentinel scan --model granite4:micro   # faster
sentinel scan --no-llm                 # skip it
```

## Install

Needs Go 1.22+ and membership of the `docker` group. No root.

```sh
git clone git@github.com:alminisl/security-bot.git
cd security-bot
go build -o sentinel ./cmd/sentinel
./sentinel scan --quick
```

For the daily audit and the dashboard as user services:

```sh
./deploy/install.sh
sudo loginctl enable-linger "$USER"   # so the timer runs while logged out
```

That installs a timer for 05:30 daily (after Watchtower's 04:00 run, so image
updates are reflected) and the dashboard on `127.0.0.1:7777`.

Trivy is optional but it is the single biggest coverage gain — without it there
is no CVE data at all:

```sh
sudo apt-get install -y trivy   # see the suggestion in the dashboard for the repo setup
```

## Exposure

The dashboard is a map of exactly where this machine is weak, so it binds to
`127.0.0.1` and stays there. There is no authentication in the server itself —
do not publish it on the LAN or the internet.

To reach it from another machine, either bind it to this host's Tailscale
address, which is private and authenticated:

```sh
sentinel serve --addr "$(tailscale ip -4 | head -1):7777"
```

or leave it on localhost and tunnel in over SSH:

```sh
ssh -L 7777:localhost:7777 you@your-server   # then open http://localhost:7777
```

`deploy/install.sh` detects a tailnet and offers to bind there for you.

Fixes are disabled unless you pass `--enable-fixes`, and even then the server
only ever runs a command stored on a finding the scan itself produced. A command
sent by a client is ignored.

## Flags

```
scan   --quick       skip registry and CVE checks (seconds, not minutes)
       --json        full scan as JSON
       --notify      alert on new critical and high findings
       --no-llm      skip the written report

serve  --addr        listen address (default 127.0.0.1:7777)
       --enable-fixes   allow applying prepared fixes from the dashboard
       --scan-on-start  audit at startup

both   --state DIR   state directory (default ~/.local/state/sentinel)
       --model NAME  ollama model (default qwen3:4b-instruct)
       --ollama URL  ollama endpoint
       --webhook URL POST alerts here
```

`scan` exits 2 when there are critical findings, so a timer or CI step can react.

## State

JSON under `~/.local/state/sentinel`: the last 60 scans, a ledger of when each
finding was first seen, the drift baseline, and a score history. SQLite would be
a drop-in replacement for `internal/store` if this ever outgrows files.

## Layout

```
cmd/sentinel        CLI
internal/model      findings, severities, scoring
internal/collect    the seven agents
internal/audit      scan orchestration
internal/store      JSON persistence
internal/narrate    ollama report
internal/notify     desktop and webhook sinks
internal/web        dashboard (embedded in the binary)
deploy              systemd units and installer
```

## Status

Proof of concept. Gamification (score streaks, XP) was deliberately dropped in
favour of the plain dashboard; the per-scope rating is a rating, not a game.
