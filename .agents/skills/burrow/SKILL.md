---
name: burrow
description: Operate the Burrow SSH tunnel / VPN gateway manager from its `burrow` command-line tool. Use when asked to list, add, remove, enable/disable, or run port-forward tunnels; to manage ~/.ssh/config login hosts or keep a host "warm" (a persistent, pre-authenticated SSH master); or to inspect Burrow's VPN gateways and 2FA accounts from the terminal. The CLI shares one JSON config and the same SSH masters as the Burrow menu-bar app.
---

# Burrow CLI

Burrow is a macOS menu-bar app that manages SSH port-forward tunnels, plain
SSH login hosts, and userspace VPN gateways (openconnect + ocproxy as a local
SOCKS proxy). It also ships a headless `burrow` CLI that shares the **same
config file and the same SSH ControlMaster sockets** as the app, so changes
made either way are visible to the other.

Use the CLI for scripting and headless control. Use the app for anything that
needs a GUI: connecting a VPN gateway (especially SAML browser sign-in),
enrolling 2FA seeds or generating Touch-ID-gated codes, and hiding hosts.

## Invoking the CLI

The `burrow` binary is not installed on `PATH` by default. From the repo:

```sh
# Run directly (rebuilds if needed); everything after `burrow` is CLI args:
swift run burrow hosts list

# Or build a standalone binary and call it:
swift build -c release --product burrow
.build/release/burrow hosts list

# Optional: put it on PATH
ln -sf "$(pwd)/.build/release/burrow" /usr/local/bin/burrow
```

Building requires the Swift 6.3 toolchain (Xcode / Command Line Tools). In this
project's dev environment, prefix builds with `DEVELOPER_DIR=/Applications/Xcode.app`.

Run `burrow` with no arguments (or `burrow help`) for the full command list.

## Config and environment

- **Config file:** `~/Library/Application Support/Burrow/config.json` (tunnels,
  gateways, 2FA account metadata). It is watched live — CLI edits appear in the
  app without a reload.
- `BURROW_CONFIG=/path/to/config.json` — use an alternate config file.
- `BURROW_SSH_EXECUTABLE=/path/to/ssh` — override the ssh binary used by `run`.
- `BURROW_OPENCONNECT` / `BURROW_OCPROXY` — override VPN tool paths (used by the
  app when connecting gateways; the CLI does not start gateways).

## Port-forward tunnels

Tunnels are supervised SSH sessions that hold one or more forwards open.

```sh
burrow init                     # create the config file if missing
burrow list                     # name, enabled/disabled, host, forwards
burrow print-config             # full config as JSON
burrow sample-config            # print an example tunnel config

# Add a tunnel (at least one of --local/--remote/--dynamic is required):
burrow add --name prod-db --host bastion.example.com --user alice \
  --identity ~/.ssh/id_ed25519 \
  --local 15432:127.0.0.1:5432          # [bind:]localPort:destHost:destPort
burrow add --name socks --host jump.example.com --dynamic 1080

burrow enable prod-db
burrow disable prod-db
burrow remove prod-db

# Run tunnels in the foreground (Ctrl-C to stop). A single tunnel on a TTY
# gets interactive SSH prompts; multiple tunnels are supervised in parallel
# with auto-reconnect:
burrow run prod-db
burrow run --all
```

Forward syntax: `--local`/`--remote` take `[bind:]listenPort:destHost:destPort`;
`--dynamic` takes `[bind:]socksPort`. If a tunnel is bound to a VPN gateway,
`run` warns when that gateway's local SOCKS port isn't listening (start it in
the app first).

## SSH hosts (~/.ssh/config)

Plain login hosts from `~/.ssh/config`. Burrow only appends its own hosts
(marked `# Added by Burrow`) and removes them surgically; it never rewrites your
existing config.

```sh
burrow hosts list               # alias -> user@host:port
burrow hosts status [ALIAS]     # which hosts have a live warm master (warm/cold)
burrow hosts add --alias lab-gpu --host gpu.lab.edu --user me --port 22
burrow hosts remove lab-gpu
burrow hosts warm ALIAS         # open a persistent master; sign in in this terminal
burrow hosts cool ALIAS         # close the master
```

### Keep-warm

"Warming" a host opens a background SSH ControlMaster and leaves it
authenticated, so a later `ssh <alias>` (from any terminal or from the app) is
instant and 2FA is entered only once. `burrow hosts warm` runs in the
foreground, so **you complete the password / 2FA / Duo-push prompt right in the
terminal**; after that ssh backgrounds the master.

The master persists only if the host has `ControlMaster auto`, a `ControlPath`,
and `ControlPersist` set in its ssh config (Burrow's own hosts and most managed
hosts do). If not, `warm` reports that no reusable master could be kept and you
should add those options. Warm masters are shared with the Burrow app, so
`hosts status` and the app's flame indicator agree.

## VPN gateways (read-only from the CLI)

```sh
burrow gateway list             # name, protocol/auth, user@server, SOCKS port
burrow gateway status [NAME]    # up/down = is the gateway's local SOCKS port listening
```

Connecting or disconnecting a gateway is done in the Burrow app — SAML gateways
require an interactive browser sign-in the CLI can't perform. The CLI only
inspects gateways and reports whether their SOCKS proxy is currently up.

## Two-factor accounts (metadata only)

```sh
burrow 2fa list                 # enrolled accounts and their linked SSH host
```

TOTP secrets live in the macOS Keychain and codes are generated by the app
(and used automatically when it keeps a host warm). The CLI shows only account
metadata — it never prints or stores secrets. Enroll or delete accounts in the
app.

## What is GUI-only

- Connecting/disconnecting VPN gateways, including SAML browser sign-in.
- Enrolling 2FA seeds and generating Touch-ID-gated codes.
- Hiding/unhiding hosts and the "keep warm" persistence toggle (a display/state
  preference stored by the app; the CLI's `hosts warm`/`cool` are one-shot
  actions on the shared master instead).
