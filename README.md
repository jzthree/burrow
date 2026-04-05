# PortKeeper

`portkeeper` is a macOS-first SSH tunnel manager with:

- a central saved config in `~/Library/Application Support/PortKeeper/config.json`
- a CLI to add, list, enable, disable, and run tunnels
- a native menu-bar app for start, stop, restart, reload, and config access
- automatic reconnect when `ssh` exits
- a core Swift module that can be reused by a future SwiftUI menu-bar app

## Quick start

```bash
cd /Users/jianzhou/Code/portkeeper
swift build
.build/debug/portkeeper init
.build/debug/portkeeper add \
  --name prod-db \
  --host bastion.example.com \
  --user alice \
  --identity ~/.ssh/id_ed25519 \
  --local 127.0.0.1:15432:127.0.0.1:5432
.build/debug/portkeeper list
.build/debug/portkeeper run prod-db
.build/debug/PortKeeper
```

Use `Ctrl-C` to stop the supervisor. While running, `portkeeper` will restart the SSH session after failures using the tunnel's configured reconnect delay.

## Forward syntax

- Local: `[bind_address:]local_port:dest_host:dest_port`
- Remote: `[bind_address:]remote_port:dest_host:dest_port`
- Dynamic SOCKS: `[bind_address:]socks_port`

## Example config

```json
{
  "tunnels": [
    {
      "enabled": true,
      "extraSSHOptions": [],
      "forwards": [
        {
          "bindAddress": "127.0.0.1",
          "destinationHost": "127.0.0.1",
          "destinationPort": 5432,
          "kind": "local",
          "listenPort": 15432
        }
      ],
      "host": "bastion.example.com",
      "identityFile": "~/.ssh/id_ed25519",
      "jumpHost": null,
      "name": "prod-db",
      "reconnectDelaySeconds": 5,
      "serverAliveCountMax": 3,
      "serverAliveInterval": 30,
      "sshPort": 22,
      "user": "alice"
    }
  ],
  "version": 1
}
```

## Menu-bar app

Run:

```bash
cd /Users/jianzhou/Code/portkeeper
swift run PortKeeper
```

The app sits in the macOS top bar and can:

- auto-start enabled tunnels on launch
- start, stop, and restart individual tunnels
- reload config after CLI edits
- open or reveal the shared config file

Install as a real app bundle:

```bash
cd /Users/jianzhou/Code/portkeeper
./scripts/install-app.sh
open ~/Applications/PortKeeper.app
```

That installs `~/Applications/PortKeeper.app` with a stable bundle identifier and signs it. On this machine, where no code-signing identity is configured, the install script uses ad-hoc signing by default. That is still a better fit for Keychain access than `swift run`, because the app path and bundle metadata remain stable between launches. If you later install a persistent signing identity, reuse the same script with `SIGNING_IDENTITY="..."`.

Generate an Xcode project:

```bash
cd /Users/jianzhou/Code/portkeeper
./scripts/generate-xcodeproj.rb
open PortKeeper.xcodeproj
```

The generated Xcode project contains:

- a `PortKeeper` macOS app target
- a `PortKeeperCore` framework target
- a shared `PortKeeper` scheme
- bundle identifier `com.jianzhou.portkeeper`

The project is configured for automatic signing, but you still need to select your team and signing identity inside Xcode.

## Architecture

The current split is deliberate:

- `PortKeeperCore` owns config parsing and SSH process supervision.
- The CLI is a thin wrapper around that core.
- The menu-bar app reuses the same store and supervisor to show status and offer manual reconnect controls.
