import Darwin
import Foundation
import PortKeeperCore

@main
struct BurrowCLI {
    static func main() async {
        // Line-buffer stdout even when it's a pipe. Errors go to stderr, which
        // is never buffered, so block buffering prints them *before* the line
        // saying what was being attempted — output that reads backwards.
        setvbuf(stdout, nil, _IOLBF, 0)
        do {
            try await CLI().run(arguments: Array(CommandLine.arguments.dropFirst()))
        } catch let error as CLIError {
            fputs("error: \(error.message)\n", stderr)
            exit(1)
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

struct CLI {
    private let environment: [String: String]
    let store: ConfigStore

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        self.environment = environment
        let configPathOverride = environment["BURROW_CONFIG"] ?? environment["PORTKEEPER_CONFIG"]
        if let configPath = configPathOverride, !configPath.isEmpty {
            let expandedPath = (configPath as NSString).expandingTildeInPath
            self.store = ConfigStore(configURL: URL(fileURLWithPath: expandedPath))
        } else {
            self.store = ConfigStore()
        }
    }

    func run(arguments: [String]) async throws {
        guard let command = arguments.first else {
            printHelp()
            return
        }

        switch command {
        case "help", "--help", "-h":
            printHelp()
        case "version", "--version", "-V":
            print("burrow \(BurrowVersion.current)")
        case "init":
            let url = try store.ensureExists()
            print("Config ready at \(url.path)")
        case "list":
            try listTunnels(json: arguments.contains("--json"))
        case "print-config":
            try printConfig()
        case "sample-config":
            printSampleConfig()
        case "add":
            try addTunnel(arguments: Array(arguments.dropFirst()))
        case "edit":
            try editTunnel(arguments: Array(arguments.dropFirst()))
        case "remove":
            try removeTunnel(arguments: Array(arguments.dropFirst()))
        case "enable":
            try setEnabled(arguments: Array(arguments.dropFirst()), enabled: true)
        case "disable":
            try setEnabled(arguments: Array(arguments.dropFirst()), enabled: false)
        case "run":
            try await runTunnels(arguments: Array(arguments.dropFirst()))
        case "reload":
            try reloadTunnels(arguments: Array(arguments.dropFirst()))
        case "reclaim":
            try reclaimRemotePort(arguments: Array(arguments.dropFirst()))
        case "profile", "profiles":
            try await profileCommand(Array(arguments.dropFirst()))
        case "folder", "folders":
            try foldersCommand(Array(arguments.dropFirst()))
        case "hosts", "host":
            try hostsCommand(Array(arguments.dropFirst()))
        case "gateway", "gateways", "vpn":
            try gatewayCommand(Array(arguments.dropFirst()))
        case "2fa", "totp":
            try twoFactorCommand(Array(arguments.dropFirst()))
        default:
            throw CLIError("unknown command '\(command)'")
        }
    }

    /// What a tunnel's config says next to what its ssh process is actually
    /// doing. A supervisor holds the definition it launched with, so printing
    /// the file alone can state, with total confidence, forwards that no live
    /// process has — which is exactly the failure this column exists to make
    /// visible.
    private struct RuntimeStatus {
        let live: PortKeeperRuntimeRegistry.LiveProcess?
        let drift: [String]

        var label: String {
            guard let live else { return "stopped" }
            let owner: String
            switch live.supervisor {
            case .app: owner = "app"
            case .cli: owner = "cli"
            case .none: owner = "orphan"
            }
            return "\(drift.isEmpty ? "running" : "drift"):\(live.pid)/\(owner)"
        }
    }

    private func runtimeStatus(for tunnel: TunnelConfig) -> RuntimeStatus {
        guard let live = PortKeeperRuntimeRegistry.liveProcess(for: tunnel) else {
            return RuntimeStatus(live: nil, drift: [])
        }
        return RuntimeStatus(
            live: live,
            drift: TunnelDrift.differences(configured: tunnel, liveCommand: live.command)
        )
    }

    private func listTunnels(json: Bool) throws {
        let config = try store.load()
        let statuses = Dictionary(
            uniqueKeysWithValues: config.tunnels.map { ($0.name, runtimeStatus(for: $0)) }
        )
        if json {
            struct Row: Encodable {
                let name: String
                let enabled: Bool
                let host: String
                let user: String?
                let gateway: String?
                let forwards: [String]
                let running: Bool
                let pid: Int?
                let supervisor: String?
                let drift: [String]
            }
            try printJSON(config.tunnels.map { tunnel in
                let status = statuses[tunnel.name]
                return Row(
                    name: tunnel.name,
                    enabled: tunnel.enabled,
                    host: tunnel.host,
                    user: tunnel.user,
                    gateway: tunnel.gateway,
                    forwards: tunnel.forwards.map(renderForward),
                    running: status?.live != nil,
                    pid: status?.live.map { Int($0.pid) },
                    supervisor: status?.live.map { live in
                        switch live.supervisor {
                        case .app: return "app"
                        case .cli: return "cli"
                        case .none: return "none"
                        }
                    },
                    drift: status?.drift ?? []
                )
            })
            return
        }
        if config.tunnels.isEmpty {
            print("No tunnels configured. Use `burrow add ...` or `burrow sample-config`.")
            return
        }

        // One line per tunnel, name first: `burrow list | cut -f1` is how the
        // shell completions enumerate tunnels.
        for tunnel in config.tunnels {
            let enablement = tunnel.enabled ? "enabled" : "disabled"
            let status = statuses[tunnel.name] ?? RuntimeStatus(live: nil, drift: [])
            let forwardList = tunnel.forwards.map(renderForward).joined(separator: ", ")
            var line = "\(tunnel.name)\t\(enablement)\t\(status.label)\t\(tunnel.host)\t\(forwardList)"
            if !status.drift.isEmpty {
                line += "\tdrift: \(status.drift.joined(separator: "; ")) — `burrow reload \(tunnel.name)` applies the config"
            }
            print(line)
        }
    }

    /// Applies the config on disk to tunnels that are already running.
    ///
    /// The app is asked first, because it owns its supervisors and can restart
    /// one without touching the VPN gateway underneath it (restarting the app
    /// to pick up an edit would drop every gateway). A CLI-supervised tunnel is
    /// restarted by ending its ssh: the supervisor re-reads config.json before
    /// each attempt, so it comes back with the new definition. An ssh nothing
    /// supervises is left alone — killing it would just leave it dead.
    private func reloadTunnels(arguments: [String]) throws {
        let config = try store.load()
        let parser = ArgumentParser(arguments: arguments)
        let force = parser.flag("--force")
        let name = arguments.first(where: { !$0.hasPrefix("-") })

        let selected: [TunnelConfig]
        if let name {
            guard let tunnel = config.tunnels.first(where: { $0.name == name }) else {
                throw CLIError("tunnel '\(name)' was not found")
            }
            selected = [tunnel]
        } else {
            selected = config.tunnels
        }

        var reloaded = 0
        var running = 0
        for tunnel in selected {
            guard let live = PortKeeperRuntimeRegistry.liveProcess(for: tunnel) else {
                if name != nil {
                    print("\(tunnel.name) isn't running — start it with `burrow run \(tunnel.name)` or in the app.")
                }
                continue
            }
            running += 1

            switch live.supervisor {
            case .app:
                BurrowReloadSignal.post(tunnel: tunnel.name)
                print("\(tunnel.name): asked the Burrow app to relaunch it (ssh pid \(live.pid))…")
                fflush(stdout)
                if let replacement = waitForReplacement(of: live.pid, tunnel: tunnel, timeout: 10) {
                    print("\(tunnel.name): running the current config (ssh pid \(replacement.pid)).")
                    reloaded += 1
                } else {
                    print("\(tunnel.name): the app didn't relaunch it — ending its ssh so the supervisor reconnects.")
                    fflush(stdout)
                    kill(live.pid, SIGTERM)
                    if let replacement = waitForReplacement(of: live.pid, tunnel: tunnel, timeout: 20) {
                        print("\(tunnel.name): back up (ssh pid \(replacement.pid)).")
                        reloaded += 1
                    } else {
                        print("\(tunnel.name): nothing brought it back. Check the app, or run `burrow run \(tunnel.name)`.")
                    }
                }
            case .cli:
                print("\(tunnel.name): restarting the supervised ssh (pid \(live.pid))…")
                fflush(stdout)
                kill(live.pid, SIGTERM)
                if let replacement = waitForReplacement(of: live.pid, tunnel: tunnel, timeout: 20) {
                    print("\(tunnel.name): running the current config (ssh pid \(replacement.pid)).")
                    reloaded += 1
                } else {
                    print("\(tunnel.name): its supervisor didn't reconnect within 20s — check `burrow list`.")
                }
            case .none:
                guard force else {
                    print("\(tunnel.name): ssh pid \(live.pid) has no supervisor (its parent is gone), so ending it would just leave the tunnel down. Take it over with `burrow run \(tunnel.name) --force`, or pass --force here to end it.")
                    continue
                }
                kill(live.pid, SIGTERM)
                print("\(tunnel.name): ended unsupervised ssh pid \(live.pid). Nothing will restart it — use `burrow run \(tunnel.name)`.")
            }
        }

        if running == 0 && name == nil {
            print("No running tunnels to reload.")
        } else if name == nil {
            print("Reloaded \(reloaded) of \(running) running tunnel(s).")
        }
    }

    /// Polls for the tunnel's ssh to come back as a different process.
    private func waitForReplacement(
        of previousPID: pid_t,
        tunnel: TunnelConfig,
        timeout: TimeInterval
    ) -> PortKeeperRuntimeRegistry.LiveProcess? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            usleep(500_000)
            if let live = PortKeeperRuntimeRegistry.liveProcess(for: tunnel), live.pid != previousPID {
                return live
            }
        }
        return nil
    }

    func printJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let text = String(data: try encoder.encode(value), encoding: .utf8) else {
            throw CLIError("failed to render JSON")
        }
        print(text)
    }

    private func printConfig() throws {
        let config = try store.load()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        guard let text = String(data: data, encoding: .utf8) else {
            throw CLIError("failed to render config")
        }
        print(text)
    }

    private func printSampleConfig() {
        let sample = AppConfig(tunnels: [
            TunnelConfig(
                name: "prod-db",
                host: "bastion.example.com",
                user: "alice",
                identityFile: "~/.ssh/id_ed25519",
                forwards: [
                    ForwardSpec(kind: .local, bindAddress: "127.0.0.1", listenPort: 15432, destinationHost: "127.0.0.1", destinationPort: 5432),
                ]
            )
        ])

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try? encoder.encode(sample)
        print(String(data: data ?? Data(), encoding: .utf8) ?? "{}")
    }

    private func addTunnel(arguments: [String]) throws {
        let parser = ArgumentParser(arguments: arguments)
        let name = try parser.requiredValue(for: "--name")
        let host = try parser.requiredValue(for: "--host")
        let forwards = try parser.values(for: "--local").map(parseLocalForward)
            + parser.values(for: "--remote").map(parseRemoteForward)
            + parser.values(for: "--dynamic").map(parseDynamicForward)

        guard !forwards.isEmpty else {
            throw CLIError("at least one of --local, --remote, or --dynamic is required")
        }

        let tunnel = TunnelConfig(
            name: name,
            host: host,
            user: parser.value(for: "--user"),
            sshPort: try parser.intValue(for: "--port") ?? 22,
            identityFile: parser.value(for: "--identity"),
            jumpHost: parser.value(for: "--jump"),
            forwards: forwards,
            serverAliveInterval: try parser.intValue(for: "--server-alive-interval") ?? 30,
            serverAliveCountMax: try parser.intValue(for: "--server-alive-count-max") ?? 3,
            reconnectDelaySeconds: try parser.intValue(for: "--reconnect-delay") ?? 5,
            enabled: !parser.flag("--disabled"),
            extraSSHOptions: parser.values(for: "--ssh-option")
        )

        try store.upsert(tunnel)
        print("Saved tunnel '\(name)' to \(store.configURL.path)")
    }

    /// Partial update of an existing tunnel: only the flags you pass change.
    /// Pass an empty value ("") to clear an optional field.
    private func editTunnel(arguments: [String]) throws {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw CLIError("usage: burrow edit <name> [--host H] [--user U] [--port N] [--identity PATH] [--jump HOST] [--gateway NAME] [--reconnect-delay N] [--local|--remote|--dynamic SPEC]... [--ssh-option KEY=VALUE]...")
        }
        let parser = ArgumentParser(arguments: Array(arguments.dropFirst()))
        let newForwards = try parser.values(for: "--local").map(parseLocalForward)
            + parser.values(for: "--remote").map(parseRemoteForward)
            + parser.values(for: "--dynamic").map(parseDynamicForward)
        let newOptions = parser.values(for: "--ssh-option")

        let found = try store.mutate { config -> Bool in
            guard let index = config.tunnels.firstIndex(where: { $0.name == name }) else {
                return false
            }
            var tunnel = config.tunnels[index]
            if let host = parser.value(for: "--host"), !host.isEmpty { tunnel.host = host }
            if let user = parser.value(for: "--user") { tunnel.user = user.isEmpty ? nil : user }
            if let port = try parser.intValue(for: "--port") { tunnel.sshPort = port }
            if let identity = parser.value(for: "--identity") { tunnel.identityFile = identity.isEmpty ? nil : identity }
            if let jump = parser.value(for: "--jump") { tunnel.jumpHost = jump.isEmpty ? nil : jump }
            if let gateway = parser.value(for: "--gateway") { tunnel.gateway = gateway.isEmpty ? nil : gateway }
            if let delay = try parser.intValue(for: "--reconnect-delay") { tunnel.reconnectDelaySeconds = delay }
            if !newForwards.isEmpty { tunnel.forwards = newForwards }
            if !newOptions.isEmpty { tunnel.extraSSHOptions = newOptions }
            config.tunnels[index] = tunnel
            return true
        }
        guard found else {
            throw CLIError("tunnel '\(name)' was not found")
        }
        print("Updated tunnel '\(name)'")
    }

    private func removeTunnel(arguments: [String]) throws {
        guard let name = arguments.first, !name.isEmpty else {
            throw CLIError("usage: burrow remove <name>")
        }

        if try store.remove(name: name) {
            print("Removed tunnel '\(name)'")
        } else {
            throw CLIError("tunnel '\(name)' was not found")
        }
    }

    private func setEnabled(arguments: [String], enabled: Bool) throws {
        guard let name = arguments.first, !name.isEmpty else {
            throw CLIError("usage: burrow \(enabled ? "enable" : "disable") <name>")
        }

        let found = try store.mutate { config -> Bool in
            guard let index = config.tunnels.firstIndex(where: { $0.name == name }) else {
                return false
            }
            config.tunnels[index].enabled = enabled
            return true
        }
        guard found else {
            throw CLIError("tunnel '\(name)' was not found")
        }
        print("\(enabled ? "Enabled" : "Disabled") tunnel '\(name)'")
    }

    /// Path to the ssh binary, overridable for tests. Shared by run, reclaim,
    /// and profile run.
    var sshExecutablePath: String {
        environment["BURROW_SSH_EXECUTABLE"] ?? environment["PORTKEEPER_SSH_EXECUTABLE"] ?? "/usr/bin/ssh"
    }

    /// Frees a stale reverse-forward (`-R`) port on a tunnel's remote host by
    /// terminating the process holding it, through the tunnel's own route
    /// (gateway and jump host included). The CLI companion to the app's
    /// reclaim action. `--dry-run` reports the holder without signalling it —
    /// on a shared login node, ending someone's session is a judgment call.
    private func reclaimRemotePort(arguments: [String]) throws {
        guard let name = arguments.first(where: { !$0.hasPrefix("-") }) else {
            throw CLIError("usage: burrow reclaim <name> [--port N] [--dry-run]")
        }
        let parser = ArgumentParser(arguments: arguments)
        let dryRun = parser.flag("--dry-run")
        let config = try store.load()
        guard let configured = config.tunnels.first(where: { $0.name == name }) else {
            throw CLIError("tunnel '\(name)' was not found")
        }
        guard let port = try parser.intValue(for: "--port") ?? RemoteForwardSupport.reverseForwardPort(of: configured) else {
            throw CLIError("tunnel '\(name)' has no reverse (-R) forward — pass --port N to reclaim a specific remote port.")
        }
        // Reach the host the way the tunnel does: a gateway-bound tunnel keeps
        // its route in a ProxyCommand, and dialing the host directly without
        // it fails in a way that reads like the remote refusing the request.
        if let gatewayName = configured.gateway,
           let gateway = config.gateways.first(where: { $0.name == gatewayName }),
           !PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
            throw CLIError("\(name) routes via gateway '\(gatewayName)' but nothing is listening on 127.0.0.1:\(gateway.socksPort). Connect it with `burrow gateway connect \(gatewayName)` or in the Burrow app first.")
        }
        let tunnel = GatewayLinker.applyingGatewayProxy(
            to: try TunnelLaunchPreparer.prepare(configured),
            gateways: config.gateways
        )

        let route = configured.jumpHost.map { "\($0) → " } ?? ""
        print(dryRun
            ? "Checking what holds remote port \(port) on \(route)\(configured.host)…"
            : "Freeing remote port \(port) on \(route)\(configured.host)…")
        // stdout is block-buffered when it isn't a terminal, stderr never is:
        // without this flush the error below prints *before* the line saying
        // what was attempted.
        fflush(stdout)

        let result = RemoteCommandRunner.run(
            arguments: SSHCommandBuilder.remoteExecArguments(
                for: tunnel,
                command: RemoteForwardSupport.freePortCommand(port, dryRun: dryRun)
            ),
            executablePath: sshExecutablePath
        )
        let outcome = RemoteForwardSupport.parseFreePortOutput(
            standardOutput: result.standardOutput,
            standardError: result.standardError
        )
        for holder in outcome.holders {
            print("  held by \(holder)")
        }
        for pid in outcome.unkillable {
            print("  could not signal pid \(pid) (it belongs to another user)")
        }

        switch outcome.status {
        case .unreachable:
            throw CLIError("couldn't reach \(configured.host): \(outcome.detail ?? "no response")")
        case .freed:
            if dryRun {
                print("Nothing is listening on remote port \(port) — it's free to bind.")
            } else {
                print("Freed remote port \(port). Apply it with `burrow reload \(name)`, or start the tunnel.")
            }
        case .busy:
            if dryRun {
                let hint = outcome.holders.isEmpty
                    ? "\(configured.host) wouldn't say what holds it (no lsof/ss/fuser, or the holder is another user's)"
                    : "run `burrow reclaim \(name) --port \(port)` to end it"
                print("Remote port \(port) is in use — \(hint).")
            } else {
                throw CLIError("remote port \(port) on \(configured.host) is still held after SIGTERM and SIGKILL. Free it on the host, or point this tunnel's reverse forward at an unused port. (Until then the tunnel connects without that forward.)")
            }
        case .unverified:
            print("Signalled the holder(s), but \(configured.host) has neither ss nor lsof, so burrow can't confirm the port is free.")
        }
    }

    private func runTunnels(arguments: [String]) async throws {
        let config = try store.load()
        let tunnelName = arguments.first(where: { !$0.hasPrefix("-") })
        let sshExecutablePath = self.sshExecutablePath
        let force = arguments.contains("--force")

        var selected: [TunnelConfig]
        if let tunnelName {
            guard let tunnel = config.tunnels.first(where: { $0.name == tunnelName }) else {
                throw CLIError("tunnel '\(tunnelName)' was not found")
            }
            selected = [GatewayLinker.applyingGatewayProxy(to: try TunnelLaunchPreparer.prepare(tunnel), gateways: config.gateways)]
        } else if arguments.contains("--all") || arguments.first(where: { !$0.hasPrefix("-") }) == nil {
            selected = try config.tunnels.filter(\.enabled).map {
                GatewayLinker.applyingGatewayProxy(to: try TunnelLaunchPreparer.prepare($0), gateways: config.gateways)
            }
        } else {
            throw CLIError("usage: burrow run [--all|<name>] [--detach] [--force]")
        }

        // Two supervisors on one tunnel is not "two chances to stay up": each
        // reclaims — SIGTERMs — the other's ssh before every attempt, and the
        // tunnel flaps until one of them is killed.
        if !force {
            let alreadyRunning = selected.compactMap { tunnel in
                PortKeeperRuntimeRegistry.liveProcess(for: tunnel).map { (tunnel: tunnel, live: $0) }
            }
            if let conflict = alreadyRunning.first, tunnelName != nil {
                let owner: String
                switch conflict.live.supervisor {
                case .app: owner = "the Burrow app is supervising it"
                case .cli: owner = "another `burrow run` is supervising it"
                case .none: owner = "nothing is supervising it"
                }
                throw CLIError("'\(conflict.tunnel.name)' already has a live ssh (pid \(conflict.live.pid)) — \(owner). Use `burrow reload \(conflict.tunnel.name)` to restart it with the current config, or `--force` to take it over.")
            }
            let blocked = Set(alreadyRunning.map(\.tunnel.name))
            for entry in alreadyRunning {
                print("skipping \(entry.tunnel.name): already running as pid \(entry.live.pid).")
            }
            selected.removeAll { blocked.contains($0.name) }
            if selected.isEmpty && !alreadyRunning.isEmpty {
                print("Nothing to start — every enabled tunnel is already running.")
                return
            }
        }

        // Detach only after the checks above, so their errors reach the
        // terminal instead of the background copy's /dev/null.
        if arguments.contains("--detach") || arguments.contains("-d") {
            try detachRun(arguments: arguments)
            return
        }

        try await supervise(
            selected,
            gateways: config.gateways,
            failFastOnGatewayDown: tunnelName != nil,
            sshExecutablePath: sshExecutablePath
        )
    }

    /// Relaunches this same command in the background, in its own session, so
    /// closing the terminal doesn't take the tunnel down with it. Output goes
    /// to a deduplicated, size-capped log rather than the terminal.
    private func detachRun(arguments: [String]) throws {
        let executable = try selfExecutablePath()
        let childArguments = ["run"] + arguments.filter { $0 != "--detach" && $0 != "-d" }
        let logURL = BoundedLogFile.logsDirectory().appendingPathComponent("cli-run.log", isDirectory: false)

        var childEnvironment = environment
        childEnvironment["BURROW_LOG_FILE"] = logURL.path
        let pid = try spawnDetached(
            executable: executable,
            arguments: childArguments,
            environment: childEnvironment
        )

        let what = childArguments.dropFirst().filter { !$0.hasPrefix("-") }.first ?? "--all"
        print("Detached: burrow run \(what) (pid \(pid)).")
        print("Logs:     \(logURL.path)")
        print("Stop it:  kill \(pid)")
    }

    /// The burrow binary currently executing, as an absolute path.
    private func selfExecutablePath() throws -> String {
        let argv0 = CommandLine.arguments.first ?? "burrow"
        if argv0.contains("/") {
            return URL(fileURLWithPath: argv0).standardizedFileURL.path
        }
        for directory in (environment["PATH"] ?? "").split(separator: ":") {
            let candidate = "\(directory)/\(argv0)"
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        throw CLIError("couldn't locate the burrow binary to detach (argv[0] was '\(argv0)'). Invoke it by path, e.g. `.build/release/burrow run NAME --detach`.")
    }

    private func spawnDetached(
        executable: String,
        arguments: [String],
        environment: [String: String]
    ) throws -> pid_t {
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        defer { posix_spawn_file_actions_destroy(&fileActions) }
        // The child logs to its own file; its raw descriptors must not keep
        // the terminal open (or write to it after the user has moved on).
        posix_spawn_file_actions_addopen(&fileActions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&fileActions, 1, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&fileActions, 2, "/dev/null", O_WRONLY, 0)

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // Its own session: no controlling terminal, so the SIGHUP that closing
        // the window sends to the foreground process group never reaches it.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID))

        var processID = pid_t()
        let argv = [executable] + arguments
        let envp = environment.map { "\($0.key)=\($0.value)" }
        let spawnResult = try ForegroundSSHRunner.withCStringArray(argv) { argumentPointers in
            try ForegroundSSHRunner.withCStringArray(envp) { environmentPointers in
                posix_spawn(&processID, executable, &fileActions, &attributes, argumentPointers, environmentPointers)
            }
        }
        guard spawnResult == 0 else {
            throw CLIError("couldn't detach: \(String(cString: strerror(spawnResult)))")
        }
        return processID
    }

    /// Where a detached run sends what it would otherwise print. Both bounds
    /// matter here: a supervisor retries forever, and nobody is watching.
    private var detachedLog: BoundedLogFile? {
        guard let path = environment["BURROW_LOG_FILE"], !path.isEmpty else {
            return nil
        }
        return BoundedLogFile(url: URL(fileURLWithPath: path), label: "burrow.cli-run-log")
    }

    /// Runs a set of already-prepared tunnels: warns (or fails) on a down
    /// gateway, then supervises them until Ctrl-C. Shared by `run` and
    /// `profile run`.
    func supervise(
        _ selected: [TunnelConfig],
        gateways: [GatewayConfig],
        failFastOnGatewayDown: Bool,
        sshExecutablePath: String
    ) async throws {
        for tunnel in selected {
            if let gatewayName = tunnel.gateway,
               let gateway = gateways.first(where: { $0.name == gatewayName }),
               !PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
                let hint = "Start it with `burrow gateway connect \(gatewayName)` or in the Burrow app."
                // A single named tunnel would just fail confusingly inside its
                // ProxyCommand — stop here with the fix. With --all, the other
                // tunnels shouldn't be held hostage; warn and continue.
                if failFastOnGatewayDown {
                    throw CLIError("\(tunnel.name) routes via gateway '\(gatewayName)' but nothing is listening on 127.0.0.1:\(gateway.socksPort). \(hint)")
                }
                print("warning: \(tunnel.name) uses gateway '\(gatewayName)' but nothing is listening on 127.0.0.1:\(gateway.socksPort). \(hint)")
            }
        }

        guard !selected.isEmpty else {
            throw CLIError("no tunnels selected")
        }

        let interactiveMode = selected.count == 1 && isatty(STDIN_FILENO) != 0
        // One instance, shared by every supervisor: the deduplicator's state
        // lives in it, and a per-call instance would suppress nothing.
        let log = detachedLog

        emit("Running \(selected.count) tunnel(s). Press Ctrl-C to stop.", to: log)
        if interactiveMode {
            print("Interactive SSH prompts will use this terminal.")
            try runInteractiveTunnel(selected[0], executablePath: sshExecutablePath)
            return
        }

        let signalHandler = SignalHandler()
        signalHandler.install()

        let runnerTask = Task {
            await withTaskGroup(of: Void.self) { group in
                for tunnel in selected {
                    let reloadDefinition = self.definitionReloader(for: tunnel.name)
                    group.addTask {
                        let supervisor = TunnelSupervisor(
                            tunnel: tunnel,
                            logger: { line in
                                Self.emit(line, source: tunnel.name, to: log)
                            },
                            executablePath: sshExecutablePath,
                            captureOutput: true,
                            configReloader: reloadDefinition
                        )
                        await supervisor.run()
                    }
                }
                await group.waitForAll()
            }
        }

        await signalHandler.waitForSignal()
        runnerTask.cancel()
        await runnerTask.value
    }

    /// A `@Sendable` view of "what does config.json say this tunnel is right
    /// now", prepared and gateway-routed exactly like a fresh launch. A
    /// supervisor calls it before each attempt, so an edit made while it runs
    /// takes effect on the next reconnect instead of waiting for a restart.
    private func definitionReloader(for name: String) -> @Sendable () -> TunnelConfig? {
        let store = self.store
        return {
            guard let config = try? store.load(),
                  let configured = config.tunnels.first(where: { $0.name == name }),
                  let prepared = try? TunnelLaunchPreparer.prepare(configured) else {
                return nil
            }
            return GatewayLinker.applyingGatewayProxy(to: prepared, gateways: config.gateways)
        }
    }

    /// A supervisor line goes to the terminal, or — when detached — to the
    /// bounded log file instead.
    private static func emit(_ line: String, source: String, to log: BoundedLogFile?) {
        guard let log else {
            print(line)
            fflush(stdout)
            return
        }
        // Supervisor lines arrive prefixed "[name] "; the log adds its own tag.
        let prefix = "[\(source)] "
        log.append(source: source, line.hasPrefix(prefix) ? String(line.dropFirst(prefix.count)) : line)
    }

    private func emit(_ line: String, to log: BoundedLogFile?) {
        Self.emit(line, source: "burrow", to: log)
    }

    private func runInteractiveTunnel(_ tunnel: TunnelConfig, executablePath: String) throws {
        var tunnel = tunnel
        let reloadDefinition = definitionReloader(for: tunnel.name)
        while true {
            if let updated = reloadDefinition(), updated != tunnel {
                print("[\(tunnel.name)] config changed on disk — relaunching with the new definition.")
                tunnel = updated
            }
            try PortKeeperRuntimeRegistry.reclaimOwnedProcess(
                for: tunnel,
                executablePath: executablePath
            )
            print("[\(tunnel.name)] starting: \(renderCommand(executablePath: executablePath, tunnel: tunnel))")
            fflush(stdout)

            let exitCode = try ForegroundSSHRunner.run(
                tunnel: tunnel,
                executablePath: executablePath,
                environment: environment
            )

            if exitCode == 130 || exitCode == 143 {
                return
            }

            print("[\(tunnel.name)] ssh exited with code \(exitCode). Reconnecting in \(tunnel.reconnectDelaySeconds)s.")
            fflush(stdout)
            sleep(UInt32(tunnel.reconnectDelaySeconds))
        }
    }

    private func renderCommand(executablePath: String, tunnel: TunnelConfig) -> String {
        ([executablePath] + SSHCommandBuilder.buildArguments(for: tunnel)).joined(separator: " ")
    }

    private func renderForward(_ forward: ForwardSpec) -> String {
        switch forward.kind {
        case .local, .remote:
            let destinationHost = forward.destinationHost ?? "?"
            let destinationPort = forward.destinationPort.map(String.init) ?? "?"
            return "\(forward.kind.rawValue):\(forward.listenPort)->\(destinationHost):\(destinationPort)"
        case .dynamic:
            return "dynamic:\(forward.listenPort)"
        }
    }

    private func parseLocalForward(_ raw: String) throws -> ForwardSpec {
        try parseFixedForward(raw, kind: .local)
    }

    private func parseRemoteForward(_ raw: String) throws -> ForwardSpec {
        try parseFixedForward(raw, kind: .remote)
    }

    private func parseDynamicForward(_ raw: String) throws -> ForwardSpec {
        let parts = raw.split(separator: ":").map(String.init)
        switch parts.count {
        case 1:
            guard let port = Int(parts[0]) else {
                throw CLIError("invalid dynamic forward '\(raw)'")
            }
            return ForwardSpec(kind: .dynamic, listenPort: port)
        case 2:
            guard let port = Int(parts[1]) else {
                throw CLIError("invalid dynamic forward '\(raw)'")
            }
            return ForwardSpec(kind: .dynamic, bindAddress: parts[0], listenPort: port)
        default:
            throw CLIError("invalid dynamic forward '\(raw)'")
        }
    }

    private func parseFixedForward(_ raw: String, kind: ForwardSpec.Kind) throws -> ForwardSpec {
        let parts = raw.split(separator: ":").map(String.init)
        switch parts.count {
        case 3:
            guard let listenPort = Int(parts[0]), let destinationPort = Int(parts[2]) else {
                throw CLIError("invalid forward '\(raw)'")
            }
            return ForwardSpec(kind: kind, listenPort: listenPort, destinationHost: parts[1], destinationPort: destinationPort)
        case 4:
            guard let listenPort = Int(parts[1]), let destinationPort = Int(parts[3]) else {
                throw CLIError("invalid forward '\(raw)'")
            }
            return ForwardSpec(kind: kind, bindAddress: parts[0], listenPort: listenPort, destinationHost: parts[2], destinationPort: destinationPort)
        default:
            throw CLIError("invalid forward '\(raw)'")
        }
    }

    private func printHelp() {
        print(
            """
            burrow

            Commands:
              init
              list [--json]        (also: is it running, and does the live ssh match config?)
              print-config
              sample-config
              version | --version
              add --name NAME --host HOST [--user USER] [--port 22] [--identity PATH] [--jump HOST]
                  [--local [BIND:]LOCAL_PORT:DEST_HOST:DEST_PORT]...
                  [--remote [BIND:]REMOTE_PORT:DEST_HOST:DEST_PORT]...
                  [--dynamic [BIND:]SOCKS_PORT]...
                  [--server-alive-interval 30] [--server-alive-count-max 3]
                  [--reconnect-delay 5] [--ssh-option KEY=VALUE]... [--disabled]
              edit NAME [any of the add flags]   (only passed flags change; "" clears)
              remove NAME
              enable NAME
              disable NAME
              run [--all|NAME] [--detach] [--force]
                  --detach  keep running after the terminal closes, logging to a capped file
                  --force   take over a tunnel something else is already supervising
              reload [NAME]             (apply config edits to a running tunnel, in place)
              reclaim NAME [--port N] [--dry-run]
                                        (free a stale remote -R port on the tunnel's host;
                                         --dry-run only reports what holds it)

            Profiles (named groups of tunnels + gateways):
              profile list [--json]
              profile create --name NAME [--tunnel T]... [--gateway G]...
              profile edit NAME [--tunnel T]... [--gateway G]...
              profile remove NAME
              profile run NAME          (run the profile's tunnels; Ctrl-C to stop)

            Folders (remote dirs mounted locally via FUSE-T sshfs):
              folders list [--json]
              folders add --name NAME --host HOST [--user U] [--remote PATH] [--local PATH] [--jump HOST]
              folders mount NAME | unmount NAME | remove NAME

            SSH hosts (~/.ssh/config):
              hosts list [--json]
              hosts status [ALIAS] [--json]
              hosts add --alias ALIAS --host HOST [--user USER] [--port 22]
              hosts remove ALIAS
              hosts warm ALIAS      (open a persistent master; sign in here)
              hosts cool ALIAS

            VPN gateways:
              gateway list [--json]
              gateway status [NAME] [--json]
              gateway connect NAME  (password auth; SAML needs the app)

            Two-factor accounts (metadata only; codes stay in the app):
              2fa list [--json]

            Config path:
              \(store.configURL.path)
            """
        )
    }
}

struct ArgumentParser {
    private let arguments: [String]

    init(arguments: [String]) {
        self.arguments = arguments
    }

    func value(for key: String) -> String? {
        for index in arguments.indices where arguments[index] == key {
            let valueIndex = arguments.index(after: index)
            if valueIndex < arguments.endIndex {
                return arguments[valueIndex]
            }
        }
        return nil
    }

    func values(for key: String) -> [String] {
        var matches: [String] = []
        for index in arguments.indices where arguments[index] == key {
            let valueIndex = arguments.index(after: index)
            if valueIndex < arguments.endIndex {
                matches.append(arguments[valueIndex])
            }
        }
        return matches
    }

    func requiredValue(for key: String) throws -> String {
        guard let value = value(for: key) else {
            throw CLIError("missing required option \(key)")
        }
        return value
    }

    func intValue(for key: String) throws -> Int? {
        guard let value = value(for: key) else {
            return nil
        }
        guard let intValue = Int(value) else {
            throw CLIError("option \(key) expects an integer")
        }
        return intValue
    }

    func flag(_ key: String) -> Bool {
        arguments.contains(key)
    }
}

final class SignalHandler {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private let signalQueue = DispatchQueue(label: "burrow.signals")
    private var sources: [DispatchSourceSignal] = []

    init() {
        var continuation: AsyncStream<Void>.Continuation?
        self.stream = AsyncStream<Void> { continuation = $0 }
        self.continuation = continuation!
    }

    func install() {
        let continuation = self.continuation
        for signalNumber in [SIGINT, SIGTERM] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: signalQueue)
            source.setEventHandler {
                continuation.yield()
                continuation.finish()
            }
            source.resume()
            sources.append(source)
        }
    }

    func waitForSignal() async {
        for await _ in stream {
            return
        }
    }
}

struct CLIError: Error {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}

private enum ForegroundSSHRunner {
    static func run(
        tunnel: TunnelConfig,
        executablePath: String,
        environment: [String: String]
    ) throws -> Int32 {
        let arguments = [executablePath] + SSHCommandBuilder.buildArguments(for: tunnel)
        let environmentPairs = environment.map { "\($0.key)=\($0.value)" }

        return try withCStringArray(arguments) { argumentPointers in
            try withCStringArray(environmentPairs) { environmentPointers in
                var processID = pid_t()
                let spawnResult = posix_spawn(
                    &processID,
                    executablePath,
                    nil,
                    nil,
                    argumentPointers,
                    environmentPointers
                )

                guard spawnResult == 0 else {
                    throw CLIError("failed to launch ssh: \(String(cString: strerror(spawnResult)))")
                }

                try PortKeeperRuntimeRegistry.recordProcess(processID, for: tunnel.name)
                var status: Int32 = 0
                while waitpid(processID, &status, 0) == -1 {
                    if errno == EINTR {
                        continue
                    }
                    throw CLIError("failed waiting for ssh: \(String(cString: strerror(errno)))")
                }

                try? PortKeeperRuntimeRegistry.clearRecordedProcess(for: tunnel.name, matching: processID)
                return childExitCode(from: status)
            }
        }
    }

    private static func childExitCode(from status: Int32) -> Int32 {
        let terminationSignal = status & 0x7f
        if terminationSignal == 0 {
            return (status >> 8) & 0xff
        }
        return 128 + terminationSignal
    }

    static func withCStringArray<Result>(
        _ values: [String],
        _ body: ([UnsafeMutablePointer<CChar>?]) throws -> Result
    ) throws -> Result {
        let pointers = values.map { strdup($0) }
        defer {
            for pointer in pointers {
                free(pointer)
            }
        }

        var nulTerminatedPointers = pointers
        nulTerminatedPointers.append(nil)
        return try body(nulTerminatedPointers)
    }
}
