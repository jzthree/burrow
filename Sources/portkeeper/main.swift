import Darwin
import Foundation
import PortKeeperCore

@main
struct BurrowCLI {
    static func main() async {
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
    private let store: ConfigStore

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
        case "init":
            let url = try store.ensureExists()
            print("Config ready at \(url.path)")
        case "list":
            try listTunnels()
        case "print-config":
            try printConfig()
        case "sample-config":
            printSampleConfig()
        case "add":
            try addTunnel(arguments: Array(arguments.dropFirst()))
        case "remove":
            try removeTunnel(arguments: Array(arguments.dropFirst()))
        case "enable":
            try setEnabled(arguments: Array(arguments.dropFirst()), enabled: true)
        case "disable":
            try setEnabled(arguments: Array(arguments.dropFirst()), enabled: false)
        case "run":
            try await runTunnels(arguments: Array(arguments.dropFirst()))
        default:
            throw CLIError("unknown command '\(command)'")
        }
    }

    private func listTunnels() throws {
        let config = try store.load()
        if config.tunnels.isEmpty {
            print("No tunnels configured. Use `burrow add ...` or `burrow sample-config`.")
            return
        }

        for tunnel in config.tunnels {
            let status = tunnel.enabled ? "enabled" : "disabled"
            let forwardList = tunnel.forwards.map(renderForward).joined(separator: ", ")
            print("\(tunnel.name)\t\(status)\t\(tunnel.host)\t\(forwardList)")
        }
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

        var config = try store.load()
        guard let index = config.tunnels.firstIndex(where: { $0.name == name }) else {
            throw CLIError("tunnel '\(name)' was not found")
        }

        config.tunnels[index].enabled = enabled
        try store.save(config)
        print("\(enabled ? "Enabled" : "Disabled") tunnel '\(name)'")
    }

    private func runTunnels(arguments: [String]) async throws {
        let config = try store.load()
        let tunnelName = arguments.first(where: { !$0.hasPrefix("-") })
        let sshExecutablePath = environment["BURROW_SSH_EXECUTABLE"] ?? environment["PORTKEEPER_SSH_EXECUTABLE"] ?? "/usr/bin/ssh"

        let selected: [TunnelConfig]
        if let tunnelName {
            guard let tunnel = config.tunnels.first(where: { $0.name == tunnelName }) else {
                throw CLIError("tunnel '\(tunnelName)' was not found")
            }
            selected = [try TunnelLaunchPreparer.prepare(tunnel)]
        } else if arguments.contains("--all") || arguments.isEmpty {
            selected = try config.tunnels.filter(\.enabled).map { try TunnelLaunchPreparer.prepare($0) }
        } else {
            throw CLIError("usage: burrow run [--all|<name>]")
        }

        guard !selected.isEmpty else {
            throw CLIError("no tunnels selected")
        }

        let interactiveMode = selected.count == 1 && isatty(STDIN_FILENO) != 0

        print("Running \(selected.count) tunnel(s). Press Ctrl-C to stop.")
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
                    group.addTask {
                        let supervisor = TunnelSupervisor(
                            tunnel: tunnel,
                            logger: { line in
                                print(line)
                                fflush(stdout)
                            },
                            executablePath: sshExecutablePath,
                            captureOutput: true
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

    private func runInteractiveTunnel(_ tunnel: TunnelConfig, executablePath: String) throws {
        while true {
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
              list
              print-config
              sample-config
              add --name NAME --host HOST [--user USER] [--port 22] [--identity PATH] [--jump HOST]
                  [--local [BIND:]LOCAL_PORT:DEST_HOST:DEST_PORT]...
                  [--remote [BIND:]REMOTE_PORT:DEST_HOST:DEST_PORT]...
                  [--dynamic [BIND:]SOCKS_PORT]...
                  [--server-alive-interval 30] [--server-alive-count-max 3]
                  [--reconnect-delay 5] [--ssh-option KEY=VALUE]... [--disabled]
              remove NAME
              enable NAME
              disable NAME
              run [--all|NAME]

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

    private static func withCStringArray<Result>(
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
