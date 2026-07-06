import Foundation
import PortKeeperCore

/// Runs a tunnel's lifecycle hook commands (fire-and-forget) with context in
/// the environment, so users can mount an sshfs path, send a desktop ping,
/// kick a sync, etc. on connect/disconnect.
enum HookRunner {
    enum Event: String {
        case connected
        case disconnected
    }

    static func run(
        _ command: String?,
        event: Event,
        tunnel: TunnelConfig,
        onFailure: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        guard let command, !command.trimmingCharacters(in: .whitespaces).isEmpty else {
            return
        }

        var env = ProcessInfo.processInfo.environment
        env["BURROW_EVENT"] = event.rawValue
        env["BURROW_TUNNEL"] = tunnel.name
        env["BURROW_HOST"] = tunnel.host
        if let user = tunnel.user { env["BURROW_USER"] = user }
        if let first = tunnel.forwards.first {
            env["BURROW_LOCAL_PORT"] = String(first.listenPort)
            if let dh = first.destinationHost { env["BURROW_DEST_HOST"] = dh }
            if let dp = first.destinationPort { env["BURROW_DEST_PORT"] = String(dp) }
        }
        if let gateway = tunnel.gateway { env["BURROW_GATEWAY"] = gateway }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]
        process.environment = env
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        // Fire-and-forget, but not silent: a hook that fails to launch or
        // exits nonzero should say so instead of leaving the user to wonder
        // why their mount/ping/sync never happened.
        let label = "\(event.rawValue) hook for \(tunnel.name)"
        process.terminationHandler = { finished in
            if finished.terminationStatus != 0 {
                onFailure("\(label) exited with code \(finished.terminationStatus).")
            }
        }
        do {
            try process.run()
        } catch {
            onFailure("\(label) failed to launch: \(error.localizedDescription)")
        }
    }
}
