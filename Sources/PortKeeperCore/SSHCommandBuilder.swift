import Foundation

public enum SSHCommandBuilder {
    public static func buildArguments(for tunnel: TunnelConfig) -> [String] {
        var args: [String] = [
            "-N",
            "-o", "ExitOnForwardFailure=yes",
            // Burrow supervises a foreground ssh. A user's ControlMaster/auto-mux
            // settings (common, plus ControlPersist) make ssh fork to background
            // and a detached master hold the forward — Burrow then sees the
            // parent "exit", retries, and collides with the orphaned listener.
            // Force a dedicated, non-multiplexed connection so the process we
            // launch is the process that owns the tunnel.
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "ServerAliveInterval=\(tunnel.serverAliveInterval)",
            "-o", "ServerAliveCountMax=\(tunnel.serverAliveCountMax)",
            "-p", "\(tunnel.sshPort)",
        ]

        if let identityFile = tunnel.identityFile, !identityFile.isEmpty {
            args.append(contentsOf: ["-i", expandTilde(in: identityFile)])
        }

        if let jumpHost = tunnel.jumpHost, !jumpHost.isEmpty {
            args.append(contentsOf: ["-J", jumpHost])
        }

        for option in tunnel.extraSSHOptions {
            args.append(contentsOf: ["-o", normalizeOption(option)])
        }

        for forward in tunnel.forwards {
            switch forward.kind {
            case .local:
                guard let destinationHost = forward.destinationHost, let destinationPort = forward.destinationPort else {
                    continue
                }
                args.append(contentsOf: ["-L", localOrRemoteSpec(for: forward, destinationHost: destinationHost, destinationPort: destinationPort)])
            case .remote:
                guard let destinationHost = forward.destinationHost, let destinationPort = forward.destinationPort else {
                    continue
                }
                args.append(contentsOf: ["-R", localOrRemoteSpec(for: forward, destinationHost: destinationHost, destinationPort: destinationPort)])
            case .dynamic:
                args.append(contentsOf: ["-D", dynamicSpec(for: forward)])
            }
        }

        args.append(remoteTarget(for: tunnel))
        return args
    }

    public static func render(_ tunnel: TunnelConfig) -> String {
        (["/usr/bin/ssh"] + buildArguments(for: tunnel))
            .map(shellQuote)
            .joined(separator: " ")
    }

    private static func remoteTarget(for tunnel: TunnelConfig) -> String {
        if let user = tunnel.user, !user.isEmpty {
            return "\(user)@\(tunnel.host)"
        }
        return tunnel.host
    }

    private static func localOrRemoteSpec(for forward: ForwardSpec, destinationHost: String, destinationPort: Int) -> String {
        let bindPrefix = forward.bindAddress.map { "\($0):" } ?? ""
        return "\(bindPrefix)\(forward.listenPort):\(destinationHost):\(destinationPort)"
    }

    private static func dynamicSpec(for forward: ForwardSpec) -> String {
        let bindPrefix = forward.bindAddress.map { "\($0):" } ?? ""
        return "\(bindPrefix)\(forward.listenPort)"
    }

    private static func expandTilde(in path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    private static func normalizeOption(_ option: String) -> String {
        guard let separatorIndex = option.firstIndex(of: "=") else {
            return option
        }

        let key = String(option[..<separatorIndex])
        let value = String(option[option.index(after: separatorIndex)...])
        return "\(key)=\(value)"
    }

    private static func shellQuote(_ argument: String) -> String {
        guard !argument.isEmpty else {
            return "''"
        }

        let safeCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-./:=,@%")
        if argument.unicodeScalars.allSatisfy({ safeCharacters.contains($0) }) {
            return argument
        }

        return "'\(argument.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
