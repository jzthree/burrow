import Foundation

public enum SSHCommandBuilder {
    public static func buildArguments(for tunnel: TunnelConfig) -> [String] {
        var args: [String] = [
            "-N",
            "-o", "ExitOnForwardFailure=yes",
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
        (["/usr/bin/ssh"] + buildArguments(for: tunnel)).joined(separator: " ")
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
        let rawValue = String(option[option.index(after: separatorIndex)...])
        let escapedValue = rawValue
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: " ", with: "\\ ")
            .replacingOccurrences(of: "\t", with: "\\\t")

        return "\(key)=\(escapedValue)"
    }
}
