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
            args.append(contentsOf: ["-o", option])
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
            .map(ShellQuoting.quote)
            .joined(separator: " ")
    }

    /// ssh arguments to run a single command on the tunnel's host — same
    /// endpoint, route, identity, and port as the tunnel, but no forwards and
    /// no `-N`. Used to reach the remote for maintenance (e.g. freeing a stale
    /// reverse-forward port).
    ///
    /// The tunnel's extra options come along because the route can live in
    /// them: a gateway-bound tunnel carries its ProxyCommand there, and
    /// without it this dials the host directly — which, for a host only
    /// reachable through the VPN, fails in a way that looks like the remote
    /// refusing the request. They come last so they win over the defaults
    /// below (a tunnel that must ask for a passphrase can turn BatchMode off).
    public static func remoteExecArguments(for tunnel: TunnelConfig, command: String) -> [String] {
        var args: [String] = [
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=20",
            "-p", "\(tunnel.sshPort)",
        ]
        if let identityFile = tunnel.identityFile, !identityFile.isEmpty {
            args.append(contentsOf: ["-i", expandTilde(in: identityFile)])
        }
        if let jumpHost = tunnel.jumpHost, !jumpHost.isEmpty {
            args.append(contentsOf: ["-J", jumpHost])
        }
        for option in tunnel.extraSSHOptions {
            args.append(contentsOf: ["-o", option])
        }
        args.append(remoteTarget(for: tunnel))
        args.append(command)
        return args
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

}
