import Foundation

public enum TunnelLaunchPreparer {
    public static func prepare(
        _ tunnel: TunnelConfig,
        fileManager: FileManager = .default
    ) throws -> TunnelConfig {
        let knownHostsDirectory = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent("burrow", isDirectory: true)
        try fileManager.createDirectory(at: knownHostsDirectory, withIntermediateDirectories: true)

        let defaultKnownHostsPath = knownHostsDirectory
            .appendingPathComponent("\(tunnel.name).known_hosts")
            .path

        var updatedOptions: [String] = []
        var sawKnownHosts = false
        var sawStrictChecking = false

        for option in tunnel.extraSSHOptions {
            // Drop options that make ssh exit right after connecting, which
            // breaks a persistent forward (the supervisor sees a clean exit and
            // reconnects forever). These come from legacy PortKeeper
            // "connection test" configs: a LocalCommand that prints and quits.
            let lowered = option.lowercased()
            if lowered.hasPrefix("localcommand=") || lowered.hasPrefix("permitlocalcommand=") {
                continue
            }
            if option.hasPrefix("UserKnownHostsFile=") {
                let candidatePath = String(option.dropFirst("UserKnownHostsFile=".count))
                    .replacingOccurrences(of: "\"", with: "")
                let finalPath = fileManager.fileExists(atPath: candidatePath) ? candidatePath : defaultKnownHostsPath
                updatedOptions.append("UserKnownHostsFile=\(finalPath)")
                sawKnownHosts = true
            } else if option == "StrictHostKeyChecking=ask" {
                updatedOptions.append("StrictHostKeyChecking=accept-new")
                sawStrictChecking = true
            } else {
                updatedOptions.append(option)
            }
        }

        if !sawKnownHosts {
            updatedOptions.append("UserKnownHostsFile=\(defaultKnownHostsPath)")
        }
        if !sawStrictChecking && !updatedOptions.contains(where: { $0.hasPrefix("StrictHostKeyChecking=") }) {
            updatedOptions.append("StrictHostKeyChecking=accept-new")
        }

        return TunnelConfig(
            name: tunnel.name,
            host: tunnel.host,
            user: tunnel.user,
            sshPort: tunnel.sshPort,
            identityFile: tunnel.identityFile,
            jumpHost: tunnel.jumpHost,
            displayGroup: tunnel.displayGroup,
            forwards: tunnel.forwards,
            serverAliveInterval: tunnel.serverAliveInterval,
            serverAliveCountMax: tunnel.serverAliveCountMax,
            reconnectDelaySeconds: tunnel.reconnectDelaySeconds,
            enabled: tunnel.enabled,
            extraSSHOptions: updatedOptions,
            gateway: tunnel.gateway,
            onConnect: tunnel.onConnect,
            onDisconnect: tunnel.onDisconnect
        )
    }
}
