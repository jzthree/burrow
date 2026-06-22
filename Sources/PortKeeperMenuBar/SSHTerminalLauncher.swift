import AppKit
import PortKeeperCore

/// Opens an interactive `ssh` session to a tunnel's host in Terminal, reusing
/// the tunnel's identity, port, jump host, and — when set — its VPN gateway's
/// ProxyCommand, so reaching internal hosts works the same way the tunnel does.
enum SSHTerminalLauncher {
    static func open(tunnel: TunnelConfig, gateways: [GatewayConfig], terminalApp: String = "auto") throws {
        let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: gateways)
        let command = interactiveCommand(for: routed)

        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-ssh-\(tunnel.name.replacingOccurrences(of: "/", with: "-")).command")
        let script = """
        #!/bin/zsh
        echo "Burrow: ssh \(tunnel.host)"
        \(command)
        """
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
        if openScript(scriptURL, terminalApp: terminalApp) {
            return
        }
        NSWorkspace.shared.open(scriptURL)
    }

    private static func openScript(_ scriptURL: URL, terminalApp: String) -> Bool {
        switch terminalApp.lowercased() {
        case "iterm":
            return openScriptInApp(scriptURL, candidates: iTermCandidates)
        case "terminal":
            return openScriptInApp(scriptURL, candidates: terminalCandidates)
        case "default":
            return false
        default:
            return openScriptInApp(scriptURL, candidates: iTermCandidates)
                || openScriptInApp(scriptURL, candidates: terminalCandidates)
        }
    }

    private static let iTermCandidates = [
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/iTerm.app").path,
        "/Applications/iTerm.app",
        "/Applications/iTerm2.app",
    ]

    private static let terminalCandidates = [
        "/System/Applications/Utilities/Terminal.app",
        "/Applications/Utilities/Terminal.app",
    ]

    private static func openScriptInApp(_ scriptURL: URL, candidates: [String]) -> Bool {
        guard let appURL = candidates
            .map(URL.init(fileURLWithPath:))
            .first(where: { FileManager.default.fileExists(atPath: $0.path) }) else {
            return false
        }

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.open([scriptURL], withApplicationAt: appURL, configuration: configuration)
        return true
    }

    /// An interactive ssh command line (no -N, no forwards) for the host.
    static func interactiveCommand(for tunnel: TunnelConfig) -> String {
        var parts = ["/usr/bin/ssh"]
        if tunnel.sshPort != 22 {
            parts += ["-p", String(tunnel.sshPort)]
        }
        if let identity = tunnel.identityFile, !identity.isEmpty {
            parts += ["-i", shellQuote((identity as NSString).expandingTildeInPath)]
        }
        if let jump = tunnel.jumpHost, !jump.isEmpty {
            parts += ["-J", shellQuote(jump)]
        }
        for option in tunnel.extraSSHOptions where option.lowercased().hasPrefix("proxycommand") {
            parts += ["-o", shellQuote(normalizedOption(option))]
        }
        let target = tunnel.user.map { "\($0)@\(tunnel.host)" } ?? tunnel.host
        parts.append(shellQuote(target))
        return parts.joined(separator: " ")
    }

    private static func normalizedOption(_ option: String) -> String {
        guard let eq = option.firstIndex(of: "=") else { return option }
        return "\(option[..<eq])=\(option[option.index(after: eq)...])"
    }

    private static func shellQuote(_ s: String) -> String {
        guard !s.isEmpty else { return "''" }
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-./:=,@%")
        if s.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return s
        }
        return "'\(s.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

}
