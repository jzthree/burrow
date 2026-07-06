import Foundation
import PortKeeperCore

// CLI surface for the parts of Burrow that live outside port-forward tunnels:
// plain ~/.ssh/config login hosts (including keep-warm), VPN gateways, and 2FA
// accounts. Anything that needs a GUI (SAML browser sign-in, Touch-ID-gated 2FA
// codes) is intentionally read-only here and points back at the app.
extension CLI {
    // MARK: - hosts

    func hostsCommand(_ arguments: [String]) throws {
        let sub = arguments.first ?? "list"
        let rest = Array(arguments.dropFirst())
        switch sub {
        case "list", "ls":
            try listSSHHosts(json: rest.contains("--json"))
        case "status":
            try sshHostStatus(rest)
        case "add":
            try addSSHHost(rest)
        case "remove", "rm":
            try removeSSHHost(rest)
        case "warm":
            try warmSSHHost(rest)
        case "cool":
            try coolSSHHost(rest)
        case "help", "-h", "--help":
            print(Self.hostsHelp)
        default:
            throw CLIError("unknown hosts command '\(sub)'. Try: list, status, add, remove, warm, cool")
        }
    }

    private func listSSHHosts(json: Bool) throws {
        let hosts = SSHConfigParser.parse()
        if json {
            try printJSON(hosts.map { hostRow(for: $0) })
            return
        }
        guard !hosts.isEmpty else {
            print("No hosts found in \(SSHConfigParser.defaultConfigURL().path).")
            return
        }
        for host in hosts {
            print("\(host.alias)\t\(sshTarget(host))")
        }
    }

    private func sshHostStatus(_ rest: [String]) throws {
        let hosts = SSHConfigParser.parse()
        let selected: [SSHConfigHost]
        if let alias = rest.first(where: { !$0.hasPrefix("-") }) {
            selected = hosts.filter { $0.matchesAlias(alias) }
            if selected.isEmpty {
                print("Host '\(alias)' not found in \(SSHConfigParser.defaultConfigURL().path).")
                return
            }
        } else {
            selected = hosts
        }
        if rest.contains("--json") {
            try printJSON(selected.map { hostRow(for: $0, warm: SSHHostWarmer.isWarm(alias: $0.alias)) })
            return
        }
        guard !selected.isEmpty else {
            print("No hosts to check.")
            return
        }
        for host in selected {
            let state = SSHHostWarmer.isWarm(alias: host.alias) ? "warm" : "cold"
            print("\(host.alias)\t\(state)\t\(sshTarget(host))")
        }
    }

    private struct HostRow: Encodable {
        let alias: String
        let host: String
        let user: String?
        let port: Int?
        let warm: Bool?
    }

    private func hostRow(for host: SSHConfigHost, warm: Bool? = nil) -> HostRow {
        HostRow(alias: host.alias, host: host.effectiveHost, user: host.user, port: host.port, warm: warm)
    }

    private func addSSHHost(_ rest: [String]) throws {
        let parser = ArgumentParser(arguments: rest)
        let alias = try parser.requiredValue(for: "--alias")
        let host = try parser.requiredValue(for: "--host")
        let entry = SSHConfigWriter.HostEntry(
            alias: alias,
            hostName: host,
            user: parser.value(for: "--user"),
            port: try parser.intValue(for: "--port")
        )
        try SSHConfigWriter.appendHost(entry)
        print("Added host '\(alias)' to \(SSHConfigParser.defaultConfigURL().path)")
    }

    private func removeSSHHost(_ rest: [String]) throws {
        guard let alias = rest.first(where: { !$0.hasPrefix("-") }) else {
            throw CLIError("usage: burrow hosts remove <alias>")
        }
        try SSHConfigWriter.removeHost(alias: alias)
        print("Removed host '\(alias)' from \(SSHConfigParser.defaultConfigURL().path)")
    }

    private func warmSSHHost(_ rest: [String]) throws {
        guard let alias = rest.first(where: { !$0.hasPrefix("-") }) else {
            throw CLIError("usage: burrow hosts warm <alias>")
        }
        guard SSHConfigParser.parse().contains(where: { $0.matchesAlias(alias) }) else {
            throw CLIError("host '\(alias)' not found in \(SSHConfigParser.defaultConfigURL().path)")
        }
        if SSHHostWarmer.isWarm(alias: alias) {
            print("'\(alias)' is already warm.")
            return
        }
        print("Warming '\(alias)' — complete any password / 2FA prompt below…")
        let status = SSHHostWarmer.warmForeground(alias: alias)
        if status == 0, SSHHostWarmer.isWarm(alias: alias) {
            print("'\(alias)' is warm — `ssh \(alias)` now reuses this master (kept alive by ControlPersist).")
        } else if status == 0 {
            throw CLIError("'\(alias)' authenticated but no reusable master exists — add `ControlMaster auto` / `ControlPersist` to its ssh config.")
        } else {
            throw CLIError("could not warm '\(alias)' (sign-in failed or was cancelled).")
        }
    }

    private func coolSSHHost(_ rest: [String]) throws {
        guard let alias = rest.first(where: { !$0.hasPrefix("-") }) else {
            throw CLIError("usage: burrow hosts cool <alias>")
        }
        SSHHostWarmer.cool(alias: alias)
        print("Cooled '\(alias)' (master closed if one was open).")
    }

    private func sshTarget(_ host: SSHConfigHost) -> String {
        var text = host.user.map { "\($0)@\(host.effectiveHost)" } ?? host.effectiveHost
        if let port = host.port, port != 22 {
            text += ":\(port)"
        }
        return text
    }

    // MARK: - gateway

    func gatewayCommand(_ arguments: [String]) throws {
        let sub = arguments.first ?? "list"
        let rest = Array(arguments.dropFirst())
        switch sub {
        case "list", "ls":
            try listGateways(json: rest.contains("--json"))
        case "status":
            try gatewayStatus(rest)
        case "connect", "up":
            try connectGateway(rest)
        case "help", "-h", "--help":
            print(Self.gatewayHelp)
        default:
            throw CLIError("unknown gateway command '\(sub)'. Try: list, status, connect")
        }
    }

    private func listGateways(json: Bool) throws {
        let config = try store.load()
        if json {
            struct Row: Encodable {
                let name: String
                let vpnProtocol: String
                let auth: String
                let user: String?
                let server: String
                let socksPort: Int
            }
            try printJSON(config.gateways.map {
                Row(
                    name: $0.name,
                    vpnProtocol: $0.vpnProtocol,
                    auth: $0.usesSAML ? "saml" : "password",
                    user: $0.user,
                    server: $0.server,
                    socksPort: $0.socksPort
                )
            })
            return
        }
        guard !config.gateways.isEmpty else {
            print("No gateways configured.")
            return
        }
        for gateway in config.gateways {
            let auth = gateway.usesSAML ? "saml" : "password"
            let user = gateway.user ?? "-"
            print("\(gateway.name)\t\(gateway.vpnProtocol)/\(auth)\t\(user)@\(gateway.server)\tSOCKS :\(gateway.socksPort)")
        }
    }

    private func gatewayStatus(_ rest: [String]) throws {
        let config = try store.load()
        let selected: [GatewayConfig]
        if let name = rest.first(where: { !$0.hasPrefix("-") }) {
            selected = config.gateways.filter { $0.name == name }
            if selected.isEmpty {
                throw CLIError("gateway '\(name)' was not found")
            }
        } else {
            selected = config.gateways
        }
        if rest.contains("--json") {
            struct Row: Encodable {
                let name: String
                let up: Bool
                let socksPort: Int
            }
            try printJSON(selected.map {
                Row(name: $0.name, up: PortProbe.canConnect(host: "127.0.0.1", port: $0.socksPort), socksPort: $0.socksPort)
            })
            return
        }
        guard !selected.isEmpty else {
            print("No gateways configured.")
            return
        }
        for gateway in selected {
            let up = PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort)
            print("\(gateway.name)\t\(up ? "up" : "down")\tSOCKS 127.0.0.1:\(gateway.socksPort)")
        }
    }

    /// Runs openconnect in the foreground for gateways that don't need a
    /// browser: openconnect prompts for the password on this terminal, and
    /// ocproxy exposes the session as the configured SOCKS port. SAML
    /// gateways genuinely need the app's sign-in window.
    private func connectGateway(_ rest: [String]) throws {
        guard let name = rest.first(where: { !$0.hasPrefix("-") }) else {
            throw CLIError("usage: burrow gateway connect <name>")
        }
        let config = try store.load()
        guard let gateway = config.gateways.first(where: { $0.name == name }) else {
            throw CLIError("gateway '\(name)' was not found")
        }
        guard !gateway.usesSAML else {
            throw CLIError("gateway '\(name)' signs in via SAML in a browser — connect it from the Burrow app")
        }
        guard let openconnectPath = GatewayCommandBuilder.openconnectPath() else {
            throw CLIError("openconnect not found. Install it with: brew install openconnect ocproxy")
        }
        guard let ocproxyPath = GatewayCommandBuilder.ocproxyPath() else {
            throw CLIError("ocproxy not found. Install it with: brew install ocproxy")
        }
        if PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
            print("'\(name)' is already up (SOCKS 127.0.0.1:\(gateway.socksPort)).")
            return
        }
        GatewayPortReclaimer.reclaimStaleListeners(port: gateway.socksPort) { print($0) }

        print("Connecting '\(name)' — answer openconnect's prompts below. Ctrl-C disconnects.")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: openconnectPath)
        // .none leaves out --passwd-on-stdin, so openconnect prompts on this tty.
        process.arguments = GatewayCommandBuilder.buildArguments(
            for: gateway,
            ocproxyPath: ocproxyPath,
            credential: .none
        )
        try process.run()
        process.waitUntilExit()
        let code = process.terminationStatus
        // 130/143: the user's own Ctrl-C / SIGTERM — a clean disconnect.
        guard code == 0 || code == 130 || code == 143 else {
            throw CLIError("openconnect exited with code \(code)")
        }
        print("Disconnected '\(name)'.")
    }

    // MARK: - 2fa

    func twoFactorCommand(_ arguments: [String]) throws {
        let sub = arguments.first ?? "list"
        let rest = Array(arguments.dropFirst())
        switch sub {
        case "list", "ls":
            try listTwoFactor(json: rest.contains("--json"))
        case "help", "-h", "--help":
            print(Self.twoFactorHelp)
        default:
            throw CLIError("unknown 2fa command '\(sub)'. Try: list")
        }
    }

    private func listTwoFactor(json: Bool) throws {
        let config = try store.load()
        if json {
            struct Row: Encodable {
                let name: String
                let sshHost: String?
                let digits: Int
                let period: Int
            }
            try printJSON(config.twoFactorAccounts.map {
                Row(name: $0.name, sshHost: $0.sshHost, digits: $0.digits, period: $0.period)
            })
            return
        }
        guard !config.twoFactorAccounts.isEmpty else {
            print("No 2FA accounts enrolled.")
            return
        }
        for account in config.twoFactorAccounts {
            let host = account.sshHost ?? "-"
            print("\(account.name)\tlinked: \(host)\t\(account.digits) digits / \(account.period)s")
        }
    }

    // MARK: - help text

    static let hostsHelp = """
    burrow hosts — plain ~/.ssh/config login hosts

      list                 aliases and their user@host:port
      status [ALIAS]        show which hosts have a live warm master
      add --alias A --host H [--user U] [--port 22]
      remove ALIAS          delete a Burrow-added host (surgical)
      warm ALIAS            open a persistent SSH master; sign in in this
                            terminal so a later `ssh ALIAS` is instant
      cool ALIAS            close the master

    Warm masters are shared with the Burrow app and any terminal — they are
    kept alive by the host's own ControlPersist setting.
    """

    static let gatewayHelp = """
    burrow gateway — VPN gateways

      list [--json]         name, protocol/auth, user@server, SOCKS port
      status [NAME] [--json] whether the gateway's local SOCKS port is up
      connect NAME          run openconnect in this terminal (password auth);
                            Ctrl-C disconnects

    SAML browser sign-in needs the Burrow app; everything else works here.
    """

    static let twoFactorHelp = """
    burrow 2fa — two-factor accounts (metadata only)

      list                 enrolled accounts and their linked SSH host

    Secrets stay in the macOS Keychain and codes are generated by the app
    (and used automatically when you keep a host warm).
    """
}
