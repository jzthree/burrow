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
            listSSHHosts()
        case "status":
            sshHostStatus(rest)
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

    private func listSSHHosts() {
        let hosts = SSHConfigParser.parse()
        guard !hosts.isEmpty else {
            print("No hosts found in \(SSHConfigParser.defaultConfigURL().path).")
            return
        }
        for host in hosts {
            print("\(host.alias)\t\(sshTarget(host))")
        }
    }

    private func sshHostStatus(_ rest: [String]) {
        let hosts = SSHConfigParser.parse()
        let selected: [SSHConfigHost]
        if let alias = rest.first(where: { !$0.hasPrefix("-") }) {
            selected = hosts.filter { $0.alias == alias }
            if selected.isEmpty {
                print("Host '\(alias)' not found in \(SSHConfigParser.defaultConfigURL().path).")
                return
            }
        } else {
            selected = hosts
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
        guard SSHConfigParser.parse().contains(where: { $0.alias == alias }) else {
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
            try listGateways()
        case "status":
            try gatewayStatus(rest)
        case "help", "-h", "--help":
            print(Self.gatewayHelp)
        default:
            throw CLIError("unknown gateway command '\(sub)'. Try: list, status")
        }
    }

    private func listGateways() throws {
        let config = try store.load()
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
        guard !selected.isEmpty else {
            print("No gateways configured.")
            return
        }
        for gateway in selected {
            let up = PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort)
            print("\(gateway.name)\t\(up ? "up" : "down")\tSOCKS 127.0.0.1:\(gateway.socksPort)")
        }
    }

    // MARK: - 2fa

    func twoFactorCommand(_ arguments: [String]) throws {
        let sub = arguments.first ?? "list"
        switch sub {
        case "list", "ls":
            try listTwoFactor()
        case "help", "-h", "--help":
            print(Self.twoFactorHelp)
        default:
            throw CLIError("unknown 2fa command '\(sub)'. Try: list")
        }
    }

    private func listTwoFactor() throws {
        let config = try store.load()
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
    burrow gateway — VPN gateways (read-only)

      list                 name, protocol/auth, user@server, SOCKS port
      status [NAME]         whether the gateway's local SOCKS port is up

    Connecting a gateway (including SAML browser sign-in) is done in the
    Burrow app; the CLI only inspects them.
    """

    static let twoFactorHelp = """
    burrow 2fa — two-factor accounts (metadata only)

      list                 enrolled accounts and their linked SSH host

    Secrets stay in the macOS Keychain and codes are generated by the app
    (and used automatically when you keep a host warm).
    """
}
