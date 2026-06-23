import AppKit
import Darwin
import PortKeeperCore

/// Opens an interactive `ssh` session to a tunnel's host in Terminal, reusing
/// the tunnel's identity, port, jump host, and — when set — its VPN gateway's
/// ProxyCommand, so reaching internal hosts works the same way the tunnel does.
enum SSHTerminalLauncher {
    struct OneTimeCode {
        let accountName: String
        let currentCode: String
        let nextCode: String
        let periodEnd: Date
    }

    static func open(
        tunnel: TunnelConfig,
        gateways: [GatewayConfig],
        terminalApp: String = "auto",
        oneTimeCode: OneTimeCode? = nil
    ) throws {
        let route = interactiveRoute(for: tunnel, gateways: gateways)
        let command = interactiveCommand(for: route.tunnel)

        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-ssh-\(tunnel.name.replacingOccurrences(of: "/", with: "-")).command")
        let script = scriptText(tunnel: tunnel, command: command, oneTimeCode: oneTimeCode, routeMessage: route.message)
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
        if openScript(scriptURL, terminalApp: terminalApp) {
            return
        }
        NSWorkspace.shared.open(scriptURL)
    }

    private static func scriptText(
        tunnel: TunnelConfig,
        command: String,
        oneTimeCode: OneTimeCode?,
        routeMessage: String?
    ) -> String {
        let routeEcho = routeMessage.map { "\necho \(shellQuote("Burrow: \($0)"))" } ?? ""
        guard let oneTimeCode else {
            return """
            #!/bin/zsh
            script_path="$0"
            trap 'rm -f "$script_path"' EXIT
            echo "Burrow: ssh \(tunnel.host)"\(routeEcho)
            \(command)
            """
        }

        return """
        #!/bin/zsh
        script_path="$0"
        expect_script="$(mktemp -t burrow-ssh-expect.XXXXXX)"
        trap 'rm -f "$script_path" "$expect_script"' EXIT
        export BURROW_SSH_COMMAND=\(shellQuote(command))
        export BURROW_OTP_CURRENT=\(shellQuote(oneTimeCode.currentCode))
        export BURROW_OTP_NEXT=\(shellQuote(oneTimeCode.nextCode))
        export BURROW_OTP_PERIOD_END=\(Int(oneTimeCode.periodEnd.timeIntervalSince1970))

        echo "Burrow: ssh \(tunnel.host)"
        \(routeMessage.map { "echo \(shellQuote("Burrow: \($0)"))" } ?? "")
        echo "Burrow: will answer token prompts with \(oneTimeCode.accountName) 2FA."

        if [[ ! -x /usr/bin/expect ]]; then
          printf "%s" "$BURROW_OTP_CURRENT" | /usr/bin/pbcopy
          echo "Burrow: /usr/bin/expect is missing; copied the current 2FA code to the clipboard."
          exec /bin/zsh -lc "$BURROW_SSH_COMMAND"
        fi

        cat > "$expect_script" <<'BURROW_EXPECT'
        set timeout 45
        set currentCode $env(BURROW_OTP_CURRENT)
        set nextCode $env(BURROW_OTP_NEXT)
        set periodEnd $env(BURROW_OTP_PERIOD_END)
        set sentCodes {}

        proc burrow_code {} {
            global currentCode nextCode periodEnd
            if {[clock seconds] + 5 >= $periodEnd} {
                return $nextCode
            }
            return $currentCode
        }

        spawn /bin/zsh -lc $env(BURROW_SSH_COMMAND)
        expect {
            -nocase -re {(tacc token code|verification code|one[- ]?time[^:\\r\\n]*code|otp|token[^:\\r\\n]*code|passcode)[^:\\r\\n]*:\\s*$} {
                set code [burrow_code]
                if {[lsearch -exact $sentCodes $code] >= 0} {
                    send_user "\\nBurrow: the generated 2FA code was not accepted; please type the code manually.\\n"
                    interact
                } else {
                    lappend sentCodes $code
                    send -- "$code\\r"
                    set timeout 8
                    exp_continue
                }
            }
            -nocase -re {password:\\s*$} {
                send_user "\\nBurrow: password prompt detected; handing this SSH session to you.\\n"
                interact
            }
            timeout {
                interact
            }
            eof {
                catch wait result
                exit [lindex $result 3]
            }
        }
        BURROW_EXPECT

        exec /usr/bin/expect -f "$expect_script"
        """
    }

    private struct InteractiveRoute {
        let tunnel: TunnelConfig
        let message: String?
    }

    private static func interactiveRoute(for tunnel: TunnelConfig, gateways: [GatewayConfig]) -> InteractiveRoute {
        guard !tunnel.extraSSHOptions.contains(where: { $0.lowercased().hasPrefix("proxycommand") }) else {
            return InteractiveRoute(tunnel: tunnel, message: nil)
        }
        guard let gatewayName = tunnel.gateway else {
            return InteractiveRoute(tunnel: tunnel, message: nil)
        }
        guard let gateway = gateways.first(where: { $0.name == gatewayName }) else {
            return InteractiveRoute(
                tunnel: tunnel,
                message: "gateway \(gatewayName) is not configured; opening direct SSH."
            )
        }
        guard isLocalPortListening(gateway.socksPort) else {
            return InteractiveRoute(
                tunnel: tunnel,
                message: "gateway \(gateway.name) is not running on SOCKS :\(gateway.socksPort); opening direct SSH."
            )
        }
        return InteractiveRoute(
            tunnel: GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: gateways),
            message: "routing through \(gateway.name) gateway (SOCKS :\(gateway.socksPort))."
        )
    }

    private static func isLocalPortListening(_ port: Int) -> Bool {
        guard port > 0 && port <= 65_535 else { return false }
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
            return false
        }

        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                connect(descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
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
