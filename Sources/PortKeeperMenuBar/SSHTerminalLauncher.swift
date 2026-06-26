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
        let safeName = tunnel.name
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: " ", with: "-")
        let controlPath = "/tmp/burrow-\(safeName)-\(String(UUID().uuidString.prefix(8))).ctl"
        let command = interactiveCommand(for: route.tunnel)
        let masterCommandText: String?
        let controlCommandText: String?
        let controlExitCommandText: String?
        if oneTimeCode != nil {
            masterCommandText = masterCommand(for: route.tunnel, controlPath: controlPath)
            controlCommandText = interactiveCommand(for: route.tunnel, controlPath: controlPath)
            controlExitCommandText = controlExitCommand(for: route.tunnel, controlPath: controlPath)
        } else {
            masterCommandText = nil
            controlCommandText = nil
            controlExitCommandText = nil
        }

        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-ssh-\(safeName).command")
        let script = scriptText(
            tunnel: tunnel,
            command: command,
            oneTimeCode: oneTimeCode,
            routeMessage: route.message,
            masterCommand: masterCommandText,
            controlCommand: controlCommandText,
            controlExitCommand: controlExitCommandText,
            controlPath: oneTimeCode == nil ? nil : controlPath
        )
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
        routeMessage: String?,
        masterCommand: String?,
        controlCommand: String?,
        controlExitCommand: String?,
        controlPath: String?
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

        guard let masterCommand, let controlCommand, let controlExitCommand, let controlPath else {
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
        export BURROW_CONTROL_PATH=\(shellQuote(controlPath))
        export BURROW_MASTER_COMMAND=\(shellQuote(masterCommand))
        export BURROW_INTERACTIVE_COMMAND=\(shellQuote(controlCommand))
        export BURROW_CONTROL_EXIT_COMMAND=\(shellQuote(controlExitCommand))
        export BURROW_OTP_CURRENT=\(shellQuote(oneTimeCode.currentCode))
        export BURROW_OTP_NEXT=\(shellQuote(oneTimeCode.nextCode))
        export BURROW_OTP_PERIOD_END=\(Int(oneTimeCode.periodEnd.timeIntervalSince1970))

        cleanup() {
          /bin/zsh -lc "$BURROW_CONTROL_EXIT_COMMAND" >/dev/null 2>&1 || true
          rm -f "$script_path" "$expect_script" "$BURROW_CONTROL_PATH"
        }
        trap cleanup EXIT

        echo "Burrow: ssh \(tunnel.host)"
        \(routeMessage.map { "echo \(shellQuote("Burrow: \($0)"))" } ?? "")
        echo "Burrow: will answer token prompts with \(oneTimeCode.accountName) 2FA, then switch to plain ssh."

        if [[ ! -x /usr/bin/expect ]]; then
          printf "%s" "$BURROW_OTP_CURRENT" | /usr/bin/pbcopy
          echo "Burrow: /usr/bin/expect is missing; copied the current 2FA code to the clipboard."
          exec /bin/zsh -lc \(shellQuote(command))
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

        spawn /bin/zsh -lc $env(BURROW_MASTER_COMMAND)
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

        if /usr/bin/expect -f "$expect_script"; then
          echo "Burrow: 2FA accepted; opening interactive shell."
          /bin/zsh -lc "$BURROW_INTERACTIVE_COMMAND"
        else
          status=$?
          echo "Burrow: 2FA helper exited with status $status."
          exit "$status"
        fi
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
    static func interactiveCommand(for tunnel: TunnelConfig, controlPath: String? = nil) -> String {
        var parts = ["/usr/bin/ssh"]
        if let controlPath {
            parts += ["-S", shellQuote(controlPath), "-o", "ControlMaster=no"]
        }
        appendConnectionOptions(for: tunnel, to: &parts)
        parts.append(shellQuote(remoteTarget(for: tunnel)))
        return parts.joined(separator: " ")
    }

    private static func masterCommand(for tunnel: TunnelConfig, controlPath: String) -> String {
        var parts = [
            "/usr/bin/ssh",
            "-M",
            "-S", shellQuote(controlPath),
            "-fN",
            "-o", "ControlPersist=no",
        ]
        appendConnectionOptions(for: tunnel, to: &parts)
        parts.append(shellQuote(remoteTarget(for: tunnel)))
        return parts.joined(separator: " ")
    }

    private static func controlExitCommand(for tunnel: TunnelConfig, controlPath: String) -> String {
        var parts = [
            "/usr/bin/ssh",
            "-S", shellQuote(controlPath),
            "-O", "exit",
        ]
        if tunnel.sshPort != 22 {
            parts += ["-p", "\(tunnel.sshPort)"]
        }
        parts.append(shellQuote(remoteTarget(for: tunnel)))
        return parts.joined(separator: " ")
    }

    private static func appendConnectionOptions(for tunnel: TunnelConfig, to parts: inout [String]) {
        if tunnel.sshPort != 22 {
            parts += ["-p", String(tunnel.sshPort)]
        }
        if let identity = tunnel.identityFile, !identity.isEmpty {
            parts += ["-i", shellQuote((identity as NSString).expandingTildeInPath)]
        }
        if let jump = tunnel.jumpHost, !jump.isEmpty {
            parts += ["-J", shellQuote(jump)]
        }

        if tunnel.serverAliveInterval > 0,
           !hasExtraSSHOption("serveraliveinterval", in: tunnel.extraSSHOptions) {
            parts += ["-o", "ServerAliveInterval=\(tunnel.serverAliveInterval)"]
        }
        if tunnel.serverAliveCountMax > 0,
           !hasExtraSSHOption("serveralivecountmax", in: tunnel.extraSSHOptions) {
            parts += ["-o", "ServerAliveCountMax=\(tunnel.serverAliveCountMax)"]
        }

        for option in tunnel.extraSSHOptions {
            parts += ["-o", shellQuote(normalizedOption(option))]
        }
    }

    private static func remoteTarget(for tunnel: TunnelConfig) -> String {
        if let alias = sshConfigAlias(for: tunnel) {
            return alias
        }
        return tunnel.user.map { "\($0)@\(tunnel.host)" } ?? tunnel.host
    }

    private static func sshConfigAlias(for tunnel: TunnelConfig) -> String? {
        guard isSimpleSSHAlias(tunnel.name) else { return nil }
        guard tunnel.gateway == nil else { return nil }
        guard !tunnel.extraSSHOptions.contains(where: { $0.lowercased().hasPrefix("proxycommand") }) else {
            return nil
        }

        let expectedAlias = tunnel.name.lowercased()
        let expectedHost = tunnel.host.lowercased()
        return SSHConfigParser.parse().first { host in
            guard host.alias.lowercased() == expectedAlias else { return false }
            guard host.effectiveHost.lowercased() == expectedHost || host.alias.lowercased() == expectedHost else {
                return false
            }
            if let user = tunnel.user, host.user != user {
                return false
            }
            if let port = host.port {
                return port == tunnel.sshPort
            }
            return tunnel.sshPort == 22
        }?.alias
    }

    private static func isSimpleSSHAlias(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        return value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
    }

    private static func hasExtraSSHOption(_ key: String, in options: [String]) -> Bool {
        options.contains { option in
            let trimmed = option.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return trimmed == key || trimmed.hasPrefix("\(key)=")
        }
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
