import AppKit
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
        let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: gateways)
        let command = interactiveCommand(for: routed)

        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-ssh-\(tunnel.name.replacingOccurrences(of: "/", with: "-")).command")
        let script = scriptText(tunnel: tunnel, command: command, oneTimeCode: oneTimeCode)
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
        oneTimeCode: OneTimeCode?
    ) -> String {
        guard let oneTimeCode else {
            return """
            #!/bin/zsh
            script_path="$0"
            trap 'rm -f "$script_path"' EXIT
            echo "Burrow: ssh \(tunnel.host)"
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
