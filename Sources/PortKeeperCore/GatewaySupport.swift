import Darwin
import Foundation

public enum GatewayRuntimeEvent: Sendable {
    case starting
    case connected
    case exited(Int32, String?)
    case failedToStart(String)
    case authenticationFailed(String)
    /// openconnect rejected the server certificate (it uses its own CA
    /// bundle, not the macOS Keychain) and suggested a pin to trust it.
    case certificateUntrusted(suggestedPin: String)
    case log(String)
}

public struct GatewayError: LocalizedError {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var errorDescription: String? { message }
}

struct CertificateTrustError: Error {
    let suggestedPin: String
}

/// How a gateway authenticates to its VPN server.
public enum GatewayCredential: Sendable {
    /// No credential (e.g. certificate-based setups configured via extraArgs).
    case none
    /// Classic password fed on stdin.
    case password(String)
    /// SAML cookie captured from a browser sign-in (GlobalProtect flow):
    /// openconnect receives the cookie as the password, plus the username
    /// and usergroup that scope it (e.g. "gateway:prelogin-cookie").
    case samlCookie(username: String, cookie: String, usergroup: String)
    /// openconnect drives the system browser itself and catches the token on
    /// a localhost redirect (AnyConnect external-browser SAML).
    case samlExternalBrowser

    var stdinSecret: String? {
        switch self {
        case .password(let password):
            return password
        case .samlCookie(_, let cookie, _):
            return cookie
        case .none, .samlExternalBrowser:
            return nil
        }
    }
}

public enum GatewayCommandBuilder {
    static let searchDirectories = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin"]

    public static func locateExecutable(named name: String, environmentOverride: String? = nil) -> String? {
        if let environmentOverride, FileManager.default.isExecutableFile(atPath: environmentOverride) {
            return environmentOverride
        }
        for directory in searchDirectories {
            let path = "\(directory)/\(name)"
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }

    public static func openconnectPath() -> String? {
        locateExecutable(named: "openconnect", environmentOverride: ProcessInfo.processInfo.environment["BURROW_OPENCONNECT"])
    }

    public static func ocproxyPath() -> String? {
        locateExecutable(named: "ocproxy", environmentOverride: ProcessInfo.processInfo.environment["BURROW_OCPROXY"])
    }

    /// Arguments for openconnect running the VPN entirely in userspace:
    /// `--script-tun` hands the tunnel to ocproxy, which exposes it as a
    /// local SOCKS5 listener. No tun device, no root, no routes.
    public static func buildArguments(for gateway: GatewayConfig, ocproxyPath: String, credential: GatewayCredential) -> [String] {
        var args: [String] = [
            "--protocol=\(gateway.vpnProtocol)",
            "--script-tun",
            "--script", "\(shellQuote(ocproxyPath)) -D \(gateway.socksPort)",
        ]

        switch credential {
        case .none:
            if let user = gateway.user, !user.isEmpty {
                args.append("--user=\(user)")
            }
        case .password:
            if let user = gateway.user, !user.isEmpty {
                args.append("--user=\(user)")
            }
            args.append("--passwd-on-stdin")
        case .samlCookie(let username, _, let usergroup):
            args.append("--user=\(username)")
            args.append("--usergroup=\(usergroup)")
            args.append("--passwd-on-stdin")
        case .samlExternalBrowser:
            args.append("--external-browser=/usr/bin/open")
        }

        args.append(contentsOf: gateway.extraArgs)
        args.append(gateway.server)
        return args
    }

    public static func render(_ gateway: GatewayConfig) -> String {
        let executable = openconnectPath() ?? "openconnect"
        let ocproxy = ocproxyPath() ?? "ocproxy"
        let credential: GatewayCredential = gateway.usesSAML
            ? .samlExternalBrowser
            : (gateway.user != nil ? .password("") : .none)
        let args = buildArguments(for: gateway, ocproxyPath: ocproxy, credential: credential)
        return ([executable] + args).map(shellQuote).joined(separator: " ")
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

/// Connects gateway configs to tunnels and to plain ssh usage.
public enum GatewayLinker {
    /// Routes a tunnel's ssh connection through its gateway's SOCKS port.
    /// A user-supplied ProxyCommand in extraSSHOptions wins.
    public static func applyingGatewayProxy(to tunnel: TunnelConfig, gateways: [GatewayConfig]) -> TunnelConfig {
        guard let gatewayName = tunnel.gateway,
              let gateway = gateways.first(where: { $0.name == gatewayName }) else {
            return tunnel
        }
        guard !tunnel.extraSSHOptions.contains(where: { $0.lowercased().hasPrefix("proxycommand") }) else {
            return tunnel
        }

        var routed = tunnel
        routed.extraSSHOptions.append(proxyCommandOption(for: gateway))
        return routed
    }

    public static func proxyCommandOption(for gateway: GatewayConfig) -> String {
        "ProxyCommand=\(proxyCommand(for: gateway))"
    }

    public static func proxyCommand(for gateway: GatewayConfig) -> String {
        "/usr/bin/nc -X 5 -x 127.0.0.1:\(gateway.socksPort) %h %p"
    }

    /// ssh config snippet routing each gateway's host patterns through its
    /// SOCKS port, so `ssh some-host` works whenever the gateway is up.
    /// Users opt in with one line in ~/.ssh/config:
    ///   Include "<path to the generated file>"
    public static func sshIncludeText(for gateways: [GatewayConfig]) -> String? {
        let entries = gateways.filter { !$0.sshHostPatterns.isEmpty }
        guard !entries.isEmpty else {
            return nil
        }

        var lines = [
            "# Generated by Burrow — do not edit; changes are overwritten.",
            "# Routes these hosts through Burrow gateways when they are connected.",
            "",
        ]
        for gateway in entries {
            lines.append("# gateway: \(gateway.name) (\(gateway.server))")
            lines.append("Match host \(gateway.sshHostPatterns.joined(separator: ","))")
            lines.append("  ProxyCommand \(proxyCommand(for: gateway))")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}

public final class GatewaySupervisor: @unchecked Sendable {
    private let gateway: GatewayConfig
    private let credential: GatewayCredential
    private let logger: @Sendable (String) -> Void
    private let eventHandler: @Sendable (GatewayRuntimeEvent) -> Void
    private let processLock = NSLock()
    private var currentProcess: Process?

    public init(
        gateway: GatewayConfig,
        credential: GatewayCredential,
        logger: @escaping @Sendable (String) -> Void,
        eventHandler: @escaping @Sendable (GatewayRuntimeEvent) -> Void = { _ in }
    ) {
        self.gateway = gateway
        self.credential = credential
        self.logger = logger
        self.eventHandler = eventHandler
    }

    public func run() async {
        await withTaskCancellationHandler(operation: {
            while !Task.isCancelled {
                do {
                    let result = try runOnce()
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.exited(result.exitCode, result.diagnostic))
                    let suffix = result.diagnostic.map { " \($0)" } ?? ""
                    logger("[gateway \(gateway.name)] openconnect exited with code \(result.exitCode).\(suffix) Reconnecting in \(gateway.reconnectDelaySeconds)s.")
                } catch let error as AuthenticationFailureError {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.authenticationFailed(error.message))
                    logger("[gateway \(gateway.name)] authentication failed: \(error.message). Stopping retries until credentials are updated.")
                    break
                } catch let error as CertificateTrustError {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.certificateUntrusted(suggestedPin: error.suggestedPin))
                    logger("[gateway \(gateway.name)] server certificate not trusted by openconnect. Suggested pin: \(error.suggestedPin)")
                    break
                } catch {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.failedToStart(error.localizedDescription))
                    logger("[gateway \(gateway.name)] failed to start: \(error.localizedDescription).")
                    break
                }

                do {
                    try await Task.sleep(for: .seconds(gateway.reconnectDelaySeconds))
                } catch {
                    break
                }
            }
            terminateCurrentProcess()
        }, onCancel: {
            self.terminateCurrentProcess()
        })
    }

    private struct RunResult {
        let exitCode: Int32
        let diagnostic: String?
    }

    private func runOnce() throws -> RunResult {
        guard let openconnectPath = GatewayCommandBuilder.openconnectPath() else {
            throw GatewayError("openconnect not found. Install it with: brew install openconnect ocproxy")
        }
        guard let ocproxyPath = GatewayCommandBuilder.ocproxyPath() else {
            throw GatewayError("ocproxy not found. Install it with: brew install ocproxy")
        }

        let runState = RunState()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: openconnectPath)
        process.arguments = GatewayCommandBuilder.buildArguments(
            for: gateway,
            ocproxyPath: ocproxyPath,
            credential: credential
        )

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        outputPipe.fileHandleForReading.readabilityHandler = { [logger, gateway] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
                return
            }
            for rawLine in text.split(whereSeparator: \.isNewline) {
                let line = String(rawLine)
                logger("[gateway \(gateway.name)] \(line)")
                self.eventHandler(.log(line))
                if let pin = Self.extractServerCertPin(from: line) {
                    runState.recordSuggestedPin(pin)
                } else if Self.isAuthenticationFailureLine(line) {
                    runState.recordAuthenticationFailure(line)
                } else if Self.isDiagnosticLine(line) {
                    runState.recordDiagnostic(line)
                }
            }
        }

        let inputPipe = Pipe()
        process.standardInput = inputPipe

        processLock.lock()
        currentProcess = process
        processLock.unlock()

        logger("[gateway \(gateway.name)] starting: \(GatewayCommandBuilder.render(gateway))")
        eventHandler(.starting)
        try process.run()

        if let secret = credential.stdinSecret {
            inputPipe.fileHandleForWriting.write(Data("\(secret)\n".utf8))
        }
        inputPipe.fileHandleForWriting.closeFile()

        // Readiness = the SOCKS listener accepts connections. ocproxy is only
        // exec'd by openconnect after the VPN session is established, so an
        // open port means the gateway is genuinely up. The long deadline
        // leaves room for Duo-style approval on a phone.
        let deadline = Date().addingTimeInterval(120)
        var announcedConnection = false
        while process.isRunning && Date() < deadline {
            if runState.hasAuthenticationFailure() {
                break
            }
            if PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
                announcedConnection = true
                eventHandler(.connected)
                break
            }
            usleep(300_000)
        }
        if !announcedConnection && process.isRunning && !runState.hasAuthenticationFailure() {
            // Late success after the deadline still flips the state.
            if PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
                eventHandler(.connected)
            }
        }

        process.waitUntilExit()
        outputPipe.fileHandleForReading.readabilityHandler = nil

        processLock.lock()
        currentProcess = nil
        processLock.unlock()

        if let pin = runState.currentSuggestedPin() {
            throw CertificateTrustError(suggestedPin: pin)
        }
        if let failure = runState.consumeAuthenticationFailure() {
            throw AuthenticationFailureError(message: failure)
        }

        return RunResult(exitCode: process.terminationStatus, diagnostic: runState.currentDiagnostic())
    }

    /// Parses openconnect's "To trust this server in future, perhaps add this
    /// to your command line: --servercert pin-sha256:..." suggestion.
    public static func extractServerCertPin(from line: String) -> String? {
        guard let markerRange = line.range(of: "--servercert") else {
            return nil
        }
        var remainder = line[markerRange.upperBound...]
        // Strip leading separators only ("--servercert pin..." or "--servercert=pin...");
        // a trailing "=" is base64 padding and must survive.
        while !remainder.hasPrefix("pin-sha256:"), let first = remainder.first, first == " " || first == "\t" || first == "=" {
            remainder = remainder.dropFirst()
        }
        guard remainder.hasPrefix("pin-sha256:") else {
            return nil
        }
        let pin = remainder.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? String(remainder)
        return pin.isEmpty ? nil : pin
    }

    private static func isAuthenticationFailureLine(_ line: String) -> Bool {
        let normalized = line.lowercased()
        return normalized.contains("login failed") ||
            normalized.contains("authentication failed") ||
            normalized.contains("failed to obtain webvpn cookie") ||
            normalized.contains("username or password") ||
            normalized.contains("password is incorrect") ||
            normalized.contains("permission denied")
    }

    private static func isDiagnosticLine(_ line: String) -> Bool {
        let normalized = line.lowercased()
        return normalized.contains("failed to connect") ||
            normalized.contains("could not resolve") ||
            normalized.contains("connection timed out") ||
            normalized.contains("certificate") && normalized.contains("fail") ||
            normalized.contains("ssl connection failure") ||
            normalized.contains("address already in use")
    }

    private func terminateCurrentProcess() {
        processLock.lock()
        let process = currentProcess
        processLock.unlock()

        guard let process, process.isRunning else {
            return
        }
        process.terminate()
    }

    private final class RunState: @unchecked Sendable {
        private let lock = NSLock()
        private var authenticationFailureMessage: String?
        private var diagnosticMessage: String?
        private var suggestedPin: String?

        func recordSuggestedPin(_ pin: String) {
            lock.lock()
            if suggestedPin == nil {
                suggestedPin = pin
            }
            lock.unlock()
        }

        func currentSuggestedPin() -> String? {
            lock.lock()
            let pin = suggestedPin
            lock.unlock()
            return pin
        }

        func recordAuthenticationFailure(_ message: String) {
            lock.lock()
            if authenticationFailureMessage == nil {
                authenticationFailureMessage = message
            }
            lock.unlock()
        }

        func recordDiagnostic(_ message: String) {
            lock.lock()
            if diagnosticMessage == nil {
                diagnosticMessage = message
            }
            lock.unlock()
        }

        func hasAuthenticationFailure() -> Bool {
            lock.lock()
            let result = authenticationFailureMessage != nil
            lock.unlock()
            return result
        }

        func consumeAuthenticationFailure() -> String? {
            lock.lock()
            let message = authenticationFailureMessage
            lock.unlock()
            return message
        }

        func currentDiagnostic() -> String? {
            lock.lock()
            let message = diagnosticMessage
            lock.unlock()
            return message
        }
    }
}
