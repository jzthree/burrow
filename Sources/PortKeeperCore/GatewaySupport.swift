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
    /// Full VPN session cookie captured from an embedded browser sign-in
    /// (AnyConnect/ASA `webvpn` cookie): openconnect skips authentication
    /// entirely and connects with the cookie via --cookie-on-stdin.
    case sessionCookie(String)

    var stdinSecret: String? {
        switch self {
        case .password(let password):
            return password
        case .samlCookie(_, let cookie, _):
            return cookie
        case .sessionCookie(let cookie):
            return cookie
        case .none, .samlExternalBrowser:
            return nil
        }
    }

    /// Browser-derived sessions can't be retried by re-running openconnect
    /// with the same secret; the app re-runs the sign-in instead.
    var isBrowserSession: Bool {
        switch self {
        case .samlCookie, .sessionCookie:
            return true
        case .none, .password, .samlExternalBrowser:
            return false
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

    /// A helper shipped inside the app bundle by the DMG release build, letting
    /// a self-contained Burrow run without a Homebrew install. Mach-O binaries
    /// (openconnect, ocproxy) live in Contents/Helpers; non-code scripts
    /// (hipreport.sh) live in Contents/Resources so codesign seals them as data
    /// rather than rejecting them as unsigned nested code. Returns nil when not
    /// bundled (the CLI, or a dev build), so callers fall back to PATH.
    public static func bundledHelperPath(_ name: String) -> String? {
        guard let executableURL = Bundle.main.executableURL else {
            return nil
        }
        let contents = executableURL
            .deletingLastPathComponent()   // Contents/MacOS
            .deletingLastPathComponent()   // Contents
        for subdirectory in ["Helpers", "Resources"] {
            let candidate = contents
                .appendingPathComponent(subdirectory, isDirectory: true)
                .appendingPathComponent(name, isDirectory: false)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate.path
            }
        }
        return nil
    }

    public static func openconnectPath() -> String? {
        if let override = ProcessInfo.processInfo.environment["BURROW_OPENCONNECT"],
           FileManager.default.isExecutableFile(atPath: override) {
            return override
        }
        return bundledHelperPath("openconnect") ?? locateExecutable(named: "openconnect")
    }

    public static func ocproxyPath() -> String? {
        if let override = ProcessInfo.processInfo.environment["BURROW_OCPROXY"],
           FileManager.default.isExecutableFile(atPath: override) {
            return override
        }
        return bundledHelperPath("ocproxy") ?? locateExecutable(named: "ocproxy")
    }

    /// openconnect's bundled HIP-report helper. GlobalProtect gateways that
    /// enforce endpoint compliance accept the tunnel but silently drop all
    /// traffic unless the client submits a HIP report, so for gp gateways we
    /// attach the helper whenever it exists; servers that don't request HIP
    /// simply never invoke it.
    public static func hipReportPath() -> String? {
        if let override = ProcessInfo.processInfo.environment["BURROW_HIPREPORT"],
           FileManager.default.isExecutableFile(atPath: override) {
            return override
        }
        if let bundled = bundledHelperPath("hipreport.sh") {
            return bundled
        }
        guard let openconnect = openconnectPath() else {
            return nil
        }
        let prefix = (openconnect as NSString).deletingLastPathComponent  // .../bin
        let homebrewPrefix = (prefix as NSString).deletingLastPathComponent
        let candidates = [
            "\(homebrewPrefix)/opt/openconnect/libexec/openconnect/hipreport.sh",
            "\(homebrewPrefix)/libexec/openconnect/hipreport.sh",
            "/usr/local/libexec/openconnect/hipreport.sh",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Arguments for openconnect running the VPN entirely in userspace:
    /// `--script-tun` hands the tunnel to ocproxy, which exposes it as a
    /// local SOCKS5 listener. No tun device, no root, no routes.
    public static func buildArguments(for gateway: GatewayConfig, ocproxyPath: String, credential: GatewayCredential) -> [String] {
        var args: [String] = [
            "--protocol=\(gateway.vpnProtocol)",
            "--script-tun",
            "--script", "\(ShellQuoting.quote(ocproxyPath)) -D \(gateway.socksPort)",
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
        case .sessionCookie:
            args.append("--cookie-on-stdin")
        }

        if gateway.vpnProtocol.lowercased() == "gp",
           !gateway.extraArgs.contains(where: { $0.hasPrefix("--csd-wrapper") }),
           let hipReport = hipReportPath() {
            args.append("--csd-wrapper=\(hipReport)")
        }

        args.append(contentsOf: gateway.extraArgs)
        args.append(gateway.server)
        return args
    }

    public static func render(_ gateway: GatewayConfig) -> String {
        let executable = openconnectPath() ?? "openconnect"
        let ocproxy = ocproxyPath() ?? "ocproxy"
        let credential: GatewayCredential
        if gateway.usesSAML {
            credential = gateway.vpnProtocol.lowercased() == "anyconnect"
                ? .sessionCookie("")
                : .samlExternalBrowser
        } else {
            credential = gateway.user != nil ? .password("") : .none
        }
        let args = buildArguments(for: gateway, ocproxyPath: ocproxy, credential: credential)
        return ([executable] + args).map(ShellQuoting.quote).joined(separator: " ")
    }
}

/// The first hop of an ssh -J style jump specification.
public struct JumpHostSpec: Equatable, Sendable {
    public let user: String?
    public let host: String
    public let port: Int?
    /// Whether the raw spec listed more hops after this one.
    public let isMultiHop: Bool

    /// Parses "user@host:port[,more...]" — the forms `-J` accepts. Returns
    /// nil for an empty spec. Bracketed IPv6 ("[::1]:22") is handled; a bare
    /// IPv6 address is left intact (its colons are not a port).
    public static func firstHop(of raw: String) -> JumpHostSpec? {
        let hops = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = hops.first, !first.isEmpty else {
            return nil
        }

        var rest = first
        var user: String?
        if let at = rest.lastIndex(of: "@") {
            user = String(rest[..<at])
            rest = String(rest[rest.index(after: at)...])
        }

        var host = rest
        var port: Int?
        if rest.hasPrefix("[") {
            if let close = rest.firstIndex(of: "]") {
                host = String(rest[rest.index(after: rest.startIndex)..<close])
                let tail = rest[rest.index(after: close)...]
                if tail.hasPrefix(":"), let parsed = Int(tail.dropFirst()) {
                    port = parsed
                }
            }
        } else if let colon = rest.lastIndex(of: ":"),
                  rest.firstIndex(of: ":") == colon, // exactly one colon — not bare IPv6
                  let parsed = Int(rest[rest.index(after: colon)...]) {
            host = String(rest[..<colon])
            port = parsed
        }

        guard !host.isEmpty else {
            return nil
        }
        return JumpHostSpec(user: user, host: host, port: port, isMultiHop: hops.count > 1)
    }
}

/// Connects gateway configs to tunnels and to plain ssh usage.
/// Pacing for unattended (silent) VPN sign-in attempts after a session drops.
///
/// The thing that usually fixes a failed attempt is the network coming back,
/// and that has no deadline — so this widens instead of quitting, matching the
/// tunnels' capped backoff. The old two-strikes-then-park policy meant a
/// five-minute outage cost the whole day's automation: the gateway sat at
/// "click Connect" long after connectivity returned.
public enum SilentSignInRetry {
    /// Delay before attempt `attempt` (1-based). Quick twice — a wake or an
    /// IdP hiccup clears in seconds — then widening to a half-hour it keeps
    /// forever.
    public static func delaySeconds(attempt: Int) -> Int {
        let schedule = [20, 60, 180, 600, 1800]
        return schedule[min(max(attempt, 1) - 1, schedule.count - 1)]
    }

    /// A human-readable "next try" for the row's status message.
    public static func describeDelay(_ seconds: Int) -> String {
        seconds < 60 ? "\(seconds)s" : "\(seconds / 60)m"
    }
}

public enum GatewayLinker {
    /// Routes a tunnel's ssh connection through its gateway's SOCKS port.
    /// A user-supplied ProxyCommand in extraSSHOptions wins.
    ///
    /// A tunnel with a jump host is routed at the FIRST HOP: ssh silently
    /// ignores a ProxyCommand when -J is present, and the final target is
    /// usually reachable only through the jump anyway. The -J is replaced by
    /// an equivalent nested ProxyCommand whose inner connection dials the
    /// jump host through the gateway. `sshHosts` resolves a jump alias to
    /// its real HostName for the SOCKS dial (the proxy's DNS won't know
    /// local aliases); it defaults to the user's parsed ~/.ssh/config.
    public static func applyingGatewayProxy(
        to tunnel: TunnelConfig,
        gateways: [GatewayConfig],
        sshHosts: [SSHConfigHost]? = nil
    ) -> TunnelConfig {
        guard let gatewayName = tunnel.gateway,
              let gateway = gateways.first(where: { $0.name == gatewayName }) else {
            return tunnel
        }
        guard !tunnel.extraSSHOptions.contains(where: { $0.lowercased().hasPrefix("proxycommand") }) else {
            return tunnel
        }

        if let jumpRaw = tunnel.jumpHost, !jumpRaw.isEmpty {
            guard let jump = JumpHostSpec.firstHop(of: jumpRaw), !jump.isMultiHop else {
                // Multi-hop chains keep their -J; the first hop can still ride
                // the gateway via the generated ssh include.
                return tunnel
            }
            var routed = tunnel
            routed.jumpHost = nil
            routed.extraSSHOptions.append(
                jumpProxyCommandOption(for: gateway, jump: jump, sshHosts: sshHosts ?? SSHConfigParser.parse())
            )
            return routed
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

    /// `-J jump` rewritten as the ProxyCommand it stands for, with the inner
    /// connection dialed through the gateway:
    ///   ssh -W [%h]:%p -o ProxyCommand='nc ... <resolved-jump> <port>' jump
    /// %h/%p are expanded by the OUTER ssh (the -W target), so the inner nc
    /// endpoint must be literal — resolved here from the jump's ssh config.
    /// The inner ssh still names the alias, keeping its config (keys, control
    /// master) in effect; with a live master the dial is skipped entirely.
    static func jumpProxyCommandOption(
        for gateway: GatewayConfig,
        jump: JumpHostSpec,
        sshHosts: [SSHConfigHost]
    ) -> String {
        let endpoint = resolvedJumpEndpoint(jump: jump, sshHosts: sshHosts)
        // '[%h]:%p' is quoted because ssh hands ProxyCommand to the user's
        // login shell — zsh would otherwise glob the brackets ("no matches
        // found"). Same quoting ssh uses for its own implicit -J command.
        var inner = "ssh -W '[%h]:%p'"
        if let user = jump.user, !user.isEmpty {
            inner += " -l \(user)"
        }
        if let port = jump.port {
            inner += " -p \(port)"
        }
        inner += " -o 'ProxyCommand=/usr/bin/nc -X 5 -x 127.0.0.1:\(gateway.socksPort) \(endpoint.host) \(endpoint.port)'"
        inner += " \(jump.host)"
        return "ProxyCommand=\(inner)"
    }

    /// The address the gateway must be able to reach for this tunnel to
    /// stand a chance: the (resolved) first jump hop when there is one,
    /// otherwise the tunnel's own target. Used for readiness probes.
    public static func gatewayProbeEndpoint(
        for tunnel: TunnelConfig,
        sshHosts: [SSHConfigHost]? = nil
    ) -> (host: String, port: Int) {
        guard let jumpRaw = tunnel.jumpHost, !jumpRaw.isEmpty,
              let jump = JumpHostSpec.firstHop(of: jumpRaw) else {
            return (tunnel.host, tunnel.sshPort)
        }
        return resolvedJumpEndpoint(jump: jump, sshHosts: sshHosts ?? SSHConfigParser.parse())
    }

    private static func resolvedJumpEndpoint(
        jump: JumpHostSpec,
        sshHosts: [SSHConfigHost]
    ) -> (host: String, port: Int) {
        let entry = sshHosts.first { $0.matchesAlias(jump.host) }
        let host = entry?.effectiveHost ?? jump.host
        let port = jump.port ?? entry?.port ?? 22
        return (host, port)
    }

    /// ssh config snippet routing each gateway's host patterns through its
    /// SOCKS port, so `ssh some-host` works whenever the gateway is up.
    /// Users opt in with one line in ~/.ssh/config:
    ///   Include "<path to the generated file>"
    ///
    /// The Match only applies while something listens on the gateway's SOCKS
    /// The gateway whose sshHostPatterns match this host name (a resolved
    /// HostName or a bare host, glob semantics via fnmatch). Mirrors the
    /// generated ssh_include Match rules, so app-side gating and display
    /// agree with what ssh will actually do.
    public static func gatewayName(matchingHost host: String, gateways: [GatewayConfig]) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        for gateway in gateways {
            for pattern in gateway.sshHostPatterns
            where fnmatch(pattern, trimmed, FNM_CASEFOLD) == 0 {
                return gateway.name
            }
        }
        return nil
    }

    /// port, so with the gateway down (or the official VPN client / campus
    /// network in use) ssh falls through to a direct connection. `final`
    /// matches the post-HostName hostname, so user aliases work unlisted.
    public static func sshIncludeText(for gateways: [GatewayConfig]) -> String? {
        let entries = gateways.filter { !$0.sshHostPatterns.isEmpty }
        guard !entries.isEmpty else {
            return nil
        }

        var lines = [
            "# Generated by Burrow — do not edit; changes are overwritten.",
            "# Routes these hosts through Burrow gateways when they are connected;",
            "# with a gateway disconnected, ssh falls back to a direct connection.",
            "",
        ]
        for gateway in entries {
            lines.append("# gateway: \(gateway.name) (\(gateway.server))")
            lines.append("Match final host \(gateway.sshHostPatterns.joined(separator: ",")) exec \"/usr/bin/nc -z 127.0.0.1 \(gateway.socksPort) 2>/dev/null\"")
            lines.append("  ProxyCommand \(proxyCommand(for: gateway))")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}

/// openconnect does not reliably terminate its --script child on exit, so a
/// dead session can leave ocproxy holding the SOCKS port: every connection
/// then enters a proxy with no VPN behind it, and the replacement ocproxy
/// cannot bind. Reap such listeners before starting a session.
public enum GatewayPortReclaimer {
    public static func reclaimStaleListeners(port: Int, logger: @Sendable (String) -> Void = { _ in }) {
        for pid in listeningPIDs(port: port) {
            let name = processName(pid) ?? "?"
            guard name.contains("ocproxy") || name.contains("openconnect") else {
                logger("port \(port) is held by '\(name)' (pid \(pid)); leaving it alone")
                continue
            }
            logger("reclaiming stale \(name) (pid \(pid)) on port \(port)")
            terminateVerified(pid: pid, expectedName: name)
        }
    }

    /// SIGTERM, grace period, then SIGKILL — but only after re-verifying the
    /// pid still belongs to the same-named process. The pid comes from an
    /// earlier snapshot; without the re-check the OS could recycle it onto an
    /// unrelated process during the grace period and we'd kill that instead.
    private static func terminateVerified(pid: pid_t, expectedName: String) {
        kill(pid, SIGTERM)
        usleep(300_000)
        guard kill(pid, 0) == 0, processName(pid) == expectedName else {
            return
        }
        kill(pid, SIGKILL)
    }

    /// Fully tears down a gateway's processes: the ocproxy holding the SOCKS
    /// port and the openconnect process for the server (its parent, which
    /// isn't itself listening on the port). Used for intentional shutdown.
    public static func killGatewayProcesses(socksPort: Int, server: String, logger: @Sendable (String) -> Void = { _ in }) {
        reclaimStaleListeners(port: socksPort, logger: logger)
        for pid in openconnectPIDs(matchingServer: server) {
            guard let name = processName(pid) else { continue }
            logger("terminating \(name) (pid \(pid)) for \(server)")
            terminateVerified(pid: pid, expectedName: name)
        }
    }

    /// True when a previous run's session for this gateway is still alive:
    /// ocproxy holds the SOCKS port and an openconnect for the server is
    /// running. Lets the app adopt surviving sessions after a restart
    /// instead of showing a working VPN as disconnected.
    ///
    /// Runs on the 10s liveness cadence, so it spawns exactly two processes
    /// (one ps, one lsof) — the previous shape (ps + lsof + a ps per listener
    /// pid) added up to real background energy.
    public static func hasLiveSession(socksPort: Int, server: String) -> Bool {
        let table = processTable()
        let openconnectAlive = table.contains { entry in
            entry.command.contains("openconnect")
                && entry.command.split(separator: " ").contains(Substring(server))
        }
        guard openconnectAlive else { return false }
        let commandsByPID = Dictionary(table.map { ($0.pid, $0.command) }, uniquingKeysWith: { first, _ in first })
        return listeningPIDs(port: socksPort).contains { pid in
            commandsByPID[pid]?.contains("ocproxy") ?? false
        }
    }

    /// One `ps -ax` pass: pid + full command per process.
    private static func processTable() -> [(pid: pid_t, command: String)] {
        let ps = Process()
        ps.executableURL = URL(fileURLWithPath: "/bin/ps")
        ps.arguments = ["-ax", "-o", "pid=,command="]
        let pipe = Pipe()
        ps.standardOutput = pipe
        ps.standardError = Pipe()
        do {
            try ps.run()
        } catch {
            return []
        }
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        ps.waitUntilExit()
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let space = trimmed.firstIndex(of: " "),
                  let pid = pid_t(trimmed[..<space]) else { return nil }
            return (pid, String(trimmed[trimmed.index(after: space)...]))
        }
    }

    /// openconnect processes whose argument list mentions the server host.
    private static func openconnectPIDs(matchingServer server: String) -> [pid_t] {
        let ps = Process()
        ps.executableURL = URL(fileURLWithPath: "/bin/ps")
        ps.arguments = ["-ax", "-o", "pid=,command="]
        let pipe = Pipe()
        ps.standardOutput = pipe
        ps.standardError = Pipe()
        do {
            try ps.run()
        } catch {
            return []
        }
        // Drain before waiting: ps output (full argv of every process) easily
        // exceeds the 64KB pipe buffer, and an undrained pipe deadlocks
        // waitUntilExit against the blocked writer.
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        ps.waitUntilExit()
        var pids: [pid_t] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // The server is its own argv element (buildArguments appends it
            // last), so require an exact token — a bare substring match would
            // let one gateway's shutdown kill another whose server name merely
            // contains this one (e.g. "vpn.edu" inside "vpn.edu.example.com").
            guard trimmed.contains("openconnect"),
                  trimmed.split(separator: " ").contains(Substring(server)) else {
                continue
            }
            if let pidString = trimmed.split(separator: " ", maxSplits: 1).first,
               let pid = pid_t(pidString) {
                pids.append(pid)
            }
        }
        return pids
    }

    private static func listeningPIDs(port: Int) -> [pid_t] {
        let lsof = Process()
        lsof.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        // -b -w: never issue blocking kernel calls (stat on mount points).
        // Without them, one dead NFS/FUSE-T mount turns this scan into a
        // multi-minute hang — measured 2m24s vs 0.13s on the same machine —
        // and this runs before every gateway launch and in the liveness probe.
        lsof.arguments = ["-b", "-w", "-nP", "-t", "-iTCP:\(port)", "-sTCP:LISTEN"]
        let pipe = Pipe()
        lsof.standardOutput = pipe
        lsof.standardError = Pipe()
        do {
            try lsof.run()
        } catch {
            return []
        }
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        lsof.waitUntilExit()
        return output.split(whereSeparator: \.isNewline).compactMap { pid_t($0.trimmingCharacters(in: .whitespaces)) }
    }

    private static func processName(_ pid: pid_t) -> String? {
        let ps = Process()
        ps.executableURL = URL(fileURLWithPath: "/bin/ps")
        ps.arguments = ["-o", "comm=", "-p", "\(pid)"]
        let pipe = Pipe()
        ps.standardOutput = pipe
        ps.standardError = Pipe()
        do {
            try ps.run()
        } catch {
            return nil
        }
        let name = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        ps.waitUntilExit()
        return (name?.isEmpty ?? true) ? nil : name
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

    /// How many sign-in attempts that never reached a live session to allow
    /// before giving up and telling the user, instead of looping silently.
    private static let maxNeverConnectedAttempts = 3

    public func run() async {
        // Attempts in a row where openconnect exited before the VPN came up. A
        // successful connect resets it; too many means retrying won't fix it.
        var neverConnectedStreak = 0
        await withTaskCancellationHandler(operation: {
            while !Task.isCancelled {
                do {
                    let result = try runOnce()
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.exited(result.exitCode, result.diagnostic))
                    let suffix = result.diagnostic.map { " \($0)" } ?? ""
                    if credential.isBrowserSession {
                        // The browser-derived session is spent; the app re-runs
                        // the sign-in instead of looping on a dead credential.
                        logger("[gateway \(gateway.name)] openconnect exited with code \(result.exitCode).\(suffix) SAML session ended; a fresh sign-in is required.")
                        break
                    }
                    if result.connected {
                        // A real session dropped — a genuine reconnect.
                        neverConnectedStreak = 0
                        logger("[gateway \(gateway.name)] openconnect exited with code \(result.exitCode).\(suffix) Reconnecting in \(gateway.reconnectDelaySeconds)s.")
                    } else {
                        neverConnectedStreak += 1
                        // A form that wants more input than we can feed will want
                        // it every time, and a 2-minute hang means the user missed
                        // (or never got) an approval — in both cases another silent
                        // attempt can't help. Give up on the first sight, not the third.
                        let futile = Self.indicatesInteractionRequired(result.diagnostic) || result.timedOut
                        if futile || neverConnectedStreak >= Self.maxNeverConnectedAttempts {
                            // Stop the silent loop and tell the user what to do.
                            eventHandler(.failedToStart(giveUpMessage(diagnostic: result.diagnostic, exitCode: result.exitCode, timedOut: result.timedOut)))
                            logger("[gateway \(gateway.name)] stopped after \(neverConnectedStreak) sign-in attempt(s) that never connected.\(suffix)")
                            break
                        }
                        logger("[gateway \(gateway.name)] openconnect exited with code \(result.exitCode) before the VPN came up (attempt \(neverConnectedStreak)/\(Self.maxNeverConnectedAttempts)).\(suffix) Reconnecting in \(gateway.reconnectDelaySeconds)s.")
                    }
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
                    // Floor of 1s — see TunnelSupervisor: a zero delay plus an
                    // instantly-failing openconnect is a busy respawn loop.
                    try await Task.sleep(for: .seconds(max(1, gateway.reconnectDelaySeconds)))
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
        /// True if the SOCKS listener came up this run (the VPN session was
        /// actually established). False means openconnect exited during the
        /// connect/sign-in phase — retrying blindly won't help if the cause is
        /// wrong auth mode (SAML vs password), an unmet second factor, or a
        /// server that isn't answering.
        let connected: Bool
        /// True when openconnect stayed alive past the readiness deadline
        /// without a session and Burrow ended the attempt itself.
        let timedOut: Bool
    }

    private func runOnce() throws -> RunResult {
        guard let openconnectPath = GatewayCommandBuilder.openconnectPath() else {
            throw GatewayError("openconnect not found. Install it with: brew install openconnect ocproxy")
        }
        guard let ocproxyPath = GatewayCommandBuilder.ocproxyPath() else {
            throw GatewayError("ocproxy not found. Install it with: brew install ocproxy")
        }

        // One openconnect per gateway, ever: a fresh launch supersedes anything
        // still around from an earlier attempt (a ghost from a cancelled task, a
        // duplicate from a double-click). Two concurrent sessions to the same
        // ASA displace each other server-side while the older ocproxy keeps the
        // SOCKS port — a "green but routes nowhere" wedge.
        GatewayPortReclaimer.killGatewayProcesses(socksPort: gateway.socksPort, server: gateway.server, logger: logger)

        // The task may have been cancelled while the reclaim ran (a stop or a
        // restart mid-launch). Launching openconnect anyway would create an
        // unsupervised ghost process nothing tracks — bail out first.
        guard !Task.isCancelled else {
            throw GatewayError("cancelled before launch")
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
        let outputDrained = DispatchSemaphore(value: 0)
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        outputPipe.fileHandleForReading.readabilityHandler = { [logger, gateway] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                // EOF: all writers closed, everything has been classified.
                handle.readabilityHandler = nil
                outputDrained.signal()
                return
            }
            guard let text = String(data: data, encoding: .utf8) else {
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
            // The throwing write turns a closed pipe (openconnect died before
            // reading its password) into an error instead of an uncatchable
            // NSFileHandleOperationException that would crash the app.
            do {
                try inputPipe.fileHandleForWriting.write(contentsOf: Data("\(secret)\n".utf8))
            } catch {
                logger("[gateway \(gateway.name)] could not hand the credential to openconnect (it may have exited early): \(error.localizedDescription)")
            }
        }
        try? inputPipe.fileHandleForWriting.close()

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
        var timedOut = false
        if !announcedConnection && process.isRunning && !runState.hasAuthenticationFailure() {
            // Late success after the deadline still flips the state.
            if PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
                announcedConnection = true
                eventHandler(.connected)
            } else {
                // openconnect is alive but the session never came up. Waiting
                // on it forever would leave the UI stuck at "Connecting" with
                // no explanation — end the attempt and report a timeout.
                timedOut = true
                logger("[gateway \(gateway.name)] no VPN session after 120s; ending the attempt.")
                process.terminate()
            }
        }

        process.waitUntilExit()
        // Wait for EOF so a final auth-failure or cert-pin line printed just
        // before exit is classified before we decide the outcome. Bounded: a
        // lingering ocproxy that inherited the pipe must not hang the loop.
        _ = outputDrained.wait(timeout: .now() + 2)
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

        return RunResult(
            exitCode: process.terminationStatus,
            diagnostic: runState.currentDiagnostic(),
            connected: announcedConnection,
            timedOut: timedOut
        )
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
            normalized.contains("address already in use") ||
            normalized.contains("user input required")
    }

    /// openconnect printed "User input required in non-interactive mode": the
    /// server's sign-in form wants more than the single stored password Burrow
    /// can feed on stdin (a second factor, a group choice, …). Retrying is
    /// pointless — every attempt hits the same form.
    private static func indicatesInteractionRequired(_ diagnostic: String?) -> Bool {
        diagnostic?.lowercased().contains("user input required") ?? false
    }

    /// The actionable message shown when we stop retrying a VPN that never came
    /// up — tailored to whether it looks like a network problem or a sign-in one.
    private func giveUpMessage(diagnostic: String?, exitCode: Int32, timedOut: Bool = false) -> String {
        if timedOut {
            let hint = gateway.usesSAML
                ? "Finish the browser sign-in (including any Duo prompt), then connect again."
                : "If your sign-in needs an approval (e.g. a push notification), complete it promptly after connecting — or switch this gateway to SAML sign-in if it uses a browser/SSO login."
            return "The VPN session to \(gateway.server) didn’t come up within 2 minutes, so Burrow stopped the attempt. \(hint)"
        }
        if Self.indicatesInteractionRequired(diagnostic) {
            // The definitive password-mode dead end: the server's form wants
            // more than a stored password (second factor, group choice, …).
            return "\(gateway.server) asked for more than a password (a second factor or group choice), which password mode can’t answer. Switch this gateway to SAML sign-in in its settings — the browser window handles the full sign-in, Duo included."
        }
        if let diagnostic, Self.looksLikeNetworkFailure(diagnostic) {
            return "Can’t reach \(gateway.server): \(diagnostic). Stopped retrying — check your internet or the VPN server, then connect again."
        }
        let base = "Couldn’t complete VPN sign-in to \(gateway.server) — openconnect exited before the session came up (code \(exitCode)). Stopped retrying."
        if gateway.usesSAML {
            return base + " Approve the browser / Duo sign-in when it opens; if it never appears, check the gateway’s SAML group."
        }
        return base + " If this VPN uses single sign-on or Duo, switch this gateway to SAML sign-in — password mode can’t complete a second factor. Otherwise re-check the VPN password."
    }

    private static func looksLikeNetworkFailure(_ diagnostic: String) -> Bool {
        let normalized = diagnostic.lowercased()
        return normalized.contains("failed to connect") ||
            normalized.contains("could not resolve") ||
            normalized.contains("connection timed out") ||
            normalized.contains("ssl connection failure")
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
