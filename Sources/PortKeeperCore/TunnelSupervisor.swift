import Darwin
import Foundation

public enum TunnelRuntimeEvent: Sendable {
    case starting
    case connected
    case exited(Int32, String?)
    case failedToStart(String)
    case authenticationFailed(String)
    case log(String)
}

struct AuthenticationFailureError: LocalizedError {
    let message: String

    var errorDescription: String? { message }
}

/// What the supervisor does when ssh output classifies as an authentication
/// failure. Ordinary failures always retry forever — this policy only governs
/// the auth-classified ones.
public enum AuthFailureRetryPolicy: Sendable {
    /// Keep the supervisor alive and retry on a long capped backoff. The right
    /// default for key-authenticated tunnels: "Permission denied" there is as
    /// often a host mid-reboot (PAM/sssd half-down) as a revoked key, and
    /// retrying a public key cannot lock an account.
    case retryWithBackoff
    /// Return from run() so the owner can invalidate credentials and re-prompt
    /// (the app's password flow). Retrying forever with a known-bad password
    /// would hammer the host and risk a lockout.
    case stopAndReport
}

/// Backoff schedule knobs — injectable so tests don't sleep for real.
public struct RetryTuning: Sendable {
    public var ordinaryCapSeconds: Int
    public var authBaseSeconds: Int
    public var authCapSeconds: Int

    public init(ordinaryCapSeconds: Int = 60, authBaseSeconds: Int = 30, authCapSeconds: Int = 300) {
        self.ordinaryCapSeconds = ordinaryCapSeconds
        self.authBaseSeconds = authBaseSeconds
        self.authCapSeconds = authCapSeconds
    }

    public static let standard = RetryTuning()
}

public final class TunnelSupervisor: @unchecked Sendable {
    private let tunnel: TunnelConfig
    private let logger: @Sendable (String) -> Void
    private let eventHandler: @Sendable (TunnelRuntimeEvent) -> Void
    private let environment: [String: String]
    private let executablePath: String
    private let captureOutput: Bool
    private let authFailurePolicy: AuthFailureRetryPolicy
    private let retryTuning: RetryTuning
    private let processLock = NSLock()
    private var currentProcess: Process?

    public init(
        tunnel: TunnelConfig,
        logger: @escaping @Sendable (String) -> Void,
        eventHandler: @escaping @Sendable (TunnelRuntimeEvent) -> Void = { _ in },
        environment: [String: String] = [:],
        executablePath: String = "/usr/bin/ssh",
        captureOutput: Bool = true,
        authFailurePolicy: AuthFailureRetryPolicy = .retryWithBackoff,
        retryTuning: RetryTuning = .standard
    ) {
        self.tunnel = tunnel
        self.logger = logger
        self.eventHandler = eventHandler
        self.environment = environment
        self.executablePath = executablePath
        self.captureOutput = captureOutput
        self.authFailurePolicy = authFailurePolicy
        self.retryTuning = retryTuning
    }

    /// Delay before retry number `consecutiveFailures` (1-based): base doubling
    /// per consecutive failure, capped. A run that reached forward readiness
    /// resets the count, so a long-lived connection that drops retries fast.
    static func retryDelay(consecutiveFailures: Int, base: Int, cap: Int) -> Int {
        let flooredBase = max(1, base)
        let cappedAt = max(flooredBase, cap)
        var delay = flooredBase
        for _ in 1..<max(1, consecutiveFailures) {
            delay = min(cappedAt, delay * 2)
            if delay >= cappedAt { break }
        }
        return min(cappedAt, delay)
    }

    public func run() async {
        await withTaskCancellationHandler(operation: {
            // Never give up: failures back off (doubling to a cap) instead of
            // counting toward a stop. The floor of 1s keeps an instantly-failing
            // ssh from spawn-fail-respawning in a tight loop; the cap keeps a
            // long outage from hammering the host every few seconds.
            var consecutiveFailures = 0
            var nextDelaySeconds = max(1, tunnel.reconnectDelaySeconds)
            while !Task.isCancelled {
                do {
                    let result = try runOnce()
                    if Task.isCancelled {
                        break
                    }
                    if result.didConnect {
                        consecutiveFailures = 0
                    }
                    consecutiveFailures += 1
                    nextDelaySeconds = Self.retryDelay(
                        consecutiveFailures: consecutiveFailures,
                        base: tunnel.reconnectDelaySeconds,
                        cap: retryTuning.ordinaryCapSeconds
                    )
                    eventHandler(.exited(result.exitCode, result.diagnosticMessage))
                    let diagnosticSuffix = result.diagnosticMessage.map { " \($0)" } ?? ""
                    logger("[\(tunnel.name)] ssh exited with code \(result.exitCode).\(diagnosticSuffix) Reconnecting in \(nextDelaySeconds)s.")
                } catch let error as AuthenticationFailureError {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.authenticationFailed(error.message))
                    if case .stopAndReport = authFailurePolicy {
                        logger("[\(tunnel.name)] authentication failed: \(error.message). Stopping retries until credentials are updated.")
                        break
                    }
                    // Key-based tunnel: a host mid-reboot reports "Permission
                    // denied" too. Back off hard, but never stop.
                    consecutiveFailures += 1
                    nextDelaySeconds = Self.retryDelay(
                        consecutiveFailures: consecutiveFailures,
                        base: retryTuning.authBaseSeconds,
                        cap: retryTuning.authCapSeconds
                    )
                    logger("[\(tunnel.name)] authentication failed: \(error.message). Retrying in \(nextDelaySeconds)s.")
                } catch {
                    if Task.isCancelled {
                        break
                    }
                    consecutiveFailures += 1
                    nextDelaySeconds = Self.retryDelay(
                        consecutiveFailures: consecutiveFailures,
                        base: tunnel.reconnectDelaySeconds,
                        cap: retryTuning.ordinaryCapSeconds
                    )
                    eventHandler(.failedToStart(error.localizedDescription))
                    logger("[\(tunnel.name)] failed to start: \(error.localizedDescription). Retrying in \(nextDelaySeconds)s.")
                }

                do {
                    try await Task.sleep(for: .seconds(max(1, nextDelaySeconds)))
                } catch {
                    break
                }
            }
            terminateCurrentProcess()
        }, onCancel: {
            self.terminateCurrentProcess()
        })
    }

    private func runOnce() throws -> RunResult {
        try PortKeeperRuntimeRegistry.reclaimOwnedProcess(
            for: tunnel,
            executablePath: executablePath,
            logger: logger
        )

        let runState = RunState()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = executablePath == "/usr/bin/ssh" ? SSHCommandBuilder.buildArguments(for: tunnel) : []
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }

        let outputPipe = Pipe()
        let outputDrained = DispatchSemaphore(value: 0)
        if captureOutput {
            process.standardOutput = outputPipe
            process.standardError = outputPipe

            outputPipe.fileHandleForReading.readabilityHandler = { [logger, tunnel] handle in
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
                    logger("[\(tunnel.name)] \(line)")
                    self.eventHandler(.log(line))
                    if Self.isAuthenticationFailureLine(line) {
                        runState.recordAuthenticationFailure(line)
                    } else if Self.isDiagnosticFailureLine(line) {
                        runState.recordDiagnostic(line)
                    }
                }
            }
        }

        processLock.lock()
        currentProcess = process
        processLock.unlock()

        logger("[\(tunnel.name)] starting: \(SSHCommandBuilder.render(tunnel))")
        eventHandler(.starting)
        try process.run()
        try PortKeeperRuntimeRegistry.recordProcess(process.processIdentifier, for: tunnel.name)
        let didConnect = waitForForwardReadiness(process: process, runState: runState)
        if didConnect {
            eventHandler(.connected)
        }
        process.waitUntilExit()

        if captureOutput {
            // The readability handler runs on its own queue with no ordering
            // guarantee against waitUntilExit — ssh's final line (a
            // "Permission denied" right before exit) may still be in flight.
            // Wait for EOF so it is classified before we decide why the
            // process exited. Bounded, because a child that inherited the
            // pipe and never closes it must not hang the supervisor.
            _ = outputDrained.wait(timeout: .now() + 2)
        }
        outputPipe.fileHandleForReading.readabilityHandler = nil

        processLock.lock()
        currentProcess = nil
        processLock.unlock()
        try? PortKeeperRuntimeRegistry.clearRecordedProcess(for: tunnel.name, matching: process.processIdentifier)

        if let authenticationFailure = runState.consumeAuthenticationFailure() {
            throw AuthenticationFailureError(message: authenticationFailure)
        }

        return RunResult(
            exitCode: process.terminationStatus,
            diagnosticMessage: runState.currentDiagnostic(),
            didConnect: didConnect
        )
    }

    private static func isAuthenticationFailureLine(_ line: String) -> Bool {
        let normalized = line.lowercased()
        return normalized.contains("permission denied") ||
            normalized.contains("authentication failed") ||
            normalized.contains("incorrect password") ||
            normalized.contains("invalid password") ||
            normalized.contains("access denied")
    }

    private static func isDiagnosticFailureLine(_ line: String) -> Bool {
        let normalized = line.lowercased()
        return normalized.contains("address already in use") ||
            normalized.contains("cannot listen to port") ||
            normalized.contains("could not request local forwarding") ||
            normalized.contains("could not resolve hostname") ||
            normalized.contains("nodename nor servname") ||
            normalized.contains("temporary failure in name resolution") ||
            normalized.contains("operation timed out") ||
            normalized.contains("connection timed out") ||
            normalized.contains("network is unreachable") ||
            normalized.contains("no route to host") ||
            normalized.contains("connection refused") ||
            normalized.contains("connection closed") ||
            normalized.contains("connection reset") ||
            normalized.contains("broken pipe") ||
            normalized.contains("host key verification failed") ||
            normalized.contains("remote host identification has changed") ||
            // The remote refused to bind a -R forward's port (usually a stale
            // reverse-forward listener from an earlier session). With
            // ExitOnForwardFailure this exits ssh, so without capturing it the
            // tunnel just loops on an opaque "exited code 0".
            normalized.contains("remote port forwarding failed")
    }

    private func waitForForwardReadiness(process: Process, runState: RunState) -> Bool {
        let probeTargets = tunnel.forwards.compactMap { forward -> (String, Int)? in
            switch forward.kind {
            case .local, .dynamic:
                let bindAddress = normalizedProbeHost(forward.bindAddress)
                return (bindAddress, forward.listenPort)
            case .remote:
                return nil
            }
        }

        guard !probeTargets.isEmpty else {
            // Remote-only forwards: no local port to probe. Give ssh a moment to fail-fast,
            // then treat a still-running process as connected.
            let warmupDeadline = Date().addingTimeInterval(2)
            while process.isRunning && runState.currentDiagnostic() == nil && Date() < warmupDeadline {
                usleep(150_000)
            }
            return process.isRunning && runState.currentDiagnostic() == nil
        }

        // Brief warmup so ssh has a chance to fail-fast on bind conflicts before
        // we mistake another process listening on the same port for our forward.
        let warmupDeadline = Date().addingTimeInterval(0.4)
        while process.isRunning && runState.currentDiagnostic() == nil && Date() < warmupDeadline {
            usleep(100_000)
        }
        guard process.isRunning, runState.currentDiagnostic() == nil else {
            return false
        }

        let deadline = Date().addingTimeInterval(TimeInterval(max(tunnel.serverAliveInterval, 10)))
        while process.isRunning && runState.currentDiagnostic() == nil && Date() < deadline {
            if probeTargets.contains(where: { processOwnsListener(process, port: $0.1) && PortProbe.canConnect(host: $0.0, port: $0.1) }) {
                return true
            }
            usleep(200_000)
        }

        return false
    }

    private func processOwnsListener(_ process: Process, port: Int) -> Bool {
        guard process.isRunning else {
            return false
        }

        let lsof = Process()
        lsof.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        lsof.arguments = [
            "-nP",
            "-a",
            "-p", "\(process.processIdentifier)",
            "-iTCP:\(port)",
            "-sTCP:LISTEN",
        ]
        lsof.standardOutput = Pipe()
        lsof.standardError = Pipe()

        do {
            try lsof.run()
            lsof.waitUntilExit()
            return lsof.terminationStatus == 0
        } catch {
            // "Not verified" — a launch failure must not report a foreign
            // listener as ours (the false green this check exists to prevent).
            // The readiness loop polls again in 200ms, so a transient failure
            // costs one iteration, not the connection.
            logger("[\(tunnel.name)] could not verify listener ownership (lsof failed to launch: \(error.localizedDescription))")
            return false
        }
    }

    private func normalizedProbeHost(_ host: String?) -> String {
        let trimmed = host?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if trimmed.isEmpty || trimmed == "localhost" || trimmed == "127.0.0.1" || trimmed == "::1" || trimmed == "*" || trimmed == "0.0.0.0" {
            return "127.0.0.1"
        }
        return host ?? "127.0.0.1"
    }

    private func terminateCurrentProcess() {
        processLock.lock()
        let process = currentProcess
        processLock.unlock()

        guard let process else {
            return
        }

        if process.isRunning {
            process.terminate()
        }
    }
}

private struct RunResult {
    let exitCode: Int32
    let diagnosticMessage: String?
    /// Whether this run reached forward readiness — resets the retry backoff.
    let didConnect: Bool
}

private final class RunState: @unchecked Sendable {
    private let lock = NSLock()
    private var authenticationFailureMessage: String?
    private var diagnosticMessage: String?

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
