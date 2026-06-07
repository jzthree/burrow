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

public final class TunnelSupervisor: @unchecked Sendable {
    private let tunnel: TunnelConfig
    private let logger: @Sendable (String) -> Void
    private let eventHandler: @Sendable (TunnelRuntimeEvent) -> Void
    private let environment: [String: String]
    private let executablePath: String
    private let captureOutput: Bool
    private let processLock = NSLock()
    private var currentProcess: Process?

    public init(
        tunnel: TunnelConfig,
        logger: @escaping @Sendable (String) -> Void,
        eventHandler: @escaping @Sendable (TunnelRuntimeEvent) -> Void = { _ in },
        environment: [String: String] = [:],
        executablePath: String = "/usr/bin/ssh",
        captureOutput: Bool = true
    ) {
        self.tunnel = tunnel
        self.logger = logger
        self.eventHandler = eventHandler
        self.environment = environment
        self.executablePath = executablePath
        self.captureOutput = captureOutput
    }

    public func run() async {
        await withTaskCancellationHandler(operation: {
            while !Task.isCancelled {
                do {
                    let result = try runOnce()
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.exited(result.exitCode, result.diagnosticMessage))
                    let diagnosticSuffix = result.diagnosticMessage.map { " \($0)" } ?? ""
                    logger("[\(tunnel.name)] ssh exited with code \(result.exitCode).\(diagnosticSuffix) Reconnecting in \(tunnel.reconnectDelaySeconds)s.")
                } catch let error as AuthenticationFailureError {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.authenticationFailed(error.message))
                    logger("[\(tunnel.name)] authentication failed: \(error.message). Stopping retries until credentials are updated.")
                    break
                } catch {
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.failedToStart(error.localizedDescription))
                    logger("[\(tunnel.name)] failed to start: \(error.localizedDescription). Retrying in \(tunnel.reconnectDelaySeconds)s.")
                }

                do {
                    try await Task.sleep(for: .seconds(tunnel.reconnectDelaySeconds))
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
        if captureOutput {
            process.standardOutput = outputPipe
            process.standardError = outputPipe

            outputPipe.fileHandleForReading.readabilityHandler = { [logger, tunnel] handle in
                let data = handle.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
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

        outputPipe.fileHandleForReading.readabilityHandler = nil

        processLock.lock()
        currentProcess = nil
        processLock.unlock()
        try? PortKeeperRuntimeRegistry.clearRecordedProcess(for: tunnel.name, matching: process.processIdentifier)

        if let authenticationFailure = runState.consumeAuthenticationFailure() {
            throw AuthenticationFailureError(message: authenticationFailure)
        }

        return RunResult(exitCode: process.terminationStatus, diagnosticMessage: runState.currentDiagnostic())
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
            normalized.contains("remote host identification has changed")
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
            if probeTargets.contains(where: { processOwnsListener(process, port: $0.1) && canConnect(host: $0.0, port: $0.1) }) {
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
            // Fall back to the older reachability probe if lsof is unavailable.
            return true
        }
    }

    private func normalizedProbeHost(_ host: String?) -> String {
        let trimmed = host?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if trimmed.isEmpty || trimmed == "localhost" || trimmed == "127.0.0.1" || trimmed == "::1" || trimmed == "*" || trimmed == "0.0.0.0" {
            return "127.0.0.1"
        }
        return host ?? "127.0.0.1"
    }

    private func canConnect(host: String, port: Int) -> Bool {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let firstResult = result else {
            return false
        }
        defer { freeaddrinfo(firstResult) }

        var pointer: UnsafeMutablePointer<addrinfo>? = firstResult
        while let current = pointer {
            let socketFD = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol)
            if socketFD >= 0 {
                let connectResult = connect(socketFD, current.pointee.ai_addr, current.pointee.ai_addrlen)
                close(socketFD)
                if connectResult == 0 {
                    return true
                }
            }
            pointer = current.pointee.ai_next
        }

        return false
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
