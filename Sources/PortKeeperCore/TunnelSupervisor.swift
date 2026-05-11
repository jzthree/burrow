import Darwin
import Foundation

public enum TunnelRuntimeEvent: Sendable {
    case starting
    case connected
    case exited(Int32)
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
                    let exitCode = try runOnce()
                    if Task.isCancelled {
                        break
                    }
                    eventHandler(.exited(exitCode))
                    logger("[\(tunnel.name)] ssh exited with code \(exitCode). Reconnecting in \(tunnel.reconnectDelaySeconds)s.")
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

    private func runOnce() throws -> Int32 {
        try PortKeeperRuntimeRegistry.reclaimOwnedProcess(
            for: tunnel,
            executablePath: executablePath,
            logger: logger
        )

        final class RunState: @unchecked Sendable {
            private let lock = NSLock()
            private var authenticationFailureMessage: String?

            func recordAuthenticationFailure(_ message: String) {
                lock.lock()
                if authenticationFailureMessage == nil {
                    authenticationFailureMessage = message
                }
                lock.unlock()
            }

            func consumeAuthenticationFailure() -> String? {
                lock.lock()
                let message = authenticationFailureMessage
                lock.unlock()
                return message
            }
        }

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
        let didConnect = waitForForwardReadiness(process: process)
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

        return process.terminationStatus
    }

    private static func isAuthenticationFailureLine(_ line: String) -> Bool {
        let normalized = line.lowercased()
        return normalized.contains("permission denied") ||
            normalized.contains("authentication failed") ||
            normalized.contains("incorrect password") ||
            normalized.contains("invalid password") ||
            normalized.contains("access denied")
    }

    private func waitForForwardReadiness(process: Process) -> Bool {
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
            while process.isRunning && Date() < warmupDeadline {
                usleep(150_000)
            }
            return process.isRunning
        }

        // Brief warmup so ssh has a chance to fail-fast on bind conflicts before
        // we mistake another process listening on the same port for our forward.
        let warmupDeadline = Date().addingTimeInterval(0.4)
        while process.isRunning && Date() < warmupDeadline {
            usleep(100_000)
        }
        guard process.isRunning else {
            return false
        }

        let deadline = Date().addingTimeInterval(TimeInterval(max(tunnel.serverAliveInterval, 10)))
        let stableDuration: TimeInterval = 1.0
        while process.isRunning && Date() < deadline {
            if probeTargets.contains(where: { canConnect(host: $0.0, port: $0.1) }) {
                let stableUntil = Date().addingTimeInterval(stableDuration)
                var remainedHealthy = true

                while process.isRunning && Date() < stableUntil {
                    if !probeTargets.contains(where: { canConnect(host: $0.0, port: $0.1) }) {
                        remainedHealthy = false
                        break
                    }
                    usleep(150_000)
                }

                if remainedHealthy && process.isRunning {
                    return true
                }
            }
            usleep(200_000)
        }

        return false
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
