import Darwin
import Foundation

public enum PortKeeperRuntimeRegistry {
    public static func reclaimOwnedProcess(
        for tunnel: TunnelConfig,
        executablePath: String = "/usr/bin/ssh",
        logger: ((String) -> Void)? = nil,
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) throws {
        let pidFileURL = try pidFileURL(for: tunnel.name, fileManager: fileManager, runtimeDirectory: runtimeDirectory)
        if fileManager.fileExists(atPath: pidFileURL.path) {
            let recordedPID = try readPID(from: pidFileURL)
            guard recordedPID > 0, recordedPID != getpid() else {
                try? fileManager.removeItem(at: pidFileURL)
                try reclaimOwnedForwardProcesses(for: tunnel, executablePath: executablePath, logger: logger)
                return
            }

            guard processExists(recordedPID) else {
                try? fileManager.removeItem(at: pidFileURL)
                try reclaimOwnedForwardProcesses(for: tunnel, executablePath: executablePath, logger: logger)
                return
            }

            guard let command = processCommand(for: recordedPID),
                  commandLooksOwned(command, tunnel: tunnel, executablePath: executablePath) else {
                try? fileManager.removeItem(at: pidFileURL)
                try reclaimOwnedForwardProcesses(for: tunnel, executablePath: executablePath, logger: logger)
                return
            }

            logger?("[\(tunnel.name)] reclaiming stale ssh process \(recordedPID).")
            kill(recordedPID, SIGTERM)
            waitForExit(of: recordedPID, timeout: 2.0)
            if processExists(recordedPID) {
                kill(recordedPID, SIGKILL)
                waitForExit(of: recordedPID, timeout: 1.0)
            }

            try? fileManager.removeItem(at: pidFileURL)
        }

        try reclaimOwnedForwardProcesses(for: tunnel, executablePath: executablePath, logger: logger)
    }

    /// The recorded ssh process for this tunnel, if it is still alive and its
    /// command still matches the tunnel's launch shape. Non-destructive — the
    /// adoption counterpart to reclaim: a healthy survivor from a previous run
    /// (quit with "keep running", an update relaunch) can be adopted instead of
    /// killed and restarted, which would needlessly drop the session and, for
    /// reverse forwards, risk the remote port lingering bound.
    public static func recordedOwnedProcess(
        for tunnel: TunnelConfig,
        executablePath: String = "/usr/bin/ssh",
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) -> pid_t? {
        guard let pidFileURL = try? pidFileURL(for: tunnel.name, fileManager: fileManager, runtimeDirectory: runtimeDirectory),
              fileManager.fileExists(atPath: pidFileURL.path),
              let pid = try? readPID(from: pidFileURL),
              pid > 0, pid != getpid(),
              processExists(pid),
              let command = processCommand(for: pid),
              commandLooksOwned(command, tunnel: tunnel, executablePath: executablePath) else {
            return nil
        }
        return pid
    }

    /// A tunnel's ssh process as it exists right now, for *inspection* rather
    /// than ownership: status reporting, drift detection, reload.
    public struct LiveProcess: Sendable, Equatable {
        public let pid: pid_t
        /// The full command line, straight from `ps`.
        public let command: String
        /// What is supervising it, judged from its parent process.
        public let supervisor: Supervisor

        public enum Supervisor: Sendable, Equatable {
            /// The menu-bar app launched it and will restart it.
            case app
            /// A `burrow run` launched it and will restart it.
            case cli
            /// Nothing is watching — its parent is gone (reparented to init)
            /// or is something else entirely. Killing it just leaves it dead.
            case none
        }
    }

    /// The live ssh process for `tunnel`, if there is one.
    ///
    /// Ownership is judged loosely on purpose: the configured forwards may be
    /// exactly what no longer matches (that mismatch is the drift callers are
    /// asking about), so identity rests on the endpoint plus Burrow's launch
    /// shape. The recorded pid is authoritative; the process scan is the
    /// fallback for a lost pid file, and there it also demands a
    /// tunnel-specific fingerprint so two tunnels to the same host can't be
    /// confused for each other.
    public static func liveProcess(
        for tunnel: TunnelConfig,
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) -> LiveProcess? {
        if let pidFileURL = try? pidFileURL(for: tunnel.name, fileManager: fileManager, runtimeDirectory: runtimeDirectory),
           fileManager.fileExists(atPath: pidFileURL.path),
           let pid = try? readPID(from: pidFileURL),
           pid > 0, pid != getpid(), processExists(pid),
           let command = processCommand(for: pid),
           looksLikeTunnelProcess(command, tunnel: tunnel) {
            return LiveProcess(pid: pid, command: command, supervisor: supervisor(of: pid))
        }

        for (pid, command) in processTable() where pid != getpid()
            && looksLikeTunnelProcess(command, tunnel: tunnel)
            && hasTunnelFingerprint(command, tunnel: tunnel) {
            return LiveProcess(pid: pid, command: command, supervisor: supervisor(of: pid))
        }
        return nil
    }

    /// The full command line of a running process, for callers that need to
    /// see what a process was actually launched with (drift, adoption).
    public static func commandLine(of pid: pid_t) -> String? {
        processCommand(for: pid)
    }

    private static func looksLikeTunnelProcess(_ command: String, tunnel: TunnelConfig) -> Bool {
        let remoteTarget = tunnel.user.map { "\($0)@\(tunnel.host)" } ?? tunnel.host
        guard command.contains("ExitOnForwardFailure=yes") else { return false }
        // The remote target is ssh's last argument and contains no spaces, so
        // it survives ps flattening even next to a quoted ProxyCommand.
        return command.split(whereSeparator: \.isWhitespace).last.map(String.init) == remoteTarget
    }

    /// Something in the command line that belongs to *this* tunnel and no
    /// other: its own known-hosts file, or one of its forwards.
    private static func hasTunnelFingerprint(_ command: String, tunnel: TunnelConfig) -> Bool {
        let safeName = tunnel.name.replacingOccurrences(of: "/", with: "_")
        if command.contains("/\(safeName).known_hosts") {
            return true
        }
        return tunnel.forwards.contains { command.contains(forwardOwnershipFragment($0)) }
    }

    private static func supervisor(of pid: pid_t) -> LiveProcess.Supervisor {
        guard let parent = parentPID(of: pid), parent > 1,
              let command = processCommand(for: parent) else {
            return .none
        }
        if command.contains("Burrow.app/Contents/MacOS/") || command.contains("/BurrowApp") {
            return .app
        }
        // The CLI runs as `burrow …` however it was invoked (installed binary,
        // `swift run`, a .build path), so match the executable's own name.
        let executable = command.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? command
        if (executable as NSString).lastPathComponent == "burrow" {
            return .cli
        }
        return .none
    }

    private static func parentPID(of pid: pid_t) -> pid_t? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-p", "\(pid)", "-o", "ppid="]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return text.flatMap { pid_t($0) }
        } catch {
            return nil
        }
    }

    /// Ends one specific process, without the command scan `reclaimOwnedProcess`
    /// also does. Use it when the pid is already known and a replacement may be
    /// starting concurrently: the scan matches on launch *shape*, so it can't
    /// tell the process being stopped from the one taking its place.
    public static func terminateProcess(
        _ pid: pid_t,
        for tunnelName: String,
        logger: ((String) -> Void)? = nil,
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) {
        guard pid > 0, pid != getpid(), processExists(pid) else {
            try? clearRecordedProcess(for: tunnelName, matching: pid, fileManager: fileManager, runtimeDirectory: runtimeDirectory)
            return
        }
        logger?("[\(tunnelName)] stopping ssh process \(pid).")
        kill(pid, SIGTERM)
        waitForExit(of: pid, timeout: 2.0)
        if processExists(pid) {
            kill(pid, SIGKILL)
            waitForExit(of: pid, timeout: 1.0)
        }
        try? clearRecordedProcess(for: tunnelName, matching: pid, fileManager: fileManager, runtimeDirectory: runtimeDirectory)
    }

    public static func recordProcess(
        _ pid: pid_t,
        for tunnelName: String,
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) throws {
        let pidFileURL = try pidFileURL(for: tunnelName, fileManager: fileManager, runtimeDirectory: runtimeDirectory)
        try fileManager.createDirectory(at: pidFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "\(pid)\n".write(to: pidFileURL, atomically: true, encoding: .utf8)
    }

    public static func clearRecordedProcess(
        for tunnelName: String,
        matching pid: pid_t? = nil,
        fileManager: FileManager = .default,
        runtimeDirectory: URL? = nil
    ) throws {
        let pidFileURL = try pidFileURL(for: tunnelName, fileManager: fileManager, runtimeDirectory: runtimeDirectory)
        guard fileManager.fileExists(atPath: pidFileURL.path) else {
            return
        }

        if let pid {
            let recordedPID = try readPID(from: pidFileURL)
            guard recordedPID == pid else {
                return
            }
        }

        try? fileManager.removeItem(at: pidFileURL)
    }

    private static func pidFileURL(
        for tunnelName: String,
        fileManager: FileManager,
        runtimeDirectory: URL?
    ) throws -> URL {
        let directory: URL
        if let runtimeDirectory {
            directory = runtimeDirectory
        } else {
            let baseURL = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Burrow", isDirectory: true)
                .appendingPathComponent("runtime", isDirectory: true)
            directory = baseURL
        }
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        let safeName = tunnelName.replacingOccurrences(of: "/", with: "_")
        return directory.appendingPathComponent("\(safeName).pid", isDirectory: false)
    }

    private static func readPID(from pidFileURL: URL) throws -> pid_t {
        let rawValue = try String(contentsOf: pidFileURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let pid = pid_t(rawValue) else {
            throw NSError(domain: "BurrowRuntimeRegistry", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid pid file contents for \(pidFileURL.lastPathComponent)",
            ])
        }
        return pid
    }

    private static func processExists(_ pid: pid_t) -> Bool {
        if kill(pid, 0) == 0 {
            return true
        }
        return errno != ESRCH
    }

    private static func processCommand(for pid: pid_t) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-p", "\(pid)", "-o", "command="]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return nil
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return nil
        }
    }

    private static func reclaimOwnedForwardProcesses(
        for tunnel: TunnelConfig,
        executablePath: String,
        logger: ((String) -> Void)?
    ) throws {
        for (pid, command) in processTable() {
            guard pid > 0, pid != getpid(), processExists(pid) else {
                continue
            }
            guard commandLooksOwned(command, tunnel: tunnel, executablePath: executablePath) else {
                continue
            }

            logger?("[\(tunnel.name)] reclaiming stale ssh process \(pid) by command match.")
            kill(pid, SIGTERM)
            waitForExit(of: pid, timeout: 2.0)
            if processExists(pid) {
                kill(pid, SIGKILL)
                waitForExit(of: pid, timeout: 1.0)
            }
        }
    }

    private static func processTable() -> [(pid: pid_t, command: String)] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,command="]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return []
            }

            guard let output = String(data: data, encoding: .utf8) else {
                return []
            }

            return output.split(whereSeparator: \.isNewline).compactMap { line -> (pid_t, String)? in
                let rawLine = String(line).trimmingCharacters(in: .whitespaces)
                guard let separator = rawLine.firstIndex(where: \.isWhitespace) else {
                    return nil
                }
                let rawPID = String(rawLine[..<separator])
                guard let pid = pid_t(rawPID) else {
                    return nil
                }
                let command = String(rawLine[separator...]).trimmingCharacters(in: .whitespaces)
                return (pid, command)
            }
        } catch {
            return []
        }
    }

    private static func commandLooksOwned(_ command: String, tunnel: TunnelConfig, executablePath: String) -> Bool {
        let remoteTarget = tunnel.user.map { "\($0)@\(tunnel.host)" } ?? tunnel.host
        let ownershipFragments = [
            executablePath,
            remoteTarget,
            "-p \(tunnel.sshPort)",
            "ExitOnForwardFailure=yes",
            "UserKnownHostsFile=",
        ]

        guard ownershipFragments.allSatisfy({ command.contains($0) }) else {
            return false
        }

        // A forward-less tunnel (an SSH host row) has no -L/-R/-D to match on;
        // fall back to its per-tunnel known-hosts file, which is just as
        // specific. Requiring a forward here would mean reclaim never matches
        // such tunnels and silently strands their ssh.
        guard !tunnel.forwards.isEmpty else {
            return command.contains("/\(tunnel.name).known_hosts")
        }

        return tunnel.forwards.contains { forward in
            command.contains(forwardOwnershipFragment(forward))
        }
    }

    private static func forwardOwnershipFragment(_ forward: ForwardSpec) -> String {
        let bindPrefix = forward.bindAddress.map { "\($0):" } ?? ""
        switch forward.kind {
        case .local:
            guard let destinationHost = forward.destinationHost,
                  let destinationPort = forward.destinationPort else {
                return "-L \(bindPrefix)\(forward.listenPort):"
            }
            return "-L \(bindPrefix)\(forward.listenPort):\(destinationHost):\(destinationPort)"
        case .remote:
            guard let destinationHost = forward.destinationHost,
                  let destinationPort = forward.destinationPort else {
                return "-R \(bindPrefix)\(forward.listenPort):"
            }
            return "-R \(bindPrefix)\(forward.listenPort):\(destinationHost):\(destinationPort)"
        case .dynamic:
            return "-D \(bindPrefix)\(forward.listenPort)"
        }
    }

    private static func waitForExit(of pid: pid_t, timeout: TimeInterval) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !processExists(pid) {
                return
            }
            usleep(100_000)
        }
    }
}
