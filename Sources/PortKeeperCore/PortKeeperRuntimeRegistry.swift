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
