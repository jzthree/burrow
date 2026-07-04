import Foundation

/// The result of a warm attempt: whether ssh authenticated and backgrounded,
/// plus whatever it wrote to stderr (banners, prompts, error lines) so callers
/// can tell "wrong code" from "network down" from "host key changed".
public struct WarmOutcome: Sendable {
    public let succeeded: Bool
    public let output: String

    public init(succeeded: Bool, output: String) {
        self.succeeded = succeeded
        self.output = output
    }
}

/// Classifies why a warm attempt failed from ssh's stderr, so the UI can say
/// "wrong code" vs "couldn't reach the host" vs "host key changed" instead of a
/// single generic message.
public enum WarmDiagnosis {
    public enum Kind: Sendable {
        case authRejected
        case network
        case hostKey
        case noMaster
        case unknown
    }

    public static func classify(_ output: String) -> Kind {
        let text = output.lowercased()
        if text.contains("host key verification failed")
            || text.contains("remote host identification has changed") {
            return .hostKey
        }
        if text.contains("permission denied")
            || text.contains("authentication failed")
            || text.contains("too many authentication failures")
            || text.contains("keyboard-interactive") {
            return .authRejected
        }
        if text.contains("connection timed out")
            || text.contains("operation timed out")
            || text.contains("could not resolve")
            || text.contains("name or service not known")
            || text.contains("connection refused")
            || text.contains("network is unreachable")
            || text.contains("no route to host") {
            return .network
        }
        return .unknown
    }

    /// A short human reason for a failed warm, preferring ssh's own last line
    /// when we can't categorize it.
    public static func shortReason(_ output: String) -> String {
        switch classify(output) {
        case .authRejected: return "the code or password was rejected"
        case .network: return "couldn't reach the host"
        case .hostKey: return "the host key was rejected"
        case .noMaster: return "no reusable master (add ControlPersist)"
        case .unknown:
            let lastLine = output
                .split(whereSeparator: { $0.isNewline })
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .last(where: { !$0.isEmpty })
            return lastLine ?? "sign-in failed"
        }
    }
}

/// Keeps an SSH host "warm" by establishing a background ControlMaster, so
/// opening a terminal (or running `ssh <alias>` anywhere) is instant and any
/// 2FA is entered once. It deliberately forwards nothing — it's just a warm,
/// authenticated session.
///
/// Burrow runs `ssh -fN <alias>` and lets the host's own ssh-config
/// ControlMaster/ControlPath/ControlPersist own the socket, so a plain
/// `ssh <alias>` in any terminal reuses the same master (and it survives
/// Burrow quitting when ControlPersist is set). Status and teardown go through
/// ssh's own control commands (`-O check` / `-O exit`).
public enum SSHHostWarmer {
    // A brand-new host would otherwise stall on the unanswerable host-key
    // yes/no prompt; accept-new pins it on first sight (same as tunnels do).
    private static let baseOptions = ["-o", "StrictHostKeyChecking=accept-new"]

    // The master holds a benign long-running remote session instead of a bare
    // -N, so it's pinned exactly like an interactive session you keep open —
    // ControlPersist's idle timer never starts. The remote sleep dies on
    // disconnect (SIGHUP), so nothing lingers past the connection; a week is far
    // longer than a laptop stays continuously connected.
    private static let keepAliveSeconds = 604_800

    /// Whether a live master *process* exists for the alias. Note this can report
    /// true for a master whose TCP died on sleep — see `isResponsive`.
    public static func isWarm(alias: String) -> Bool {
        run(["-O", "check", alias], environment: nil, inheritStdio: false, wait: true) == 0
    }

    /// Whether the master answers a real multiplexed round-trip quickly. Catches
    /// a master whose connection died (e.g. on sleep) but whose process lingers
    /// for up to ServerAliveCountMax×Interval before ssh notices.
    public static func isResponsive(alias: String) -> Bool {
        guard isWarm(alias: alias) else { return false }
        // Reuse the existing master only; a short client-side timeout bounds a
        // stale master that would otherwise hang until its own keepalive gives up.
        return runWithTimeout(["-o", "BatchMode=yes", alias, "true"], seconds: 6) == 0
    }

    /// Establishes the master, capturing ssh's output for diagnosis. Succeeds
    /// once ssh has authenticated and backgrounded itself (-f). `environment`
    /// carries the askpass that answers a password and/or 2FA prompt. Blocking —
    /// call off the main thread.
    public static func warm(alias: String, environment: [String: String]?) -> WarmOutcome {
        let arguments = ["-f", "-o", "ConnectTimeout=20"] + baseOptions + [alias, "sleep", "\(keepAliveSeconds)"]
        let (code, output) = runCapturing(arguments, environment: environment)
        return WarmOutcome(succeeded: code == 0, output: output)
    }

    /// Foreground warm: inherits the caller's terminal so the user can complete
    /// a password / 2FA prompt (or approve a Duo push) directly. `-f` backgrounds
    /// the pinned master after authentication. Returns ssh's exit code.
    @discardableResult
    public static func warmForeground(alias: String) -> Int32 {
        run(["-f", "-o", "ConnectTimeout=45"] + baseOptions + [alias, "sleep", "\(keepAliveSeconds)"], environment: nil, inheritStdio: true, wait: true)
    }

    /// Tears the master down.
    public static func cool(alias: String) {
        _ = run(["-O", "exit", alias], environment: nil, inheritStdio: false, wait: true)
    }

    @discardableResult
    private static func run(
        _ arguments: [String],
        environment: [String: String]?,
        inheritStdio: Bool,
        wait: Bool
    ) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = arguments
        if !inheritStdio {
            // Capture (and discard) the small control-command output; the
            // caller doesn't want it on the terminal.
            process.standardOutput = Pipe()
            process.standardError = Pipe()
        }
        applyEnvironment(environment, to: process)
        do {
            try process.run()
        } catch {
            return -1
        }
        guard wait else {
            return 0
        }
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// Runs ssh capturing stderr for diagnosis. stdout goes to /dev/null (ssh
    /// writes banners/errors to stderr); stderr is drained before waiting so a
    /// large banner can't deadlock the pipe.
    private static func runCapturing(
        _ arguments: [String],
        environment: [String: String]?
    ) -> (code: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        let errorPipe = Pipe()
        process.standardError = errorPipe
        applyEnvironment(environment, to: process)
        do {
            try process.run()
        } catch {
            return (-1, "failed to launch ssh: \(error.localizedDescription)")
        }
        // -f closes ssh's fds when it backgrounds, so this reaches EOF.
        let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        return (process.terminationStatus, output.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Runs ssh with a hard client-side timeout: if it hasn't exited within
    /// `seconds`, it's terminated and 124 is returned. Used to bound a probe
    /// against a stale master that could otherwise hang for hours.
    private static func runWithTimeout(_ arguments: [String], seconds: Double) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = arguments
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return -1
        }
        let deadline = Date().addingTimeInterval(seconds)
        while process.isRunning {
            if Date() >= deadline {
                process.terminate()
                return 124
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return process.terminationStatus
    }

    private static func applyEnvironment(_ environment: [String: String]?, to process: Process) {
        guard let environment else { return }
        // Inherit the user's env (PATH etc.) and overlay the askpass keys.
        var merged = ProcessInfo.processInfo.environment
        for (key, value) in environment {
            merged[key] = value
        }
        process.environment = merged
    }
}
