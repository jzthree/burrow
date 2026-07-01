import Foundation

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
    /// Whether a live master connection exists for the alias.
    public static func isWarm(alias: String) -> Bool {
        run(["-O", "check", alias], environment: nil, inheritStdio: false, wait: true) == 0
    }

    /// Establishes the master. Returns true once ssh has authenticated and
    /// backgrounded itself (-f). `environment` carries the askpass that answers
    /// a password and/or 2FA prompt. Blocking — call off the main thread.
    @discardableResult
    public static func warm(alias: String, environment: [String: String]?) -> Bool {
        run(["-f", "-N", "-o", "ConnectTimeout=20", alias], environment: environment, inheritStdio: false, wait: true) == 0
    }

    /// Foreground warm: inherits the caller's terminal so the user can complete
    /// a password / 2FA prompt (or approve a Duo push) directly. `-fN`
    /// backgrounds the master after authentication. Returns ssh's exit code.
    @discardableResult
    public static func warmForeground(alias: String) -> Int32 {
        run(["-f", "-N", "-o", "ConnectTimeout=45", alias], environment: nil, inheritStdio: true, wait: true)
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
        if let environment {
            // Inherit the user's env (PATH etc.) and overlay the askpass keys.
            var merged = ProcessInfo.processInfo.environment
            for (key, value) in environment {
                merged[key] = value
            }
            process.environment = merged
        }
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
}
