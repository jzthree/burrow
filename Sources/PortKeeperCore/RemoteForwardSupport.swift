import Foundation

/// Ordering helpers shared by the app and its tests.
public enum OrderingSupport {
    /// Sort `items` (keyed by `key`) by a stored order of keys. Items whose key
    /// appears in `order` come first, in that order; the rest keep their
    /// original relative position after them. Unknown keys in `order` are
    /// ignored. Stable and total, so a partial or stale order never drops items.
    public static func ordered<T>(_ items: [T], by order: [String], key: (T) -> String) -> [T] {
        let rank = Dictionary(order.enumerated().map { ($0.element, $0.offset) }, uniquingKeysWith: { first, _ in first })
        return items.enumerated().sorted { lhs, rhs in
            let l = rank[key(lhs.element)]
            let r = rank[key(rhs.element)]
            switch (l, r) {
            case let (l?, r?): return l < r
            case (_?, nil): return true       // known before unknown
            case (nil, _?): return false
            case (nil, nil): return lhs.offset < rhs.offset // both unknown: stable
            }
        }.map(\.element)
    }
}

/// Handling for `-R` (reverse) forwards whose port the remote refuses to bind
/// — the remote mirror of Burrow's local stale-listener reclaim. Almost always
/// a leftover reverse-forward listener from an earlier session (an
/// `ssh -N -R <port>:…` that is still alive on the remote), so a new tunnel
/// can't bind the same port and, with ExitOnForwardFailure, exits on sight.
public enum RemoteForwardSupport {
    /// The reverse-forward listen port ssh couldn't bind, parsed from ssh's
    /// own message: "remote port forwarding failed for listen port 31703"
    /// (or "Warning: remote port forwarding failed for listen port 31703").
    public static func conflictingPort(in output: String) -> Int? {
        let lowered = output.lowercased()
        guard lowered.contains("remote port forwarding failed") else {
            return nil
        }
        guard let range = lowered.range(of: "listen port ") else {
            // Fall back to the tunnel's declared reverse port if ssh didn't
            // name one; the caller supplies it.
            return nil
        }
        let digits = lowered[range.upperBound...].prefix { $0.isNumber }
        return Int(digits)
    }

    /// The first reverse (`-R`) forward's listen port, if the tunnel has one.
    public static func reverseForwardPort(of tunnel: TunnelConfig) -> Int? {
        tunnel.forwards.first { $0.kind == .remote }?.listenPort
    }

    /// A shell command that frees `port` on the remote by terminating the
    /// process holding it — the user's own stale reverse-forward listener.
    /// Tries `fuser` first (kills only processes the caller can signal), then
    /// falls back to `ss`-derived pids. Deliberately scoped to the one port
    /// the tunnel is trying to reclaim.
    public static func freePortCommand(_ port: Int) -> String {
        """
        (fuser -k \(port)/tcp 2>/dev/null) || \
        (for p in $(ss -Hltnp \"sport = :\(port)\" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do kill \"$p\" 2>/dev/null; done); \
        sleep 1; \
        if ss -Hltn \"sport = :\(port)\" 2>/dev/null | grep -q :\(port); then echo BURROW_PORT_BUSY; else echo BURROW_PORT_FREE; fi
        """
    }
}

/// Runs `/usr/bin/ssh` with the given arguments and captures its output.
/// Blocking — call off the main thread.
public enum RemoteCommandRunner {
    public struct Result: Sendable {
        public let exitCode: Int32
        public let standardOutput: String
        public let standardError: String
    }

    public static func run(arguments: [String], executablePath: String = "/usr/bin/ssh") -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        do {
            try process.run()
        } catch {
            return Result(exitCode: -1, standardOutput: "", standardError: error.localizedDescription)
        }
        // Drain before waiting so a large banner can't deadlock the pipe.
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(
            exitCode: process.terminationStatus,
            standardOutput: String(data: outData, encoding: .utf8) ?? "",
            standardError: String(data: errData, encoding: .utf8) ?? ""
        )
    }
}
