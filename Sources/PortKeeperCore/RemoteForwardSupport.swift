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

    /// The port named by a "Connected without -R 31703 …" status — a tunnel
    /// that came up minus one reverse forward because the remote wouldn't
    /// release it. Lets a degraded-but-connected tunnel keep offering the
    /// same "free the port" action a failed one does.
    public static func degradedForwardPort(in status: String) -> Int? {
        guard let range = status.range(of: "without -R ") else {
            return nil
        }
        return Int(status[range.upperBound...].prefix { $0.isNumber })
    }

    /// The first reverse (`-R`) forward's listen port, if the tunnel has one.
    public static func reverseForwardPort(of tunnel: TunnelConfig) -> Int? {
        tunnel.forwards.first { $0.kind == .remote }?.listenPort
    }

    /// A shell command that frees `port` on the remote by terminating the
    /// process holding it — the user's own stale reverse-forward listener,
    /// which on the remote side is the *sshd* serving the abandoned session.
    ///
    /// Holders are discovered three ways because HPC login nodes ship wildly
    /// different toolboxes: `lsof`, `ss` and `fuser`. Each is reported by pid
    /// and command before anything is signalled, so the caller can say what it
    /// killed (or, with `dryRun`, kill nothing and just name the holder — a
    /// stale forward on a shared login node is someone's judgment call).
    /// Deliberately scoped to the one port being reclaimed, and the calling
    /// shell's own process tree is never a candidate.
    public static func freePortCommand(_ port: Int, dryRun: Bool = false) -> String {
        let discover = """
        found=""
        if command -v lsof >/dev/null 2>&1; then found="$found $(lsof -ti tcp:\(port) -sTCP:LISTEN 2>/dev/null)"; fi
        if command -v ss >/dev/null 2>&1; then found="$found $(ss -Hltnp 2>/dev/null | grep -E '[:.]\(port)( |$)' | grep -o 'pid=[0-9]*' | cut -d= -f2)"; fi
        if command -v fuser >/dev/null 2>&1; then found="$found $(fuser -n tcp \(port) 2>/dev/null)"; fi
        pids=$(printf '%s\\n' $found | grep -E '^[0-9]+$' | sort -u)
        for p in $pids; do
          if [ "$p" = "$$" ] || [ "$p" = "$PPID" ]; then continue; fi
          echo "BURROW_PORT_HOLDER $p $(ps -o command= -p $p 2>/dev/null | cut -c1-120)"
        done
        """

        let verify = """
        if command -v ss >/dev/null 2>&1; then
          if ss -Hltn 2>/dev/null | grep -qE '[:.]\(port)( |$)'; then echo BURROW_PORT_BUSY; else echo BURROW_PORT_FREE; fi
        elif command -v lsof >/dev/null 2>&1; then
          if lsof -ti tcp:\(port) -sTCP:LISTEN >/dev/null 2>&1; then echo BURROW_PORT_BUSY; else echo BURROW_PORT_FREE; fi
        else
          echo BURROW_PORT_UNVERIFIED
        fi
        """

        guard !dryRun else {
            return """
            \(discover)
            \(verify)
            """
        }

        return """
        \(discover)
        for p in $pids; do
          if [ "$p" = "$$" ] || [ "$p" = "$PPID" ]; then continue; fi
          kill "$p" 2>/dev/null || echo "BURROW_PORT_KILL_FAILED $p"
        done
        sleep 1
        for p in $pids; do
          if [ "$p" = "$$" ] || [ "$p" = "$PPID" ]; then continue; fi
          if kill -0 "$p" 2>/dev/null; then kill -9 "$p" 2>/dev/null; fi
        done
        sleep 1
        \(verify)
        """
    }

    /// What a `freePortCommand` run actually achieved.
    public struct PortFreeOutcome: Sendable, Equatable {
        public enum Status: Sendable, Equatable {
            /// The port is free now.
            case freed
            /// Something still holds it — `holders` says what, when the host
            /// would tell us.
            case busy
            /// The kills ran but the host has neither `ss` nor `lsof`, so
            /// "is it free now?" can't be answered.
            case unverified
            /// The command never ran (couldn't reach the host).
            case unreachable
        }

        public let status: Status
        /// "12345 (sshd: alice@notty)" for each process found holding the port.
        public let holders: [String]
        /// Pids that refused to die — a holder owned by another user.
        public let unkillable: [String]
        /// stderr's last line when the host couldn't be reached.
        public let detail: String?

        public init(status: Status, holders: [String] = [], unkillable: [String] = [], detail: String? = nil) {
            self.status = status
            self.holders = holders
            self.unkillable = unkillable
            self.detail = detail
        }

        /// One line naming who held the port, for logs and status messages.
        public var holderSummary: String? {
            guard !holders.isEmpty else { return nil }
            return holders.joined(separator: ", ")
        }
    }

    public static func parseFreePortOutput(standardOutput: String, standardError: String) -> PortFreeOutcome {
        var holders: [String] = []
        var unkillable: [String] = []
        var status: PortFreeOutcome.Status?

        for line in standardOutput.split(whereSeparator: \.isNewline).map(String.init) {
            if line.hasPrefix("BURROW_PORT_HOLDER ") {
                let rest = String(line.dropFirst("BURROW_PORT_HOLDER ".count))
                    .trimmingCharacters(in: .whitespaces)
                guard let separator = rest.firstIndex(where: \.isWhitespace) else {
                    holders.append(rest)
                    continue
                }
                let pid = String(rest[..<separator])
                let command = String(rest[separator...]).trimmingCharacters(in: .whitespaces)
                holders.append(command.isEmpty ? pid : "\(pid) (\(command))")
            } else if line.hasPrefix("BURROW_PORT_KILL_FAILED ") {
                unkillable.append(String(line.dropFirst("BURROW_PORT_KILL_FAILED ".count)).trimmingCharacters(in: .whitespaces))
            } else if line.contains("BURROW_PORT_FREE") {
                status = .freed
            } else if line.contains("BURROW_PORT_BUSY") {
                status = .busy
            } else if line.contains("BURROW_PORT_UNVERIFIED") {
                status = .unverified
            }
        }

        guard let status else {
            let detail = standardError.split(whereSeparator: \.isNewline).last.map(String.init)
            return PortFreeOutcome(status: .unreachable, holders: holders, unkillable: unkillable, detail: detail)
        }
        return PortFreeOutcome(status: status, holders: holders, unkillable: unkillable, detail: nil)
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
