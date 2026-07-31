import Foundation
import PortKeeperCore

/// Persistent tunnel lifecycle log: supervisor launches/finishes, reclaim
/// kills, ssh output and exits. The in-app popover keeps only ~20 lines in
/// memory, which loses intermittent lifecycle failures; this file is the
/// durable record. Two guards keep a retry loop from turning it into trash:
///  - LogDeduplicator collapses repeats to one annotated line per 5-minute
///    window per distinct message (digits ignored, so changing pids/backoff
///    delays still count as repeats), preserving the count and span.
///  - Size-capped rotation hard-bounds the total on disk at ~1 MB no matter
///    what the dedup misses.
enum TunnelLog {
    static var logURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("logs", isDirectory: true)
            .appendingPathComponent("tunnel.log", isDirectory: false)
    }

    /// One serial queue so concurrent appends can't interleave partial lines.
    private static let queue = DispatchQueue(label: "burrow.tunnel-log", qos: .utility)
    private static let maxBytes = 512_000
    // Guarded by `queue` — every read and write happens on it.
    nonisolated(unsafe) private static var deduplicator = LogDeduplicator()

    static func append(tunnel: String, _ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let now = Date()
        queue.async {
            guard let line = deduplicator.process(source: tunnel, message: trimmed, at: now) else {
                return
            }
            write("\(ISO8601DateFormatter().string(from: now)) [\(tunnel)] \(line)\n")
        }
    }

    private static func write(_ line: String) {
        let url = logURL
        let fm = FileManager.default
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Cap growth: roll to .1 (replacing any older roll) — at most ~1 MB.
        if let size = (try? fm.attributesOfItem(atPath: url.path)[.size]) as? Int, size > maxBytes {
            let rolled = url.deletingLastPathComponent().appendingPathComponent("tunnel.1.log")
            try? fm.removeItem(at: rolled)
            try? fm.moveItem(at: url, to: rolled)
        }
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
    }
}
