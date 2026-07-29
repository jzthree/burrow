import Foundation

/// Persistent, append-only text log of gateway activity: every openconnect
/// output line and every state transition, timestamped. The in-app popover
/// keeps only the last ~20 lines in memory; this file is the durable answer to
/// "why did the VPN disconnect half an hour ago?".
enum GatewayLog {
    static var logURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("logs", isDirectory: true)
            .appendingPathComponent("gateway.log", isDirectory: false)
    }

    /// One serial queue so concurrent appends can't interleave partial lines.
    private static let queue = DispatchQueue(label: "burrow.gateway-log", qos: .utility)
    private static let maxBytes = 1_500_000

    static func append(gateway: String, _ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let line = "\(ISO8601DateFormatter().string(from: Date())) [\(gateway)] \(trimmed)\n"
        queue.async {
            let url = logURL
            let fm = FileManager.default
            try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            // Cap growth: roll to .1 (replacing any older roll) — at most ~3 MB.
            if let size = (try? fm.attributesOfItem(atPath: url.path)[.size]) as? Int, size > maxBytes {
                let rolled = url.deletingLastPathComponent().appendingPathComponent("gateway.1.log")
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
}
