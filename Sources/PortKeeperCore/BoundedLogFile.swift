import Foundation

/// An append-only log file with two hard bounds: repeats are collapsed by
/// `LogDeduplicator`, and the file rotates at a size cap. Burrow's supervisors
/// retry forever, so a log without both bounds turns one bad night into
/// megabytes of the same line.
///
/// Thread-safe: every read and write of the deduplicator and the file happens
/// on the instance's own serial queue.
public final class BoundedLogFile: @unchecked Sendable {
    public let fileURL: URL
    private let maxBytes: Int
    private let queue: DispatchQueue
    private var deduplicator: LogDeduplicator

    public init(
        url: URL,
        maxBytes: Int = 512_000,
        window: TimeInterval = 300,
        label: String = "burrow.bounded-log"
    ) {
        self.fileURL = url
        self.maxBytes = maxBytes
        self.queue = DispatchQueue(label: label, qos: .utility)
        self.deduplicator = LogDeduplicator(window: window)
    }

    /// Appends one line, unless it is a repeat inside its suppression window.
    /// `source` scopes the deduplication (one tunnel's retry storm doesn't
    /// suppress another's identical message).
    public func append(source: String, _ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let now = Date()
        queue.async { [self] in
            guard let line = deduplicator.process(source: source, message: trimmed, at: now) else {
                return
            }
            write("\(ISO8601DateFormatter().string(from: now)) [\(source)] \(line)\n")
        }
    }

    private func write(_ line: String) {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Cap growth: roll to .1 (replacing any older roll) — at most ~2× the cap.
        if let size = (try? fileManager.attributesOfItem(atPath: fileURL.path)[.size]) as? Int, size > maxBytes {
            try? fileManager.removeItem(at: rolledURL)
            try? fileManager.moveItem(at: fileURL, to: rolledURL)
        }
        if !fileManager.fileExists(atPath: fileURL.path) {
            fileManager.createFile(atPath: fileURL.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: fileURL) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
    }

    /// `tunnel.log` → `tunnel.1.log`.
    private var rolledURL: URL {
        let base = fileURL.deletingPathExtension().lastPathComponent
        let ext = fileURL.pathExtension
        let rolledName = ext.isEmpty ? "\(base).1" : "\(base).1.\(ext)"
        return fileURL.deletingLastPathComponent().appendingPathComponent(rolledName, isDirectory: false)
    }

    /// `~/Library/Application Support/Burrow/logs/<name>`.
    public static func logsDirectory(fileManager: FileManager = .default) -> URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("logs", isDirectory: true)
    }
}
