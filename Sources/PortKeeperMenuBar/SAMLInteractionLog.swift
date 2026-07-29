import Foundation

/// Append-only JSONL log of how SAML sign-ins actually go: pages visited, which
/// controls the user touches (as locators), timing, and outcomes. The point is
/// observation — a few days of real flows to design recipe replay against.
///
/// Privacy: never logs a password, code, cookie, or any typed value — only
/// element locators (tag/name/label), URL host+path (query stripped; it can
/// carry SAML payloads), event names, and timings. Local file only.
enum SAMLInteractionLog {
    static var logURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("logs", isDirectory: true)
            .appendingPathComponent("saml-interactions.jsonl", isDirectory: false)
    }

    /// One serial queue so concurrent appends can't interleave partial lines.
    private static let queue = DispatchQueue(label: "burrow.saml-log", qos: .utility)
    private static let maxBytes = 1_500_000

    /// Appends one event line. `details` values must be JSON-encodable scalars
    /// (String/Int/Double/Bool); anything else is dropped.
    static func append(_ event: String, gateway: String, _ details: [String: Any] = [:]) {
        var record: [String: Any] = [
            "ts": ISO8601DateFormatter().string(from: Date()),
            "gw": gateway,
            "ev": event,
        ]
        for (key, value) in details {
            switch value {
            case is String, is Int, is Double, is Bool:
                record[key] = value
            default:
                break
            }
        }
        guard JSONSerialization.isValidJSONObject(record),
              let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else {
            return
        }
        queue.async {
            let url = logURL
            let fm = FileManager.default
            try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            // Cap growth: roll the current file to .1 (replacing any older roll)
            // so there's always at most ~2 files / ~3 MB of history.
            if let size = (try? fm.attributesOfItem(atPath: url.path)[.size]) as? Int, size > maxBytes {
                let rolled = url.deletingLastPathComponent().appendingPathComponent("saml-interactions.1.jsonl")
                try? fm.removeItem(at: rolled)
                try? fm.moveItem(at: url, to: rolled)
            }
            if !fm.fileExists(atPath: url.path) {
                fm.createFile(atPath: url.path, contents: nil)
            }
            guard let handle = try? FileHandle(forWritingTo: url) else { return }
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data + Data("\n".utf8))
        }
    }

    /// Compact one-line element description for the log:
    /// `button#signin name=login "Sign In"`.
    static func describeField(tag: String?, type: String?, name: String?, elementID: String?, label: String?, text: String?) -> String {
        var parts: [String] = []
        var head = (tag ?? "?")
        if let type, !type.isEmpty { head += "[\(type)]" }
        if let elementID, !elementID.isEmpty { head += "#\(elementID)" }
        parts.append(head)
        if let name, !name.isEmpty { parts.append("name=\(name)") }
        if let label, !label.isEmpty { parts.append("aria=\(label)") }
        if let text, !text.isEmpty { parts.append("\"\(text.prefix(40))\"") }
        return parts.joined(separator: " ")
    }

    /// Host + path with the query stripped (SAML payloads ride the query).
    static func describeURL(_ url: URL?) -> String {
        guard let url else { return "?" }
        return (url.host ?? "?") + url.path
    }
}
