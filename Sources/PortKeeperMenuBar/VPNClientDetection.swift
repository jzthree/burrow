import Foundation

struct DetectedVPN: Identifiable, Equatable {
    let label: String
    let server: String
    let vpnProtocol: String

    var id: String { "\(vpnProtocol)|\(server)" }
}

/// Best-effort scan of the official VPN clients' on-disk configs so a new
/// gateway can be prefilled instead of typed.
enum VPNClientConfigScanner {
    static func detect() -> [DetectedVPN] {
        var results: [DetectedVPN] = []
        results.append(contentsOf: detectGlobalProtect())
        results.append(contentsOf: detectAnyConnect())

        var seen = Set<String>()
        return results.filter { seen.insert($0.id).inserted }
    }

    // MARK: - GlobalProtect (Palo Alto)

    private static func detectGlobalProtect() -> [DetectedVPN] {
        let home = NSHomeDirectory()
        let plistPaths = [
            "/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist",
            "\(home)/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist",
            "\(home)/Library/Preferences/com.paloaltonetworks.GlobalProtect.pansetup.plist",
            "\(home)/Library/Preferences/com.paloaltonetworks.GlobalProtect.client.plist",
        ]

        var servers: [String] = []
        for path in plistPaths {
            guard let data = FileManager.default.contents(atPath: path),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) else {
                continue
            }
            collectPortalValues(in: plist, into: &servers)
        }

        return servers.compactMap { server in
            normalizedServer(server).map {
                DetectedVPN(label: "GlobalProtect portal", server: $0, vpnProtocol: "gp")
            }
        }
    }

    /// Recursively collects string values under keys that look portal-related
    /// ("Portal", "LastUrl", "Server"), which covers the layouts PanGPS uses.
    private static func collectPortalValues(in object: Any, into servers: inout [String]) {
        if let dictionary = object as? [String: Any] {
            for (key, value) in dictionary {
                let lowered = key.lowercased()
                if let text = value as? String,
                   lowered.contains("portal") || lowered.contains("lasturl") || lowered == "server" {
                    servers.append(text)
                } else {
                    collectPortalValues(in: value, into: &servers)
                }
            }
        } else if let array = object as? [Any] {
            for element in array {
                collectPortalValues(in: element, into: &servers)
            }
        }
    }

    // MARK: - Cisco AnyConnect / Secure Client

    private static func detectAnyConnect() -> [DetectedVPN] {
        var results: [DetectedVPN] = []

        let profileDirectories = [
            "/opt/cisco/secureclient/vpn/profile",
            "/opt/cisco/anyconnect/profile",
        ]
        for directory in profileDirectories {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directory) else {
                continue
            }
            for entry in entries where entry.lowercased().hasSuffix(".xml") {
                guard let contents = try? String(contentsOfFile: "\(directory)/\(entry)", encoding: .utf8) else {
                    continue
                }
                for hostEntry in matches(of: "<HostEntry>(.*?)</HostEntry>", in: contents) {
                    let name = firstMatch(of: "<HostName>(.*?)</HostName>", in: hostEntry)
                    guard let address = firstMatch(of: "<HostAddress>(.*?)</HostAddress>", in: hostEntry) ?? name,
                          let server = normalizedServer(address) else {
                        continue
                    }
                    let label = name.map { "AnyConnect: \($0)" } ?? "AnyConnect profile"
                    results.append(DetectedVPN(label: label, server: server, vpnProtocol: "anyconnect"))
                }
            }
        }

        // The client's "recent server" preference.
        let preferences = "\(NSHomeDirectory())/.anyconnect"
        if let contents = try? String(contentsOfFile: preferences, encoding: .utf8),
           let recent = firstMatch(of: "<DefaultHostName>(.*?)</DefaultHostName>", in: contents),
           let server = normalizedServer(recent) {
            results.append(DetectedVPN(label: "AnyConnect: recent server", server: server, vpnProtocol: "anyconnect"))
        }

        return results
    }

    // MARK: - Helpers

    private static func normalizedServer(_ raw: String) -> String? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        for prefix in ["https://", "http://"] where text.lowercased().hasPrefix(prefix) {
            text = String(text.dropFirst(prefix.count))
        }
        if let slashIndex = text.firstIndex(of: "/") {
            text = String(text[..<slashIndex])
        }
        guard !text.isEmpty, text.contains("."), !text.contains(" ") else {
            return nil
        }
        return text
    }

    private static func matches(of pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
            return []
        }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            Range(match.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    private static func firstMatch(of pattern: String, in text: String) -> String? {
        matches(of: pattern, in: text).first?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
