import AppKit
import PortKeeperCore

struct ChromiumBrowser: Identifiable, Equatable {
    let displayName: String
    let appPath: String

    var id: String { appPath }
}

/// Launches a Chromium-based browser with its traffic (and DNS) routed
/// through a gateway's SOCKS port. Each gateway gets its own browser profile
/// so the proxied instance is a separate process — flags are ignored when
/// reusing a running instance's profile. Safari is absent by design: it only
/// honors the system-wide proxy, which Burrow refuses to touch.
enum ChromiumBrowserLauncher {
    private static let candidates: [(name: String, path: String)] = [
        ("Google Chrome", "/Applications/Google Chrome.app"),
        ("Brave", "/Applications/Brave Browser.app"),
        ("Microsoft Edge", "/Applications/Microsoft Edge.app"),
        ("Vivaldi", "/Applications/Vivaldi.app"),
        ("Chromium", "/Applications/Chromium.app"),
    ]

    static func installed() -> [ChromiumBrowser] {
        var results: [ChromiumBrowser] = []
        let home = NSHomeDirectory()
        for candidate in candidates {
            for path in [candidate.path, home + candidate.path] where FileManager.default.fileExists(atPath: path) {
                results.append(ChromiumBrowser(displayName: candidate.name, appPath: path))
                break
            }
        }
        return results
    }

    static func launch(_ browser: ChromiumBrowser, through gateway: GatewayConfig) throws {
        let profileDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("browser-profiles", isDirectory: true)
            .appendingPathComponent("\(gateway.name)-\(browser.displayName.replacingOccurrences(of: " ", with: "-"))", isDirectory: true)
        try FileManager.default.createDirectory(at: profileDirectory, withIntermediateDirectories: true)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [
            "-na", browser.appPath,
            "--args",
            "--user-data-dir=\(profileDirectory.path)",
            "--proxy-server=socks5://127.0.0.1:\(gateway.socksPort)",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        try process.run()
    }
}
