import Foundation
import PortKeeperCore

/// Persistent tunnel lifecycle log: supervisor launches/finishes, reload and
/// reclaim events, ssh output and exits. The in-app popover keeps only ~20
/// lines in memory, which loses intermittent lifecycle failures; this file is
/// the durable record.
///
/// `BoundedLogFile` supplies the two guards that keep a retry loop from
/// turning it into trash: repeats collapse to one annotated line per 5-minute
/// window per distinct message (digits ignored, so changing pids and backoff
/// delays still count as repeats), and rotation caps the total on disk at
/// ~1 MB no matter what the deduplication misses.
enum TunnelLog {
    static var logURL: URL {
        BoundedLogFile.logsDirectory().appendingPathComponent("tunnel.log", isDirectory: false)
    }

    private static let file = BoundedLogFile(url: logURL, label: "burrow.tunnel-log")

    static func append(tunnel: String, _ message: String) {
        file.append(source: tunnel, message)
    }
}
