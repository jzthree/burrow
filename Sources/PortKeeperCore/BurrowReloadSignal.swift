import Foundation

/// How `burrow reload` asks the running menu-bar app to relaunch a tunnel with
/// the config as it is on disk *now*.
///
/// A supervisor holds the definition it started with, so an edit made while a
/// tunnel is up doesn't reach the live ssh on its own — and restarting the app
/// to apply one would drop every VPN gateway with it. A distributed
/// notification is the smallest thing that crosses the process boundary: no
/// port, no socket, no file to clean up, and harmless when the app isn't
/// running (the CLI falls back to restarting the ssh itself).
public enum BurrowReloadSignal {
    /// Posted with the tunnel name as the notification's object, or `nil` to
    /// mean "every running tunnel".
    public static let name = Notification.Name("com.burrow.reload-tunnel")

    public static func post(tunnel: String?) {
        DistributedNotificationCenter.default().postNotificationName(
            name,
            object: tunnel,
            userInfo: nil,
            deliverImmediately: true
        )
    }
}
