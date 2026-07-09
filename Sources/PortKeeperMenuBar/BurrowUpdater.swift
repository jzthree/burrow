import AppKit
import Sparkle

/// Sparkle-backed self-updater: signed appcast, download, EdDSA verification,
/// and swap-and-relaunch, all handled by the framework.
///
/// Active only when running from a real .app bundle whose Info.plist carries
/// the Sparkle keys (SUFeedURL/SUPublicEDKey) — install-app.sh and make-dmg.sh
/// stamp them. `swift run` and bare dev binaries have no bundle for Sparkle to
/// replace, so they stay on the lightweight release-page check instead.
@MainActor
final class BurrowUpdater {
    private var controller: SPUStandardUpdaterController?

    var isActive: Bool { controller != nil }

    init() {
        guard Bundle.main.bundleIdentifier != nil,
              Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil else {
            return
        }
        controller = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
    }

    /// User-initiated check with Sparkle's standard UI.
    func checkForUpdates() {
        // A menu-bar (LSUIElement) app has no Dock presence; activate so the
        // update window comes to the front instead of appearing behind others.
        NSApp.activate(ignoringOtherApps: true)
        controller?.checkForUpdates(nil)
    }

    /// Mirrors Burrow's "Check Daily for Updates" toggle onto Sparkle's
    /// scheduled background checks.
    func setAutomaticChecks(_ enabled: Bool) {
        controller?.updater.automaticallyChecksForUpdates = enabled
    }
}
