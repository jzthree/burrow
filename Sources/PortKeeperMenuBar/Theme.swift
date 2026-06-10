import AppKit
import SwiftUI

/// The MenuBarExtra popover floats above ordinary floating windows, so any
/// dialog we open from it would land *behind* the menu. Dismissing the
/// popover when a window opens keeps ordering sane and matches how system
/// menu items behave.
@MainActor
enum MenuBarPopover {
    static func dismiss() {
        for window in NSApp.windows where String(describing: type(of: window)).contains("MenuBarExtraWindow") {
            window.orderOut(nil)
        }
    }
}

/// Appearance-aware palette so the menu reads correctly in light and dark
/// mode, including over translucent materials.
extension Color {
    private static func dynamic(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
        })
    }

    /// Failure text, diagnosis lines, and destructive hover accents.
    static let burrowFailure = dynamic(
        light: NSColor(srgbRed: 0.72, green: 0.11, blue: 0.09, alpha: 1),
        dark: NSColor(srgbRed: 1.0, green: 0.49, blue: 0.43, alpha: 1)
    )

    /// Accent for the auto-connect bolt.
    static let burrowAccent = dynamic(
        light: NSColor(srgbRed: 0.31, green: 0.31, blue: 0.84, alpha: 1),
        dark: NSColor(srgbRed: 0.66, green: 0.68, blue: 1.0, alpha: 1)
    )

    /// Soft halo behind an enabled bolt.
    static let burrowAccentHalo = dynamic(
        light: NSColor(srgbRed: 0.94, green: 0.95, blue: 1.0, alpha: 1),
        dark: NSColor(srgbRed: 0.44, green: 0.46, blue: 0.96, alpha: 0.30)
    )

    /// Fill for the primary footer action (New Tunnel).
    static let burrowPrimaryButton = dynamic(
        light: NSColor(srgbRed: 0.08, green: 0.08, blue: 0.09, alpha: 1),
        dark: NSColor(srgbRed: 0.32, green: 0.32, blue: 0.36, alpha: 1)
    )
}
