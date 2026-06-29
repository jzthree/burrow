import AppKit

/// Template menu-bar icons (auto black/white per menu bar appearance):
/// the website's "burrow / tunnel mouth" mark — two concentric arches over a
/// base node. The node fills in while any tunnel is running.
@MainActor
enum MenuBarIcon {
    static let idle = make(active: false)
    static let active = make(active: true)

    private static func make(active: Bool) -> NSImage {
        // Sized to fill a menu-bar slot with little dead space (a semicircle is
        // ~2:1, so a short, wide canvas keeps the glyph large).
        let image = NSImage(size: NSSize(width: 20, height: 13), flipped: false) { _ in
            NSColor.black.set()

            let centerX: CGFloat = 10
            let baseY: CGFloat = 2.6

            // Outer tunnel arch (upper semicircle), nearly the full width.
            let outer = NSBezierPath()
            outer.appendArc(withCenter: NSPoint(x: centerX, y: baseY), radius: 9, startAngle: 0, endAngle: 180)
            outer.lineWidth = 1.8
            outer.lineCapStyle = .round
            outer.stroke()

            // Inner concentric arch.
            let inner = NSBezierPath()
            inner.appendArc(withCenter: NSPoint(x: centerX, y: baseY), radius: 4.7, startAngle: 0, endAngle: 180)
            inner.lineWidth = 1.5
            inner.lineCapStyle = .round
            inner.stroke()

            // Base node — filled when a tunnel is up, a thin ring when idle.
            let radius: CGFloat = 1.8
            let node = NSBezierPath(ovalIn: NSRect(
                x: centerX - radius, y: baseY - radius,
                width: radius * 2, height: radius * 2
            ))
            if active {
                node.fill()
            } else {
                node.lineWidth = 1.3
                node.stroke()
            }
            return true
        }
        image.isTemplate = true
        return image
    }
}
