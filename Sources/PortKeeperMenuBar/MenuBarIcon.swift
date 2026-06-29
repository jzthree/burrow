import AppKit

/// Template menu-bar icons (auto black/white per menu bar appearance):
/// the website's "burrow / tunnel mouth" mark — two concentric arches over a
/// base node. The node fills in while any tunnel is running.
@MainActor
enum MenuBarIcon {
    static let idle = make(active: false)
    static let active = make(active: true)

    private static func make(active: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 15), flipped: false) { _ in
            NSColor.black.set()

            let centerX: CGFloat = 9
            let baseY: CGFloat = 2.9

            // Outer tunnel arch (upper semicircle).
            let outer = NSBezierPath()
            outer.appendArc(withCenter: NSPoint(x: centerX, y: baseY), radius: 6.6, startAngle: 0, endAngle: 180)
            outer.lineWidth = 1.5
            outer.lineCapStyle = .round
            outer.stroke()

            // Inner concentric arch.
            let inner = NSBezierPath()
            inner.appendArc(withCenter: NSPoint(x: centerX, y: baseY), radius: 3.4, startAngle: 0, endAngle: 180)
            inner.lineWidth = 1.3
            inner.lineCapStyle = .round
            inner.stroke()

            // Base node — filled when a tunnel is up, a thin ring when idle.
            let radius: CGFloat = 1.5
            let node = NSBezierPath(ovalIn: NSRect(
                x: centerX - radius, y: baseY - radius,
                width: radius * 2, height: radius * 2
            ))
            if active {
                node.fill()
            } else {
                node.lineWidth = 1.1
                node.stroke()
            }
            return true
        }
        image.isTemplate = true
        return image
    }
}
