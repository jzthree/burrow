import AppKit

/// Template menu-bar icons (auto black/white per menu bar appearance):
/// a burrow mound on a ground line. The tunnel opening fills in while
/// any tunnel is running.
@MainActor
enum MenuBarIcon {
    static let idle = make(active: false)
    static let active = make(active: true)

    private static func make(active: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 15), flipped: false) { _ in
            NSColor.black.set()

            let ground = NSBezierPath()
            ground.move(to: NSPoint(x: 1.2, y: 2.4))
            ground.line(to: NSPoint(x: 16.8, y: 2.4))
            ground.lineWidth = 1.5
            ground.lineCapStyle = .round
            ground.stroke()

            let mound = NSBezierPath()
            mound.move(to: NSPoint(x: 3.2, y: 2.4))
            mound.curve(
                to: NSPoint(x: 9, y: 12.2),
                controlPoint1: NSPoint(x: 3.6, y: 10.2),
                controlPoint2: NSPoint(x: 5.6, y: 12.2)
            )
            mound.curve(
                to: NSPoint(x: 14.8, y: 2.4),
                controlPoint1: NSPoint(x: 12.4, y: 12.2),
                controlPoint2: NSPoint(x: 14.4, y: 10.2)
            )
            mound.lineWidth = 1.5
            mound.lineCapStyle = .round
            mound.stroke()

            let opening = NSBezierPath()
            opening.move(to: NSPoint(x: 6.7, y: 2.4))
            opening.curve(
                to: NSPoint(x: 9, y: 7.4),
                controlPoint1: NSPoint(x: 7.0, y: 5.8),
                controlPoint2: NSPoint(x: 7.9, y: 7.4)
            )
            opening.curve(
                to: NSPoint(x: 11.3, y: 2.4),
                controlPoint1: NSPoint(x: 10.1, y: 7.4),
                controlPoint2: NSPoint(x: 11.0, y: 5.8)
            )
            opening.close()
            if active {
                opening.fill()
            } else {
                opening.lineWidth = 1.2
                opening.stroke()
            }
            return true
        }
        image.isTemplate = true
        return image
    }
}
