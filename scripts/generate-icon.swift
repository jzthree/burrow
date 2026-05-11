#!/usr/bin/env swift

import AppKit
import Foundation

let rootURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let outputURL = rootURL.appendingPathComponent("XcodeSupport/Burrow.icns")
let iconsetURL = rootURL.appendingPathComponent(".build/Burrow.iconset", isDirectory: true)

try? FileManager.default.removeItem(at: iconsetURL)
try FileManager.default.createDirectory(at: iconsetURL, withIntermediateDirectories: true)
try FileManager.default.createDirectory(at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)

struct IconImage {
    let filename: String
    let pixels: Int
}

let images = [
    IconImage(filename: "icon_16x16.png", pixels: 16),
    IconImage(filename: "icon_16x16@2x.png", pixels: 32),
    IconImage(filename: "icon_32x32.png", pixels: 32),
    IconImage(filename: "icon_32x32@2x.png", pixels: 64),
    IconImage(filename: "icon_128x128.png", pixels: 128),
    IconImage(filename: "icon_128x128@2x.png", pixels: 256),
    IconImage(filename: "icon_256x256.png", pixels: 256),
    IconImage(filename: "icon_256x256@2x.png", pixels: 512),
    IconImage(filename: "icon_512x512.png", pixels: 512),
    IconImage(filename: "icon_512x512@2x.png", pixels: 1024),
]

for image in images {
    let png = try renderIcon(pixels: image.pixels)
    try png.write(to: iconsetURL.appendingPathComponent(image.filename))
}

let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconsetURL.path, "-o", outputURL.path]
try process.run()
process.waitUntilExit()

guard process.terminationStatus == 0 else {
    throw NSError(domain: "BurrowIcon", code: Int(process.terminationStatus), userInfo: [
        NSLocalizedDescriptionKey: "iconutil failed with status \(process.terminationStatus)",
    ])
}

print("Generated \(outputURL.path)")

func renderIcon(pixels: Int) throws -> Data {
    let size = NSSize(width: pixels, height: pixels)
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixels,
        pixelsHigh: pixels,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .calibratedRGB,
        bitmapFormat: [],
        bytesPerRow: 0,
        bitsPerPixel: 0
    ), let graphicsContext = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw NSError(domain: "BurrowIcon", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "No graphics context",
        ])
    }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = graphicsContext
    defer { NSGraphicsContext.restoreGraphicsState() }

    let context = graphicsContext.cgContext
    context.setAllowsAntialiasing(true)
    context.setShouldAntialias(true)

    let scale = CGFloat(pixels) / 1024.0
    func r(_ value: CGFloat) -> CGFloat { value * scale }
    func rect(_ x: CGFloat, _ y: CGFloat, _ width: CGFloat, _ height: CGFloat) -> NSRect {
        NSRect(x: r(x), y: r(y), width: r(width), height: r(height))
    }
    func point(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        NSPoint(x: r(x), y: r(y))
    }

    let bounds = NSRect(origin: .zero, size: size)
    let outer = NSBezierPath(roundedRect: bounds.insetBy(dx: r(42), dy: r(42)), xRadius: r(212), yRadius: r(212))
    outer.addClip()

    NSGradient(
        starting: NSColor(calibratedRed: 0.18, green: 0.62, blue: 0.72, alpha: 1),
        ending: NSColor(calibratedRed: 0.43, green: 0.84, blue: 0.65, alpha: 1)
    )?.draw(in: bounds, angle: 92)

    let horizon = NSBezierPath()
    horizon.move(to: point(0, 318))
    horizon.curve(to: point(1024, 310), controlPoint1: point(250, 410), controlPoint2: point(710, 430))
    horizon.line(to: point(1024, 0))
    horizon.line(to: point(0, 0))
    horizon.close()
    NSColor(calibratedRed: 0.24, green: 0.53, blue: 0.30, alpha: 1).setFill()
    horizon.fill()

    let foreground = NSBezierPath()
    foreground.move(to: point(0, 216))
    foreground.curve(to: point(1024, 210), controlPoint1: point(285, 302), controlPoint2: point(706, 312))
    foreground.line(to: point(1024, 0))
    foreground.line(to: point(0, 0))
    foreground.close()
    NSColor(calibratedRed: 0.19, green: 0.40, blue: 0.25, alpha: 1).setFill()
    foreground.fill()

    let tunnelShadow = NSBezierPath(ovalIn: rect(250, 136, 524, 514))
    NSColor.black.withAlphaComponent(0.12).setFill()
    tunnelShadow.fill()

    let tunnel = NSBezierPath()
    tunnel.move(to: point(268, 176))
    tunnel.line(to: point(268, 396))
    tunnel.curve(to: point(512, 646), controlPoint1: point(278, 536), controlPoint2: point(380, 646))
    tunnel.curve(to: point(756, 396), controlPoint1: point(644, 646), controlPoint2: point(746, 536))
    tunnel.line(to: point(756, 176))
    tunnel.close()
    NSColor(calibratedRed: 0.065, green: 0.095, blue: 0.105, alpha: 1).setFill()
    tunnel.fill()

    let glow = NSBezierPath()
    glow.move(to: point(368, 180))
    glow.line(to: point(368, 380))
    glow.curve(to: point(512, 526), controlPoint1: point(374, 464), controlPoint2: point(434, 526))
    glow.curve(to: point(656, 380), controlPoint1: point(590, 526), controlPoint2: point(650, 464))
    glow.line(to: point(656, 180))
    glow.close()
    NSColor(calibratedRed: 0.10, green: 0.16, blue: 0.16, alpha: 1).setFill()
    glow.fill()

    let lip = NSBezierPath()
    lip.move(to: point(244, 198))
    lip.curve(to: point(780, 198), controlPoint1: point(372, 258), controlPoint2: point(652, 258))
    lip.lineWidth = r(34)
    NSColor(calibratedRed: 0.46, green: 0.34, blue: 0.22, alpha: 1).setStroke()
    lip.stroke()

    let path = NSBezierPath()
    path.move(to: point(216, 748))
    path.curve(to: point(430, 734), controlPoint1: point(274, 704), controlPoint2: point(354, 700))
    path.curve(to: point(560, 614), controlPoint1: point(506, 768), controlPoint2: point(574, 704))
    path.lineWidth = r(42)
    path.lineCapStyle = .round
    path.lineJoinStyle = .round
    NSColor.white.withAlphaComponent(0.88).setStroke()
    path.stroke()

    let dotColor = NSColor(calibratedRed: 0.94, green: 0.78, blue: 0.36, alpha: 1)
    for dot in [point(602, 424), point(424, 424)] {
        let eye = NSBezierPath(ovalIn: NSRect(x: dot.x - r(16), y: dot.y - r(16), width: r(32), height: r(32)))
        dotColor.setFill()
        eye.fill()
    }

    let highlight = NSBezierPath(roundedRect: bounds.insetBy(dx: r(78), dy: r(78)), xRadius: r(176), yRadius: r(176))
    NSColor.white.withAlphaComponent(0.12).setStroke()
    highlight.lineWidth = r(18)
    highlight.stroke()

    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "BurrowIcon", code: 2, userInfo: [
            NSLocalizedDescriptionKey: "Failed to encode PNG",
        ])
    }
    return png
}
