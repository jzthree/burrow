import AppKit
import CoreImage

/// Grabs a QR code straight off the screen: the native interactive region
/// screenshot (drag to select), then a QR decode of that selection. Lets a user
/// enroll a 2FA secret from a QR shown in a browser without pasting anything.
enum ScreenQRScanner {
    enum ScanError: Error, LocalizedError {
        case cancelled
        case noQRFound
        case captureUnavailable

        var errorDescription: String? {
            switch self {
            case .cancelled:
                return "Screenshot cancelled."
            case .noQRFound:
                return "No QR code found in that selection — drag a box around the whole code."
            case .captureUnavailable:
                return "Couldn’t start a screenshot. Grant Burrow Screen Recording access in System Settings ▸ Privacy & Security."
            }
        }
    }

    /// Runs `screencapture -i` and decodes any QR in the captured region.
    /// Blocking — it waits for the drag-select — so call it off the main actor.
    static func scanRegion() throws -> String {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-qr-\(UUID().uuidString).png")
        defer { try? FileManager.default.removeItem(at: tmp) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        // -i interactive region select, -x no shutter sound.
        process.arguments = ["-i", "-x", tmp.path]
        do {
            try process.run()
        } catch {
            throw ScanError.captureUnavailable
        }
        process.waitUntilExit()

        // Escape (or an empty selection) writes no file.
        guard FileManager.default.fileExists(atPath: tmp.path),
              let image = CIImage(contentsOf: tmp) else {
            throw ScanError.cancelled
        }

        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode,
            context: CIContext(),
            options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )
        for case let qr as CIQRCodeFeature in detector?.features(in: image) ?? [] {
            if let message = qr.messageString, !message.isEmpty {
                return message
            }
        }
        throw ScanError.noQRFound
    }
}
