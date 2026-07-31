import Foundation
import Testing
@testable import PortKeeperCore

@Suite struct LogDeduplicatorTests {
    private let epoch = Date(timeIntervalSinceReferenceDate: 0)

    @Test func firstOccurrenceEmitsVerbatim() {
        var dedup = LogDeduplicator(window: 300)
        #expect(dedup.process(source: "t", message: "ssh exited with code 0.", at: epoch) == "ssh exited with code 0.")
    }

    @Test func repeatsSuppressUntilWindowThenAnnotateWithCount() {
        var dedup = LogDeduplicator(window: 300)
        _ = dedup.process(source: "t", message: "ssh exited with code 15. Reconnecting in 5s.", at: epoch)
        // A 5-second retry loop: 59 repeats inside the window, all silent.
        for second in stride(from: 5, to: 300, by: 5) {
            let line = dedup.process(
                source: "t",
                message: "ssh exited with code 15. Reconnecting in 5s.",
                at: epoch.addingTimeInterval(TimeInterval(second))
            )
            #expect(line == nil)
        }
        let summary = dedup.process(
            source: "t",
            message: "ssh exited with code 15. Reconnecting in 5s.",
            at: epoch.addingTimeInterval(300)
        )
        #expect(summary == "ssh exited with code 15. Reconnecting in 5s. (+59 similar in the past 5m)")
    }

    /// The naive "same as the previous line" check fails when a loop cycles
    /// through two alternating errors. Each message keys independently here,
    /// so an hour-long two-message flicker costs a bounded handful of lines.
    @Test func alternatingMessagesStillCollapse() {
        var dedup = LogDeduplicator(window: 300)
        var emitted = 0
        for second in stride(from: 0, to: 3600, by: 5) {
            let message = (second / 5) % 2 == 0
                ? "reclaiming stale ssh process 43362."
                : "ssh exited with code 15. Reconnecting in 5s."
            if dedup.process(source: "t", message: message, at: epoch.addingTimeInterval(TimeInterval(second))) != nil {
                emitted += 1
            }
        }
        // Two first-occurrence lines plus at most one summary per message per
        // 5-minute window: 2 + 2 * (3600 / 300) = 26.
        #expect(emitted <= 26)
        #expect(emitted >= 4)
    }

    @Test func digitChangesCountAsRepeats() {
        var dedup = LogDeduplicator(window: 300)
        _ = dedup.process(source: "t", message: "reclaiming stale ssh process 43362.", at: epoch)
        #expect(dedup.process(source: "t", message: "reclaiming stale ssh process 61102.", at: epoch.addingTimeInterval(5)) == nil)
        // Backoff growth widens the digit run ("5s" → "40s") — still a repeat.
        _ = dedup.process(source: "t", message: "Reconnecting in 5s.", at: epoch)
        #expect(dedup.process(source: "t", message: "Reconnecting in 40s.", at: epoch.addingTimeInterval(5)) == nil)
    }

    @Test func distinctMessagesAndSourcesDoNotCrossSuppress() {
        var dedup = LogDeduplicator(window: 300)
        _ = dedup.process(source: "alpha", message: "ssh exited with code 15.", at: epoch)
        #expect(dedup.process(source: "alpha", message: "remote port forwarding failed", at: epoch.addingTimeInterval(1)) != nil)
        #expect(dedup.process(source: "beta", message: "ssh exited with code 15.", at: epoch.addingTimeInterval(2)) != nil)
    }

    @Test func quietPeriodResetsWithoutStaleAnnotation() {
        var dedup = LogDeduplicator(window: 300)
        _ = dedup.process(source: "t", message: "Connected", at: epoch)
        // One lone occurrence much later: no suppressed repeats to report.
        #expect(dedup.process(source: "t", message: "Connected", at: epoch.addingTimeInterval(4000)) == "Connected")
    }
}
