import Foundation

/// Collapses repeating log lines so a supervisor stuck in a retry loop costs
/// one line per suppression window instead of one every few seconds.
///
/// Each message is keyed by its text with digit runs collapsed, per source:
/// "reclaiming stale ssh process 43362" and "... 61102" — or the backoff
/// variants "Reconnecting in 5s" / "Reconnecting in 40s" — count as repeats of
/// one another. Because every distinct message keys independently, a loop that
/// cycles through two alternating errors still collapses (each message has its
/// own window) rather than defeating a naive "same as the previous line" check.
///
/// The first occurrence is emitted immediately, so the log still pinpoints
/// when an incident began. Repeats inside the window are counted silently; the
/// next occurrence after the window closes re-emits the message annotated with
/// the suppressed count and span. If a loop stops mid-window, the trailing
/// partial window's count is never flushed — an accepted loss of at most one
/// window's worth of "it happened again" for a design with no timers.
///
/// Pure state machine — no clock, no IO — so tests drive time explicitly.
public struct LogDeduplicator {
    private struct KeyState {
        var lastEmitted: Date
        var suppressed: Int
    }

    private let window: TimeInterval
    private var states: [String: KeyState] = [:]

    public init(window: TimeInterval = 300) {
        self.window = window
    }

    /// The line to write now, or nil if this occurrence is suppressed.
    public mutating func process(source: String, message: String, at now: Date) -> String? {
        let key = "\(source)|\(Self.collapsingDigitRuns(message))"

        // Bound memory across arbitrarily many distinct messages. Entries
        // still inside a live window are kept so their counts aren't lost.
        if states.count > 512 {
            states = states.filter { now.timeIntervalSince($0.value.lastEmitted) < window }
        }

        guard let state = states[key] else {
            states[key] = KeyState(lastEmitted: now, suppressed: 0)
            return message
        }

        let elapsed = now.timeIntervalSince(state.lastEmitted)
        guard elapsed >= window else {
            states[key] = KeyState(lastEmitted: state.lastEmitted, suppressed: state.suppressed + 1)
            return nil
        }

        states[key] = KeyState(lastEmitted: now, suppressed: 0)
        guard state.suppressed > 0 else {
            return message
        }
        return "\(message) (+\(state.suppressed) similar in the past \(Self.describeDuration(elapsed)))"
    }

    private static func collapsingDigitRuns(_ message: String) -> String {
        var result = ""
        result.reserveCapacity(message.count)
        var previousWasDigit = false
        for character in message {
            if character.isNumber {
                if !previousWasDigit {
                    result.append("#")
                }
                previousWasDigit = true
            } else {
                result.append(character)
                previousWasDigit = false
            }
        }
        return result
    }

    private static func describeDuration(_ seconds: TimeInterval) -> String {
        let total = Int(seconds.rounded())
        if total < 120 {
            return "\(total)s"
        }
        if total < 7200 {
            return "\(total / 60)m"
        }
        return "\(total / 3600)h\((total % 3600) / 60)m"
    }
}
