import Foundation
import UserNotifications

/// Coalesced, de-duplicated user notifications. The goal is to never spam: a
/// Wi-Fi drop that knocks out ten tunnels produces ONE "10 tunnels
/// disconnected" notification, not ten — and the per-tunnel retry loop (which
/// keeps emitting failure events) never re-notifies for a problem already
/// announced. Brief blips that recover within the debounce window are silent.
@MainActor
final class BurrowNotifier {
    private var authorized = false
    private var available = false

    private var pendingProblems: [String: String] = [:]   // name -> reason
    private var pendingRecoveries: Set<String> = []
    private var announcedProblems: Set<String> = []        // currently-notified
    private var flushTask: Task<Void, Never>?

    /// Debounce window: collect simultaneous failures (and same-window
    /// recoveries) before emitting, so a network blip coalesces into one note.
    private let debounce: Duration = .seconds(6)

    init() {
        // UNUserNotificationCenter requires a bundled app; skip when running the
        // bare binary (e.g. from .build) to avoid a crash.
        guard Bundle.main.bundleIdentifier != nil else {
            return
        }
        available = true
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { [weak self] granted, _ in
            Task { @MainActor in self?.authorized = granted }
        }
    }

    /// A tunnel/gateway entered a problem state that warrants attention.
    func reportProblem(name: String, reason: String) {
        guard available, !announcedProblems.contains(name) else {
            return
        }
        pendingProblems[name] = reason
        pendingRecoveries.remove(name)
        scheduleFlush()
    }

    /// A tunnel/gateway recovered. Only notifies if its problem was announced.
    func reportRecovery(name: String) {
        guard available else { return }
        pendingProblems[name] = nil
        if announcedProblems.contains(name) {
            pendingRecoveries.insert(name)
            scheduleFlush()
        }
    }

    /// Clear tracking for a tunnel the user deliberately stopped/removed, so its
    /// later teardown doesn't read as a problem or a recovery.
    func forget(name: String) {
        pendingProblems[name] = nil
        pendingRecoveries.remove(name)
        announcedProblems.remove(name)
    }

    private func scheduleFlush() {
        flushTask?.cancel()
        flushTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: self?.debounce ?? .seconds(6))
            guard let self, !Task.isCancelled else { return }
            self.flush()
        }
    }

    private func flush() {
        let problems = pendingProblems
        pendingProblems = [:]
        let recoveries = pendingRecoveries
        pendingRecoveries = []

        if !problems.isEmpty {
            for name in problems.keys {
                announcedProblems.insert(name)
            }
            if problems.count == 1, let (name, reason) = problems.first {
                send(title: "\(name) disconnected", body: reason)
            } else {
                let names = problems.keys.sorted().joined(separator: ", ")
                send(title: "\(problems.count) tunnels disconnected", body: names)
            }
        }

        if !recoveries.isEmpty {
            for name in recoveries {
                announcedProblems.remove(name)
            }
            if announcedProblems.isEmpty && recoveries.count > 1 {
                send(title: "Tunnels reconnected", body: "\(recoveries.count) back up.")
            } else if recoveries.count == 1, let name = recoveries.first {
                send(title: "\(name) reconnected", body: "Back up.")
            } else {
                send(title: "\(recoveries.count) tunnels reconnected", body: recoveries.sorted().joined(separator: ", "))
            }
        }
    }

    /// One notification per newly-seen release version.
    func announceUpdate(version: String, current: String) {
        send(title: "Burrow \(version) is available", body: "You have \(current). Open the menu to update.")
    }

    private func send(title: String, body: String) {
        guard authorized else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
