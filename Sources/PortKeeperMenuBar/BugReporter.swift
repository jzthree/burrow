import AppKit
import PortKeeperCore
import SwiftUI

/// Files GitHub issues for Burrow. Prefers the authenticated `gh` CLI — that
/// creates the issue outright and hands back its URL — and falls back to a
/// prefilled new-issue page in the browser when gh isn't installed or signed in.
enum BugReporter {
    static let repoSlug = "jzthree/burrow"

    struct SubmitError: Error, LocalizedError, Sendable {
        let message: String
        /// A browser URL the caller can offer so the report isn't lost.
        let fallbackURL: URL?
        var errorDescription: String? { message }
    }

    /// The environment block appended to every report — the first thing anyone
    /// triaging a bug asks for.
    static func environmentFooter() -> String {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osString = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "x86_64"
        #endif
        return """
        ---
        Filed from Burrow \(BurrowVersion.display()) · macOS \(osString) (\(arch))
        """
    }

    /// Locates a usable `gh`. GUI apps launched from Finder get a minimal PATH,
    /// so the common install sites are checked explicitly rather than via `which`.
    private static func ghExecutable() -> String? {
        ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// True when a report can be filed without bouncing through the browser.
    static var canFileDirectly: Bool { ghExecutable() != nil }

    /// Creates the issue via gh and returns its URL. Blocking (it spawns gh), so
    /// call off the main actor. Throws `SubmitError` — carrying a browser
    /// fallback — on any failure.
    static func fileIssue(title: String, body: String) throws -> URL {
        let fullBody = body + "\n\n" + environmentFooter()
        guard let gh = ghExecutable() else {
            throw SubmitError(
                message: "GitHub CLI (gh) isn't installed — opening the browser instead.",
                fallbackURL: browserURL(title: title, body: fullBody)
            )
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: gh)
        process.arguments = ["issue", "create", "--repo", repoSlug, "--title", title, "--body", fullBody]
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        do {
            try process.run()
        } catch {
            throw SubmitError(
                message: "Couldn't launch gh: \(error.localizedDescription)",
                fallbackURL: browserURL(title: title, body: fullBody)
            )
        }
        // gh's output is a single URL line — small enough to read before waiting.
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let stdout = String(data: outData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if process.terminationStatus == 0,
           let line = stdout.split(whereSeparator: \.isNewline).last.map(String.init),
           let url = URL(string: line) {
            return url
        }

        // Not authenticated, offline, repo moved… fall back to the browser with
        // everything the user typed still prefilled.
        let errText = String(data: errData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        throw SubmitError(
            message: errText.isEmpty ? "gh couldn't create the issue." : errText,
            fallbackURL: browserURL(title: title, body: fullBody)
        )
    }

    /// A github.com "new issue" URL with the title & body prefilled.
    static func browserURL(title: String, body: String) -> URL {
        var components = URLComponents(string: "https://github.com/\(repoSlug)/issues/new")!
        components.queryItems = [
            URLQueryItem(name: "title", value: title),
            URLQueryItem(name: "body", value: body),
        ]
        return components.url!
    }
}

/// Hosts the bug-report composer in its own window, so it survives the menu-bar
/// popover dismissing while the user is typing.
@MainActor
final class BugReportWindowController: NSObject, NSWindowDelegate {
    private weak var viewModel: MenuBarViewModel?
    private var window: NSWindow?
    private var isSyncing = false

    init(viewModel: MenuBarViewModel) {
        self.viewModel = viewModel
    }

    func present() {
        if window == nil {
            window = makeWindow()
        }
        window?.title = "Report a Bug"
        MenuBarPopover.dismiss()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func dismiss() {
        guard !isSyncing, let window, window.isVisible else { return }
        isSyncing = true
        window.close()
        isSyncing = false
    }

    func windowWillClose(_ notification: Notification) {
        guard !isSyncing else { return }
        isSyncing = true
        viewModel?.showingBugReport = false
        isSyncing = false
    }

    private func makeWindow() -> NSWindow? {
        guard let viewModel else { return nil }
        let hosting = NSHostingController(rootView: BugReportSheet(viewModel: viewModel))
        let window = NSWindow(contentViewController: hosting)
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.setContentSize(NSSize(width: 460, height: 470))
        window.center()
        return window
    }
}

struct BugReportSheet: View {
    @ObservedObject var viewModel: MenuBarViewModel

    @State private var title = ""
    @State private var details = ""
    @State private var submitting = false
    @State private var errorMessage: String?
    @State private var fallbackURL: URL?
    @State private var createdURL: URL?

    private var canSubmit: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !submitting
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                Image(systemName: "ladybug.fill")
                    .font(.system(size: 20))
                    .foregroundStyle(Color.burrowAccent)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Report a Bug")
                        .font(.system(size: 15, weight: .bold))
                    Text("Files a GitHub issue on jzthree/burrow.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }

            if let createdURL {
                successView(createdURL)
            } else {
                composer
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder private var composer: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("TITLE")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
            TextField("A short summary — e.g. “Keep-warm keeps prompting after 2FA change”", text: $title)
                .textFieldStyle(.roundedBorder)
        }

        VStack(alignment: .leading, spacing: 4) {
            Text("WHAT HAPPENED")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
            TextEditor(text: $details)
                .font(.system(size: 12))
                .frame(minHeight: 150)
                .overlay(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                )
                .overlay(alignment: .topLeading) {
                    if details.isEmpty {
                        Text("Steps to reproduce, what you expected, what you saw.")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary.opacity(0.6))
                            .padding(.top, 8)
                            .padding(.leading, 5)
                            .allowsHitTesting(false)
                    }
                }
        }

        Label("Your Burrow version and macOS version are added automatically.",
              systemImage: "info.circle")
            .font(.system(size: 10))
            .foregroundStyle(.secondary)

        if let errorMessage {
            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 10.5))
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }

        Spacer(minLength: 0)
        Divider()
        HStack(spacing: 10) {
            if fallbackURL != nil {
                Button("Open in Browser") { openFallback() }
            }
            Spacer()
            Button("Cancel") { viewModel.showingBugReport = false }
            Button(submitting ? "Submitting…" : "Submit") { submit() }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSubmit)
        }
        .buttonStyle(.bordered)
    }

    @ViewBuilder private func successView(_ url: URL) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Issue created", systemImage: "checkmark.seal.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.green)
            Text("Thanks — your report is filed. Track it on GitHub:")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Link(url.absoluteString, destination: url)
                .font(.system(size: 12, design: .monospaced))
            Spacer(minLength: 0)
            Divider()
            HStack {
                Spacer()
                Button("Done") { viewModel.showingBugReport = false }
                    .keyboardShortcut(.defaultAction)
            }
            .buttonStyle(.bordered)
        }
    }

    private func submit() {
        errorMessage = nil
        fallbackURL = nil
        submitting = true
        Task {
            defer { submitting = false }
            let result = await viewModel.submitBugReport(title: title, details: details)
            switch result {
            case .success(let url):
                createdURL = url
            case .failure(let error):
                errorMessage = error.message
                fallbackURL = error.fallbackURL
            }
        }
    }

    private func openFallback() {
        guard let fallbackURL else { return }
        NSWorkspace.shared.open(fallbackURL)
        viewModel.showingBugReport = false
    }
}
