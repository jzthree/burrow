import AppKit
import PortKeeperCore
import SwiftUI

/// Hosts the Authenticator in its own window so revealing a code (which needs a
/// Touch ID sheet) isn't interrupted by the menu-bar popover dismissing.
@MainActor
final class AuthenticatorWindowController: NSObject, NSWindowDelegate {
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
        window?.title = "Authenticator"
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
        viewModel?.showingAuthenticator = false
        isSyncing = false
    }

    private func makeWindow() -> NSWindow? {
        guard let viewModel else { return nil }
        let hosting = NSHostingController(rootView: AuthenticatorSheet(viewModel: viewModel))
        let window = NSWindow(contentViewController: hosting)
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.setContentSize(NSSize(width: 440, height: 560))
        window.center()
        return window
    }
}

struct AuthenticatorSheet: View {
    @ObservedObject var viewModel: MenuBarViewModel
    @State private var isAdding = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if isAdding {
                        AddCodeCard(
                            existingNames: viewModel.twoFactorAccounts.map(\.name),
                            onCancel: { withAnimation { isAdding = false } },
                            onAdd: { name, secret in
                                if viewModel.enrollTwoFactor(name: name, secret: secret) {
                                    withAnimation { isAdding = false }
                                    return true
                                }
                                return false
                            }
                        )
                        .transition(.opacity.combined(with: .move(edge: .top)))
                    }

                    if viewModel.twoFactorAccounts.isEmpty && !isAdding {
                        emptyState
                    } else {
                        ForEach(viewModel.twoFactorAccounts) { account in
                            AuthenticatorRow(
                                account: account,
                                revealed: viewModel.revealedCodes[account.id],
                                onReveal: { viewModel.revealTwoFactorCode(named: account.id) },
                                onHide: { viewModel.hideTwoFactorCode(named: account.id) },
                                onDelete: { viewModel.deleteTwoFactorAccount(named: account.id) }
                            )
                        }
                    }
                }
                .padding(14)
            }

            Divider()
            footer
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .frame(width: 440, height: 560)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 18))
                .foregroundStyle(Color.burrowAccent)
            VStack(alignment: .leading, spacing: 1) {
                Text("Authenticator")
                    .font(.system(size: 16, weight: .bold))
                Text("Verification codes, unlocked with Touch ID.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !isAdding {
                Button {
                    withAnimation { isAdding = true }
                } label: {
                    Label("Add", systemImage: "plus")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                .buttonStyle(.borderless)
                .help("Add a verification code")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var footer: some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.fill")
                .font(.system(size: 9))
            Text("Secrets stay in your Keychain — never synced, never leave this Mac.")
                .font(.system(size: 10))
            Spacer()
            Button("Done") { viewModel.closeAuthenticator() }
                .keyboardShortcut(.defaultAction)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "key.radiowaves.forward")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(.secondary.opacity(0.5))
            Text("No codes yet")
                .font(.system(size: 13, weight: .semibold))
            Text("Add a code from any site's authenticator setup — paste its otpauth:// link or the “can't scan” secret key.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
            Button {
                withAnimation { isAdding = true }
            } label: {
                Label("Add a code", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 2)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }
}

private struct AuthenticatorRow: View {
    let account: TwoFactorAccount
    let revealed: MenuBarViewModel.RevealedCode?
    let onReveal: () -> Void
    let onHide: () -> Void
    let onDelete: () -> Void

    @State private var hovering = false
    @State private var justCopied = false

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.burrowAccent.opacity(0.14))
                Text(initial)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(Color.burrowAccent)
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 1) {
                Text(account.name)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)
                Text("\(account.digits) digits · every \(account.period)s")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            if let revealed, revealed.periodEnd > Date() {
                revealedView(revealed)
            } else {
                Button(action: onReveal) {
                    HStack(spacing: 5) {
                        Image(systemName: "touchid")
                            .font(.system(size: 13, weight: .semibold))
                        Text("Reveal")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(Color.burrowAccent)
                    .padding(.horizontal, 12)
                    .frame(height: 30)
                    .background(
                        Capsule(style: .continuous).fill(Color.burrowAccent.opacity(0.12))
                    )
                }
                .buttonStyle(.plain)
                .help("Reveal the current code with Touch ID")
            }

            Button(action: onDelete) {
                Image(systemName: "trash")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .opacity(hovering ? 1 : 0)
            .help("Remove \(account.name)")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.55))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
        .onHover { hovering = $0 }
    }

    private func revealedView(_ revealed: MenuBarViewModel.RevealedCode) -> some View {
        TimelineView(.periodic(from: Date(), by: 0.2)) { context in
            let total = Double(account.period)
            let remaining = max(0, revealed.periodEnd.timeIntervalSince(context.date))
            let fraction = min(1, max(0, remaining / total))
            let seconds = Int(remaining.rounded(.up))

            HStack(spacing: 10) {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(revealed.code, forType: .string)
                    justCopied = true
                } label: {
                    HStack(spacing: 6) {
                        Text(spacedCode(revealed.code))
                            .font(.system(size: 18, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.primary)
                        Image(systemName: justCopied ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 10))
                            .foregroundStyle(justCopied ? Color.green : .secondary)
                    }
                }
                .buttonStyle(.plain)
                .help(justCopied ? "Copied" : "Copy code")

                ZStack {
                    Circle()
                        .stroke(Color.secondary.opacity(0.2), lineWidth: 2.5)
                    Circle()
                        .trim(from: 0, to: fraction)
                        .stroke(seconds <= 5 ? Color.orange : Color.burrowAccent,
                                style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    Text("\(seconds)")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(seconds <= 5 ? Color.orange : .secondary)
                }
                .frame(width: 24, height: 24)

                Button(action: onHide) {
                    Image(systemName: "eye.slash")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Hide")
            }
        }
    }

    private var initial: String {
        account.name.first.map { String($0).uppercased() } ?? "?"
    }

    private func spacedCode(_ code: String) -> String {
        guard code.count == 6 || code.count == 8 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[code.startIndex..<mid]) \(code[mid...])"
    }
}

/// Inline add form with live parsing of the pasted secret.
private struct AddCodeCard: View {
    let existingNames: [String]
    let onCancel: () -> Void
    /// Returns true if the enrollment succeeded (so the card can close).
    let onAdd: (_ name: String, _ secret: String) -> Bool

    @State private var secretText = ""
    @State private var nameText = ""
    @State private var nameEditedByUser = false

    private var parsed: TOTPSecret? {
        let trimmed = secretText.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : TOTPSecret.parse(trimmed)
    }

    private var suggestedName: String {
        guard let parsed else { return "" }
        if let issuer = parsed.issuer, !issuer.isEmpty { return issuer }
        if let label = parsed.label, !label.isEmpty {
            return label.split(separator: ":").last.map(String.init) ?? label
        }
        return ""
    }

    private var trimmedName: String {
        nameText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var nameTaken: Bool {
        existingNames.contains { $0.caseInsensitiveCompare(trimmedName) == .orderedSame }
    }

    private var canAdd: Bool {
        parsed != nil && !trimmedName.isEmpty && !nameTaken
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Add a code")
                .font(.system(size: 12.5, weight: .bold))

            VStack(alignment: .leading, spacing: 4) {
                Text("AUTHENTICATOR SECRET")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    TextField("otpauth://… or base32 key", text: $secretText)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                    Button {
                        if let clip = NSPasteboard.general.string(forType: .string) {
                            secretText = clip
                        }
                    } label: {
                        Image(systemName: "doc.on.clipboard")
                    }
                    .buttonStyle(.bordered)
                    .help("Paste")
                }
                statusLine
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("NAME")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.secondary)
                TextField("e.g. vista", text: $nameText)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12))
                if nameTaken {
                    Text("A code named “\(trimmedName)” already exists — adding will replace it.")
                        .font(.system(size: 10))
                        .foregroundStyle(.orange)
                }
            }

            HStack {
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Add") {
                    if onAdd(trimmedName, secretText) {
                        secretText = ""; nameText = ""; nameEditedByUser = false
                    }
                }
                .keyboardShortcut(.return)
                .disabled(!canAdd)
            }
            .buttonStyle(.bordered)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.burrowAccent.opacity(0.06))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.burrowAccent.opacity(0.25), lineWidth: 1)
        )
        .onChange(of: secretText) { _ in
            // Auto-fill the name from the secret until the user types their own.
            if !nameEditedByUser {
                nameText = suggestedName
            }
        }
        .onChange(of: nameText) { newValue in
            if newValue != suggestedName { nameEditedByUser = !newValue.isEmpty }
        }
    }

    @ViewBuilder
    private var statusLine: some View {
        if let parsed {
            Label("Valid code · \(parsed.digits) digits · every \(parsed.period)s · \(parsed.algorithm.rawValue.uppercased())",
                  systemImage: "checkmark.seal.fill")
                .font(.system(size: 10))
                .foregroundStyle(.green)
        } else if !secretText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Label("Not a recognizable authenticator secret yet", systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 10))
                .foregroundStyle(.orange)
        } else {
            Text("Paste the otpauth:// link, or the “can't scan the QR?” key.")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
    }
}
