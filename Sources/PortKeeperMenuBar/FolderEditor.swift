import PortKeeperCore
import SwiftUI

struct FolderDraft: Identifiable {
    let id = UUID()
    let originalName: String?
    var name: String
    var host: String
    var user: String
    var remotePath: String
    var localPath: String
    var jumpHost: String
    /// The user typed a name themselves — stop auto-suggesting from host/path.
    var nameEditedByUser: Bool

    init(folder: FolderConfig, originalName: String?) {
        self.originalName = originalName
        self.name = folder.name
        self.host = folder.host
        self.user = folder.user ?? ""
        self.remotePath = folder.remotePath
        self.localPath = folder.localPath
        self.jumpHost = folder.jumpHost ?? ""
        self.nameEditedByUser = originalName != nil
    }

    static func newFolder() -> FolderDraft {
        FolderDraft(folder: FolderConfig(name: "", host: ""), originalName: nil)
    }

    func toFolder() throws -> FolderConfig {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { throw DraftError("A folder name is required.") }
        guard !trimmedHost.isEmpty else { throw DraftError("A host is required.") }
        return FolderConfig(
            name: trimmedName,
            host: trimmedHost,
            user: user.trimmingCharacters(in: .whitespaces).isEmpty ? nil : user.trimmingCharacters(in: .whitespaces),
            remotePath: remotePath.trimmingCharacters(in: .whitespaces),
            localPath: localPath.trimmingCharacters(in: .whitespaces),
            jumpHost: jumpHost.trimmingCharacters(in: .whitespaces).isEmpty ? nil : jumpHost.trimmingCharacters(in: .whitespaces)
        )
    }
}

struct FolderEditorSheet: View {
    @Binding var draft: FolderDraft
    /// ssh-config aliases for the host picker.
    let knownHosts: [String]
    /// Existing tunnels, to prefill the jump when the chosen host uses one.
    let tunnels: [TunnelConfig]
    let existingFolderNames: [String]
    let onCancel: () -> Void
    /// mountNow: "Save & Mount" vs plain Save.
    let onSave: (_ mountNow: Bool) -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(draft.originalName == nil ? "New Mounted Folder" : "Edit Folder")
                    .font(.system(size: 16, weight: .bold))
                Text("A remote directory in the Finder over SSH (FUSE-T — no kernel extension). Keep the host warm and mounts are instant with no prompts.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                GridRow {
                    fieldLabel("Host")
                    HStack(spacing: 6) {
                        TextField("vista, or user@host.edu", text: $draft.host)
                            .textFieldStyle(.roundedBorder)
                        if !knownHosts.isEmpty {
                            Menu {
                                ForEach(knownHosts, id: \.self) { alias in
                                    Button(alias) { applyHost(alias) }
                                }
                            } label: {
                                Image(systemName: "chevron.up.chevron.down")
                                    .font(.system(size: 9, weight: .semibold))
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            .help("Pick a host from your ssh config")
                        }
                    }
                }
                GridRow {
                    fieldLabel("Remote path")
                    TextField("empty = home directory (~)", text: $draft.remotePath)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: draft.remotePath) { _ in autoSuggestName() }
                }
                GridRow {
                    fieldLabel("Name")
                    VStack(alignment: .leading, spacing: 2) {
                        TextField(suggestedName.isEmpty ? "vista-home" : suggestedName, text: $draft.name)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: draft.name) { newValue in
                                if newValue != suggestedName {
                                    draft.nameEditedByUser = !newValue.isEmpty
                                }
                            }
                        if let nameProblem {
                            Label(nameProblem, systemImage: "exclamationmark.triangle.fill")
                                .font(.system(size: 10))
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }

            DisclosureGroup {
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                    GridRow {
                        fieldLabel("User")
                        TextField("from ssh config when empty", text: $draft.user)
                            .textFieldStyle(.roundedBorder)
                    }
                    GridRow {
                        fieldLabel("Jump host")
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("e.g. randi (empty = direct)", text: $draft.jumpHost)
                                .textFieldStyle(.roundedBorder)
                            if let jumpSuggestion {
                                Button("Use \(jumpSuggestion) (your tunnels to this host jump through it)") {
                                    draft.jumpHost = jumpSuggestion
                                }
                                .buttonStyle(.link)
                                .font(.system(size: 10))
                            }
                        }
                    }
                    GridRow {
                        fieldLabel("Mount at")
                        TextField(defaultLocalPath, text: $draft.localPath)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                .padding(.top, 6)
            } label: {
                Text("Advanced")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 0)
            Divider()

            HStack(spacing: 10) {
                if draft.originalName != nil {
                    Button("Delete", role: .destructive, action: onDelete)
                }
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Save", action: { onSave(false) })
                    .disabled(!canSave)
                Button("Save & Mount", action: { onSave(true) })
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func fieldLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(.secondary)
            .frame(width: 82, alignment: .trailing)
    }

    // MARK: - Suggestions & validation

    private func applyHost(_ alias: String) {
        draft.host = alias
        if let jumpSuggestion, draft.jumpHost.isEmpty {
            // A host we always reach through a jump should mount through it too.
            draft.jumpHost = jumpSuggestion
        }
        autoSuggestName()
    }

    private func autoSuggestName() {
        guard !draft.nameEditedByUser else { return }
        draft.name = suggestedName
    }

    /// "vista-home", "cri22in001-jzhou" — host plus the path's last component.
    private var suggestedName: String {
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: "@").last.map(String.init) ?? ""
        guard !host.isEmpty else { return "" }
        let leaf = draft.remotePath.split(separator: "/").last.map(String.init) ?? "home"
        return "\(host)-\(leaf)"
    }

    private var jumpSuggestion: String? {
        let host = draft.host.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, draft.jumpHost.isEmpty else { return nil }
        return tunnels.first { $0.host == host && !($0.jumpHost ?? "").isEmpty }?.jumpHost
    }

    private var defaultLocalPath: String {
        let name = draft.name.trimmingCharacters(in: .whitespaces)
        return "~/mnt/\(name.isEmpty ? "<name>" : name)"
    }

    private var nameProblem: String? {
        let trimmed = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let taken = existingFolderNames.contains { $0 == trimmed && $0 != draft.originalName }
        return taken ? "A folder named “\(trimmed)” already exists." : nil
    }

    private var canSave: Bool {
        !draft.name.trimmingCharacters(in: .whitespaces).isEmpty
            && !draft.host.trimmingCharacters(in: .whitespaces).isEmpty
            && nameProblem == nil
    }
}
