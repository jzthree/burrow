import PortKeeperCore
import SwiftUI

struct ProfileDraft: Identifiable {
    let id = UUID()
    let originalName: String?
    var name: String
    var selectedTunnels: Set<String>
    var selectedGateways: Set<String>

    init(profile: Profile, originalName: String?) {
        self.originalName = originalName
        self.name = profile.name
        self.selectedTunnels = Set(profile.tunnels)
        self.selectedGateways = Set(profile.gateways)
    }

    static func newProfile(existing: [Profile]) -> ProfileDraft {
        let names = Set(existing.map(\.name))
        var name = "profile"
        var suffix = 2
        while names.contains(name) {
            name = "profile-\(suffix)"
            suffix += 1
        }
        return ProfileDraft(profile: Profile(name: name), originalName: nil)
    }

    func toProfile() throws -> Profile {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw DraftError("Profile name is required.")
        }
        guard !selectedTunnels.isEmpty || !selectedGateways.isEmpty else {
            throw DraftError("Pick at least one tunnel or gateway.")
        }
        return Profile(name: trimmed, tunnels: selectedTunnels.sorted(), gateways: selectedGateways.sorted())
    }
}

struct ProfileEditorSheet: View {
    @Binding var draft: ProfileDraft
    let tunnelNames: [String]
    let gatewayNames: [String]
    let onCancel: () -> Void
    let onSave: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(draft.originalName == nil ? "New Profile" : "Edit Profile")
                    .font(.system(size: 16, weight: .bold))
                Text("Start and stop a named set of tunnels and gateways together.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    Text("Name")
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 70, alignment: .trailing)
                    TextField("work", text: $draft.name)
                        .textFieldStyle(.roundedBorder)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    section(title: "Tunnels", items: tunnelNames, selection: $draft.selectedTunnels)
                    if !gatewayNames.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            section(title: "VPN Gateways", items: gatewayNames, selection: $draft.selectedGateways)
                            Text("A tunnel's gateway starts automatically when needed — include a gateway here only so the profile also stops it.")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                                .lineLimit(3)
                                .padding(.horizontal, 2)
                        }
                    }
                }
                .padding(.vertical, 2)
            }

            Divider()

            HStack {
                if draft.originalName != nil {
                    Button("Delete", role: .destructive, action: onDelete)
                }
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Save", action: onSave)
                    .keyboardShortcut(.defaultAction)
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func section(title: String, items: [String], selection: Binding<Set<String>>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 12.5, weight: .bold))
            if items.isEmpty {
                Text("None configured.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(items, id: \.self) { item in
                    Toggle(isOn: Binding(
                        get: { selection.wrappedValue.contains(item) },
                        set: { on in
                            if on { selection.wrappedValue.insert(item) } else { selection.wrappedValue.remove(item) }
                        }
                    )) {
                        Text(item).font(.system(size: 12))
                    }
                    .toggleStyle(.checkbox)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.62))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }
}
