import SwiftUI

/// Drag-to-reorder for the custom rows in the menu-bar panel.
///
/// The panel is a `MenuBarExtra(.window)` — an `NSPanel` that hides the instant
/// an AppKit drag session starts, so pasteboard `.onDrag`/`.onDrop` aborts
/// mid-drag. This uses a pure-SwiftUI `DragGesture` instead: the picked-up row
/// follows the finger, the list reorders live as the pointer crosses other
/// rows, and the arrangement is persisted on release. Row frames are measured
/// (not assumed uniform), so variable-height rows reorder correctly.

/// Per-row frames in the list's coordinate space, keyed by row id.
struct RowFramePreferenceKey: PreferenceKey {
    static let defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { $1 })
    }
}

struct ReorderableRow: ViewModifier {
    let id: String
    let space: String
    @Binding var draggingId: String?
    @Binding var dragOffset: CGFloat
    let frames: [String: CGRect]
    let onReorder: (_ dragged: String, _ target: String) -> Void
    let onCommit: () -> Void

    private var isDragging: Bool { draggingId == id }

    func body(content: Content) -> some View {
        content
            .background(
                GeometryReader { geo in
                    Color.clear.preference(
                        key: RowFramePreferenceKey.self,
                        value: [id: geo.frame(in: .named(space))]
                    )
                }
            )
            .offset(y: isDragging ? dragOffset : 0)
            .scaleEffect(isDragging ? 1.02 : 1, anchor: .center)
            .shadow(color: .black.opacity(isDragging ? 0.20 : 0), radius: 7, x: 0, y: 4)
            .zIndex(isDragging ? 1 : 0)
            .gesture(dragGesture)
    }

    private var dragGesture: some Gesture {
        DragGesture(minimumDistance: 8, coordinateSpace: .named(space))
            .onChanged { value in
                if draggingId == nil { draggingId = id }
                guard draggingId == id else { return }
                let pointerY = value.location.y
                // Crossed onto another row? Reorder live (the callback rejects an
                // out-of-group move on its own, so a rejected target just no-ops).
                if let target = frames.first(where: { kv in
                    kv.key != id && pointerY >= kv.value.minY && pointerY <= kv.value.maxY
                })?.key {
                    onReorder(id, target)
                }
                // Keep the row's midpoint pinned under the finger relative to the
                // slot it now occupies, so live reorders never make it jump.
                if let mid = frames[id]?.midY {
                    dragOffset = pointerY - mid
                } else {
                    dragOffset = value.translation.height
                }
            }
            .onEnded { _ in
                let committed = draggingId == id
                draggingId = nil
                dragOffset = 0
                if committed { onCommit() }
            }
    }
}

struct ReorderableList: ViewModifier {
    let space: String
    @Binding var frames: [String: CGRect]

    func body(content: Content) -> some View {
        content
            .coordinateSpace(name: space)
            .onPreferenceChange(RowFramePreferenceKey.self) { frames = $0 }
    }
}

extension View {
    /// Makes this row a `DragGesture` reorder source/target within `space`.
    func reorderableRow(
        id: String,
        space: String,
        draggingId: Binding<String?>,
        dragOffset: Binding<CGFloat>,
        frames: [String: CGRect],
        onReorder: @escaping (String, String) -> Void,
        onCommit: @escaping () -> Void
    ) -> some View {
        modifier(ReorderableRow(
            id: id, space: space, draggingId: draggingId, dragOffset: dragOffset,
            frames: frames, onReorder: onReorder, onCommit: onCommit
        ))
    }

    /// Wrap the list container: defines the coordinate space and collects the
    /// rows' measured frames for hit-testing during a drag.
    func reorderableList(space: String, frames: Binding<[String: CGRect]>) -> some View {
        modifier(ReorderableList(space: space, frames: frames))
    }
}
