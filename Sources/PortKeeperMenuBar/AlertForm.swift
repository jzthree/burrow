import AppKit

/// Field rows for Burrow's NSAlert prompts.
///
/// A bare stack of NSTextFields reads as a list of grey sentences — nothing
/// says which parts are editable until you click one and a cursor appears.
/// Every row here pairs a right-aligned label with a visibly bezeled field, so
/// the form looks like a form before you touch it, and each field's *name*
/// stays visible after you've typed in it (a placeholder disappears exactly
/// when you'd want to check what the box was for).
enum AlertForm {
    static let labelWidth: CGFloat = 108
    static let fieldWidth: CGFloat = 268
    static var totalWidth: CGFloat { labelWidth + 8 + fieldWidth }

    static func container() -> NSStackView {
        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: totalWidth, height: 0))
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: totalWidth).isActive = true
        return stack
    }

    static func field(placeholder: String, value: String = "", secure: Bool = false) -> NSTextField {
        let field = secure ? NSSecureTextField() : NSTextField()
        field.placeholderString = placeholder
        field.stringValue = value
        // Explicit rather than inherited: a rounded bezel with a drawn
        // background is what makes a control read as "type here".
        field.isBezeled = true
        field.bezelStyle = .roundedBezel
        field.drawsBackground = true
        field.isEditable = true
        field.isSelectable = true
        field.focusRingType = .default
        field.translatesAutoresizingMaskIntoConstraints = false
        field.widthAnchor.constraint(equalToConstant: fieldWidth).isActive = true
        return field
    }

    /// A labeled row. `label` is shown without a colon when empty, so a
    /// full-width control (a checkbox, a note) can share the same alignment.
    static func row(_ label: String, _ control: NSView) -> NSStackView {
        let caption = NSTextField(labelWithString: label.isEmpty ? "" : "\(label):")
        caption.alignment = .right
        caption.textColor = .secondaryLabelColor
        caption.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        caption.translatesAutoresizingMaskIntoConstraints = false
        caption.widthAnchor.constraint(equalToConstant: labelWidth).isActive = true
        caption.setContentCompressionResistancePriority(.required, for: .horizontal)

        let row = NSStackView(views: [caption, control])
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false
        return row
    }

    /// Small explanatory text under a field, indented to the field column so it
    /// reads as belonging to it.
    static func note(_ text: String) -> NSStackView {
        let note = NSTextField(wrappingLabelWithString: text)
        note.textColor = .secondaryLabelColor
        note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        note.translatesAutoresizingMaskIntoConstraints = false
        note.widthAnchor.constraint(equalToConstant: fieldWidth).isActive = true
        return row("", note)
    }

    /// A titled divider between groups of fields — "these next ones are a
    /// different subject, and optional".
    static func section(_ title: String) -> NSStackView {
        let separator = NSBox()
        separator.boxType = .separator
        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.widthAnchor.constraint(equalToConstant: totalWidth).isActive = true

        let caption = NSTextField(labelWithString: title)
        caption.textColor = .secondaryLabelColor
        caption.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)

        let stack = NSStackView(views: [separator, caption])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    /// Sizes the accessory view to its content — an NSAlert won't do it for a
    /// constraint-driven stack, and an unsized one collapses to nothing.
    static func finish(_ container: NSStackView) {
        container.layoutSubtreeIfNeeded()
        container.setFrameSize(container.fittingSize)
    }
}
