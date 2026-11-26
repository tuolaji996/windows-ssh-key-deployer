import AppKit
import SwiftUI

/// Colours that adapt to light and dark appearance.
enum Palette {
    static let page = Color(nsColor: .windowBackgroundColor)
    static let card = dynamic(light: NSColor.white, dark: NSColor(white: 1, alpha: 0.055))
    static let cardStroke = dynamic(light: NSColor(white: 0, alpha: 0.09), dark: NSColor(white: 1, alpha: 0.09))
    static let inset = dynamic(light: NSColor(white: 0, alpha: 0.045), dark: NSColor(white: 0, alpha: 0.28))
    static let sidebar = dynamic(light: NSColor(white: 0.955, alpha: 1), dark: NSColor(white: 0.13, alpha: 1))
    static let success = dynamic(light: NSColor(red: 0.13, green: 0.6, blue: 0.3, alpha: 1),
                                 dark: NSColor(red: 0.3, green: 0.82, blue: 0.47, alpha: 1))
    static let danger = dynamic(light: NSColor(red: 0.82, green: 0.18, blue: 0.16, alpha: 1),
                                dark: NSColor(red: 1, green: 0.42, blue: 0.4, alpha: 1))
    static let caution = dynamic(light: NSColor(red: 0.72, green: 0.42, blue: 0, alpha: 1),
                                 dark: NSColor(red: 1, green: 0.72, blue: 0.3, alpha: 1))

    private static func dynamic(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        })
    }
}

/// A titled, rounded section.
struct Card<Content: View, Accessory: View>: View {
    let title: String
    let systemImage: String
    var tint: Color? = nil
    @ViewBuilder var accessory: () -> Accessory
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 8) {
                Label(title, systemImage: systemImage)
                    .font(.headline)
                    .foregroundStyle(tint ?? Color.primary)
                Spacer(minLength: 8)
                accessory()
            }
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.card, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(tint?.opacity(0.45) ?? Palette.cardStroke))
    }
}

extension Card where Accessory == EmptyView {
    init(title: String, systemImage: String, tint: Color? = nil, @ViewBuilder content: @escaping () -> Content) {
        self.init(title: title, systemImage: systemImage, tint: tint, accessory: { EmptyView() }, content: content)
    }
}

/// A form label with its control and, below the control, an inline error.
struct FieldRow<Field: View>: View {
    let label: String
    var error: String?
    var labelWidth: CGFloat
    @ViewBuilder var field: () -> Field

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: labelWidth, alignment: .trailing)
            VStack(alignment: .leading, spacing: 4) {
                field()
                if let error {
                    InlineError(text: error)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct InlineError: View {
    let text: String

    var body: some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.circle.fill")
        }
        .font(.caption)
        .foregroundStyle(Palette.danger)
    }
}

/// A red outline for a text field with an error.
struct ErrorOutline: ViewModifier {
    let isActive: Bool

    func body(content: Content) -> some View {
        content.overlay(
            RoundedRectangle(cornerRadius: 5)
                .strokeBorder(Palette.danger, lineWidth: 1.5)
                .opacity(isActive ? 1 : 0)
                .allowsHitTesting(false))
    }
}

extension View {
    func errorOutline(_ isActive: Bool) -> some View { modifier(ErrorOutline(isActive: isActive)) }
}

/// A small tinted note with an icon.
struct Callout: View {
    let text: String
    let systemImage: String
    var tint: Color = .accentColor

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: systemImage).foregroundStyle(tint)
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.callout)
        .padding(10)
        .background(tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

/// A capsule label such as "Persistent".
struct Badge: View {
    let text: String
    let tint: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(tint)
            .background(tint.opacity(0.14), in: Capsule())
            .fixedSize()
    }
}

/// Monospaced, selectable text with a Copy button.
struct CopyableBlock: View {
    let title: String
    let text: String
    let copyLabel: String
    let copiedLabel: String
    let onCopy: (String) -> Void
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title).font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
                Spacer()
                Button {
                    onCopy(text)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Label(copied ? copiedLabel : copyLabel, systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .controlSize(.small)
            }
            Text(text)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Palette.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
    }
}
