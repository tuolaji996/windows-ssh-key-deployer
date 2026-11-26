import DeployerCore
import SwiftUI

/// Asks the user to compare the server's host-key fingerprint before anything is sent.
struct HostKeySheet: View {
    let hostKey: HostKeyPrompt
    let onDecision: (Bool) -> Void
    @Environment(\.appLanguage) private var language

    private func t(_ chinese: String, _ english: String) -> String { language.t(chinese, english) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 4) {
                    Text(t("确认服务器主机指纹", "Confirm the server's host key"))
                        .font(.title2.weight(.semibold))
                    Text(t("请通过独立渠道（例如在云服务商控制台中运行下面的命令）核对指纹，完全一致时才继续。",
                           "Compare this fingerprint through an independent channel, such as running the command below in your provider's console. Continue only if it matches exactly."))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Text("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Palette.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))

            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 8) {
                row(t("服务器", "Server"), "\(hostKey.host):\(hostKey.port)")
                row(t("算法", "Algorithm"), "\(hostKey.algorithm) (\(hostKey.keyLength) bit)")
                row("SHA-256", hostKey.sha256Fingerprint, emphasized: true)
                row("MD5", hostKey.md5Fingerprint)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.card, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Palette.cardStroke))

            HStack {
                Spacer()
                Button(t("不一致，取消", "Doesn't match, cancel"), role: .cancel) { onDecision(false) }
                    .keyboardShortcut(.cancelAction)
                // Deliberately not the default action: approving must be an explicit click.
                Button(t("指纹一致，继续", "Fingerprint matches, continue")) { onDecision(true) }
            }
            .controlSize(.large)
        }
        .padding(24)
        .frame(width: 580)
    }

    private func row(_ label: String, _ value: String, emphasized: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .font(.system(.callout, design: .monospaced).weight(emphasized ? .semibold : .regular))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
