import DeployerCore
import SwiftUI

/// Asks the user to compare the server's host-key fingerprint before anything is sent.
struct HostKeySheet: View {
    let hostKey: HostKeyInfo
    let language: AppLanguage
    let onDecision: (Bool) -> Void

    private func t(_ chinese: String, _ english: String) -> String {
        language == .chinese ? chinese : english
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(t("确认服务器主机指纹", "Confirm the server host key"), systemImage: "lock.shield")
                .font(.title2.weight(.semibold))

            Text(t("请通过独立渠道（例如云服务商控制台中运行 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub）核对以下指纹。只有完全一致时才继续。",
                   "Compare this fingerprint through an independent channel, such as running ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub in your provider's console. Continue only if it matches exactly."))
                .fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                row(t("服务器", "Server"), "\(hostKey.host):\(hostKey.port)")
                row(t("算法", "Algorithm"), "\(hostKey.algorithm) (\(hostKey.keyLength) bit)")
                row("SHA-256", hostKey.sha256Fingerprint, emphasized: true)
                row("MD5", hostKey.md5Fingerprint)
            }
            .padding(12)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))

            HStack {
                Spacer()
                Button(t("不一致，取消", "Doesn't match, cancel"), role: .cancel) { onDecision(false) }
                    .keyboardShortcut(.cancelAction)
                // Deliberately not the default action: approving must be an explicit click.
                Button(t("指纹一致，继续", "Fingerprint matches, continue")) { onDecision(true) }
            }
        }
        .padding(24)
        .frame(width: 560)
    }

    private func row(_ label: String, _ value: String, emphasized: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .font(.system(emphasized ? .body : .callout, design: .monospaced).weight(emphasized ? .semibold : .regular))
                .textSelection(.enabled)
        }
    }
}
