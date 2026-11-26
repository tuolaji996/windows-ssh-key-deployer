import DeployerCore
import SwiftUI

/// Shows what was detected on the server and every change that will be made,
/// before anything is changed. Cancel is the default; approving needs a click.
struct PlanSheet: View {
    let plan: DeploymentPlan
    let onDecision: (Bool) -> Void
    @Environment(\.appLanguage) private var language

    private func t(_ chinese: String, _ english: String) -> String { language.t(chinese, english) }
    private var server: ServerInfo { plan.server }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "checklist")
                    .font(.system(size: 28))
                    .foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 4) {
                    Text(t("确认变更计划", "Review the plan"))
                        .font(.title2.weight(.semibold))
                    Text(t("服务器已检测完毕，尚未做任何修改。批准后才会执行以下操作。",
                           "The server has been inspected and nothing has been changed yet. These steps run only after you approve."))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            section(t("检测到的服务器", "Detected server")) {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 6) {
                    row(t("系统", "System"), server.displayName + (server.osVersion.isEmpty || server.osName.contains(server.osVersion) ? "" : " (\(server.osVersion))"))
                    row(t("权限", "Privileges"), server.privilege.text(language), warn: server.privilege == .none)
                    row(t("包管理器", "Packages"), server.packageManager?.rawValue ?? t("未识别", "Not detected"))
                    row(t("服务管理", "Init system"), server.initSystem.rawValue + (server.socketActivated ? t("（ssh.socket 启动）", " (ssh.socket)") : ""))
                    row(t("防火墙", "Firewall"), server.firewall?.rawValue ?? t("未启用", "None active"))
                    row("SELinux", server.selinuxEnforcing ? t("强制模式", "Enforcing") : t("未强制", "Not enforcing"))
                    if !server.currentPorts.isEmpty {
                        row(t("当前端口", "SSH ports"), server.currentPorts.map(String.init).joined(separator: ", "))
                    }
                }
            }

            section(t("将要执行的操作", "What will happen")) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(plan.actions.enumerated()), id: \.offset) { _, action in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Image(systemName: action.systemImage)
                                .foregroundStyle(action.isPersistent ? Palette.caution : Color.accentColor)
                                .frame(width: 20)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(action.text(language))
                                    .fixedSize(horizontal: false, vertical: true)
                                if action.isPersistent {
                                    Badge(text: t("永久保留：回滚时不会卸载", "Persistent: not removed on rollback"), tint: Palette.caution)
                                } else if action.isTemporary {
                                    Badge(text: t("临时：完成后自动移除", "Temporary: removed afterwards"), tint: .secondary)
                                }
                            }
                            Spacer(minLength: 0)
                        }
                    }
                }
            }

            if plan.actions.contains(where: \.isPersistent) {
                Callout(text: t("标为“永久保留”的软件包安装不会被回滚，即使后续步骤失败。",
                                "Package installs marked persistent stay on the server even if a later step fails and everything else is rolled back."),
                        systemImage: "exclamationmark.triangle.fill", tint: Palette.caution)
            }

            HStack {
                Spacer()
                // Cancel is the default (Return) and the escape action; approving is an explicit click.
                Button(t("取消，不做修改", "Cancel, change nothing")) { onDecision(false) }
                    .keyboardShortcut(.defaultAction)
                Button(t("批准并继续", "Approve and continue")) { onDecision(true) }
            }
            .controlSize(.large)
            .background(
                Button("") { onDecision(false) }
                    .keyboardShortcut(.cancelAction)
                    .opacity(0)
                    .accessibilityHidden(true))
        }
        .padding(24)
        .frame(width: 600)
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            content()
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Palette.card, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Palette.cardStroke))
        }
    }

    private func row(_ label: String, _ value: String, warn: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .foregroundStyle(warn ? Palette.danger : Color.primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
