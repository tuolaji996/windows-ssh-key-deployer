import DeployerCore
import SwiftUI

/// Live progress: status, outcome card, step timeline and log.
struct ProgressColumn: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language

    private func t(_ chinese: String, _ english: String) -> String { language.t(chinese, english) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                StatusHeader()
                if let result = model.result, model.phase == .succeeded {
                    ResultCard(result: result)
                }
                if let failure = model.failure, model.phase == .failed {
                    FailureCard(failure: failure)
                }
                StepTimeline()
                if model.phase == .idle && !model.recentServers.isEmpty {
                    RecentServersCard()
                }
                LogCard()
            }
            .padding(16)
        }
    }
}

// MARK: - Status

private struct StatusHeader: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language

    private var icon: (String, Color) {
        switch model.phase {
        case .idle: return ("bolt.horizontal.circle", .secondary)
        case .deploying: return ("arrow.triangle.2.circlepath.circle.fill", .accentColor)
        case .succeeded: return ("checkmark.circle.fill", Palette.success)
        case .failed: return (model.failure?.isCancellation == true ? "minus.circle.fill" : "xmark.circle.fill",
                              model.failure?.isCancellation == true ? .secondary : Palette.danger)
        }
    }

    private var title: String {
        switch model.phase {
        case .idle: return language.t("准备部署", "Ready")
        case .deploying: return language.t("正在部署", "Deploying")
        case .succeeded: return language.t("部署成功", "Deployed")
        case .failed: return model.failure?.isCancellation == true ? language.t("已停止", "Stopped") : language.t("部署失败", "Failed")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: icon.0)
                    .font(.system(size: 28))
                    .foregroundStyle(icon.1)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.title3.weight(.semibold))
                    Text(model.status(language))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if model.phase == .deploying {
                    Text("\(Int((model.progress * 100).rounded()))%")
                        .font(.system(.title3, design: .rounded).weight(.semibold).monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            if model.phase == .deploying {
                ProgressView(value: model.progress)
                    .progressViewStyle(.linear)
            }
        }
        .padding(.horizontal, 4)
    }
}

// MARK: - Timeline

private struct StepTimeline: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language
    @State private var expandedAfterSuccess = false

    var body: some View {
        let steps = model.visibleSteps
        let doneCount = steps.filter { model.stepStates[$0] == .done }.count
        let collapsed = model.phase == .succeeded && !expandedAfterSuccess

        Card(title: language.t("步骤", "Steps"), systemImage: "list.bullet") {
            HStack(spacing: 8) {
                Text("\(doneCount)/\(steps.count)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
                if model.phase == .succeeded {
                    Button(collapsed ? language.t("展开", "Show") : language.t("收起", "Hide")) {
                        expandedAfterSuccess.toggle()
                    }
                    .buttonStyle(.link)
                    .font(.callout)
                }
            }
        } content: {
            if collapsed {
                Label(language.t("全部 \(steps.count) 个步骤均已完成。", "All \(steps.count) steps completed."),
                      systemImage: "checkmark.circle.fill")
                    .foregroundStyle(Palette.success)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(steps.enumerated()), id: \.element) { index, step in
                        TimelineRow(
                            title: step.title(language),
                            detail: detail(for: step),
                            state: model.stepStates[step] ?? .pending,
                            isLast: index == steps.count - 1,
                            nextDone: index + 1 < steps.count && model.stepStates[steps[index + 1]] == .done)
                    }
                }
            }
        }
    }

    /// The live core message under the active step (English only; Chinese shows the step title above).
    private func detail(for step: DeploymentStep) -> String? {
        guard model.stepStates[step] == .active, language == .english, model.phase == .deploying else { return nil }
        return model.activeStepDetail
    }
}

private struct TimelineRow: View {
    let title: String
    let detail: String?
    let state: StepState
    let isLast: Bool
    let nextDone: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            icon
                .frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(state == .active ? Font.body.weight(.semibold) : Font.body)
                    .foregroundStyle(state == .pending ? Color.secondary : Color.primary)
                if let detail {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.bottom, isLast ? 0 : 10)
        .background(alignment: .topLeading) {
            if !isLast {
                Rectangle()
                    .fill(state == .done && nextDone ? Palette.success.opacity(0.6) : Color.secondary.opacity(0.25))
                    .frame(width: 2)
                    .padding(.top, 21)
                    .padding(.bottom, 1)
                    .offset(x: 8)
            }
        }
    }

    @ViewBuilder private var icon: some View {
        switch state {
        case .pending:
            Circle().strokeBorder(Color.secondary.opacity(0.45), lineWidth: 1.5)
                .padding(1)
        case .active:
            ZStack {
                Circle().fill(Color.accentColor.opacity(0.22))
                Circle().fill(Color.accentColor).padding(4.5)
            }
        case .done:
            Image(systemName: "checkmark.circle.fill")
                .resizable()
                .foregroundStyle(Palette.success)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .resizable()
                .foregroundStyle(Palette.danger)
        }
    }
}

// MARK: - Recent servers

private struct RecentServersCard: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language

    private func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: language == .chinese ? "zh-Hans" : "en")
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    var body: some View {
        Card(title: language.t("最近的服务器", "Recent servers"), systemImage: "clock.arrow.circlepath") {
            Text(language.t("不保存密码", "Passwords are never saved"))
                .font(.caption)
                .foregroundStyle(.secondary)
        } content: {
            VStack(spacing: 0) {
                ForEach(Array(model.recentServers.enumerated()), id: \.element.id) { index, server in
                    if index > 0 { Divider() }
                    HStack(spacing: 10) {
                        Image(systemName: "server.rack")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(server.title)
                                .font(.body.weight(.medium))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text("\(SSHSnippets.abbreviated(server.keyPath)) · \(relative(server.lastUsed))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer(minLength: 8)
                        Button(language.t("填入", "Use")) { model.fill(from: server) }
                            .controlSize(.small)
                        Button {
                            model.removeRecent(server)
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.tertiary)
                        .help(language.t("从列表中移除", "Remove from the list"))
                    }
                    .padding(.vertical, 7)
                }
            }
        }
    }
}

// MARK: - Log

private struct LogCard: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language
    @State private var copied = false

    var body: some View {
        Card(title: language.t("日志", "Log"), systemImage: "text.alignleft") {
            Button {
                model.copyLog(language: language)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                Label(copied ? language.t("已复制", "Copied") : language.t("复制日志", "Copy log"),
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .controlSize(.small)
            .disabled(model.log.isEmpty)
        } content: {
            if model.log.isEmpty {
                Text(language.t("开始部署后，这里会显示详细日志。", "The detailed log appears here once a deployment starts."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 60)
                    .background(Palette.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 5) {
                            ForEach(model.log) { entry in
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(entry.time, style: .time)
                                        .foregroundStyle(.secondary)
                                    Text(entry.text(language))
                                        .foregroundStyle(entry.isError ? Palette.danger : Color.primary)
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .id(entry.id)
                            }
                        }
                        .font(.system(.caption, design: .monospaced))
                        .padding(10)
                    }
                    .frame(height: 240)
                    .background(Palette.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .onChange(of: model.log.count) { _ in
                        if let last = model.log.last { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
    }
}

// MARK: - Outcome cards

struct ResultCard: View {
    @Environment(\.appLanguage) private var language
    let result: ResultSummary

    var body: some View {
        Card(title: language.t("部署完成，密钥登录已验证", "Done: key login verified"),
             systemImage: "checkmark.seal.fill", tint: Palette.success) {
            VStack(alignment: .leading, spacing: 12) {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 6) {
                    if let os = result.osName {
                        row(language.t("系统", "System"), os)
                    }
                    row(language.t("服务器", "Server"), result.host)
                    row(language.t("SSH 端口", "SSH port"), result.sshPort == result.previousPort
                        ? String(result.sshPort)
                        : language.t("\(result.sshPort)（原 \(result.previousPort)）", "\(result.sshPort) (was \(result.previousPort))"))
                    row(language.t("登录账号", "Account"), result.username)
                    row(language.t("登录策略", "Policy"),
                        PolicyText.summary(root: result.rootLogin, passwordLogin: result.passwordLogin, account: result.username, prefixed: false)(language))
                }
                CopyableBlock(title: language.t("连接命令", "Connect"), text: result.sshCommand,
                              copyLabel: language.t("复制", "Copy"), copiedLabel: language.t("已复制", "Copied"),
                              onCopy: Clipboard.copy)
                CopyableBlock(title: language.t("~/.ssh/config 配置", "~/.ssh/config entry"), text: result.sshConfig,
                              copyLabel: language.t("复制", "Copy"), copiedLabel: language.t("已复制", "Copied"),
                              onCopy: Clipboard.copy)
                ForEach(result.warnings, id: \.self) { warning in
                    Callout(text: warning, systemImage: "exclamationmark.triangle.fill", tint: Palette.caution)
                }
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct FailureCard: View {
    @Environment(\.appLanguage) private var language
    let failure: FailureSummary

    private var tint: Color { failure.isCancellation ? .secondary : Palette.danger }

    var body: some View {
        Card(title: failure.title(language),
             systemImage: failure.isCancellation ? "stop.circle.fill" : "xmark.octagon.fill",
             tint: tint) {
            VStack(alignment: .leading, spacing: 10) {
                if let hint = failure.hint {
                    Text(hint(language))
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if !failure.detail.isEmpty {
                    Text(failure.detail)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(Palette.inset, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
                switch failure.rollback {
                case .notNeeded:
                    Label(language.t("服务器未做任何修改。", "Nothing on the server was changed."), systemImage: "checkmark.shield")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case .rolledBack:
                    Label(language.t("已开始的修改已全部回滚。", "Changes that had started were rolled back."),
                          systemImage: "arrow.uturn.backward.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case .incomplete:
                    Callout(text: language.t("回滚未确认！请立即通过现有会话或服务器控制台检查 SSH。",
                                             "Rollback was not confirmed! Check SSH now from an existing session or the server console."),
                            systemImage: "exclamationmark.triangle.fill", tint: Palette.danger)
                }
            }
        }
    }
}
