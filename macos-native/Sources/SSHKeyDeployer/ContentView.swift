import DeployerCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: DeployerViewModel
    @AppStorage("language") private var language = AppLanguage.systemDefault
    @AppStorage("theme") private var theme = AppTheme.system

    private func t(_ chinese: String, _ english: String) -> String {
        language == .chinese ? chinese : english
    }

    var body: some View {
        Form {
            connectionSection
            policySection
            keySection
            progressSection
            aboutSection
        }
        .formStyle(.grouped)
        .toolbar { toolbar }
        .navigationTitle("SSH Key Deployer")
        .sheet(item: Binding(
            get: { model.pendingHostKey.map(IdentifiedHostKey.init) },
            set: { if $0 == nil && model.pendingHostKey != nil { model.resolveHostKey(approved: false) } }
        )) { item in
            HostKeySheet(hostKey: item.info, language: language) { approved in
                model.resolveHostKey(approved: approved)
            }
        }
    }

    // MARK: Sections

    private var connectionSection: some View {
        Section {
            TextField(t("服务器地址", "Server host"), text: $model.host, prompt: Text("203.0.113.10"))
            TextField(t("SSH 端口", "SSH port"), text: $model.port)
            TextField(t("账号", "Account"), text: $model.username)
            SecureField(t("当前密码", "Current password"), text: $model.password)
        } header: {
            Text(t("服务器连接", "Server connection"))
        } footer: {
            Text(t("密码只保存在内存中，仅用于本次连接和 sudo，部署结束后自动清除。",
                   "The password is kept in memory only for this connection and sudo, and is cleared when the deployment ends."))
        }
        .disabled(model.isBusy)
    }

    private var policySection: some View {
        Section {
            Toggle(t("启用 root 登录（仅密钥或密钥+密码）", "Allow root login (key, or key and password)"),
                   isOn: $model.enableRootLogin)
            Toggle(t("保留密码登录", "Keep password login enabled"), isOn: $model.allowPasswordLogin)
        } header: {
            Text(t("SSH 登录策略", "SSH login policy"))
        } footer: {
            Text(t("关闭密码登录前，工具会先验证新密钥可以登录。请保持现有会话或服务器控制台打开，直到验证完成。",
                   "Before password login is disabled, the new key is verified. Keep an existing session or the server console open until verification completes."))
        }
        .disabled(model.isBusy)
    }

    private var keySection: some View {
        Section {
            HStack {
                TextField(t("私钥路径", "Private-key path"), text: $model.keyPath)
                    .onSubmit { Task { await model.refreshKeyInfo() } }
                Menu(t("选择…", "Choose…")) {
                    Button(t("选择现有私钥…", "Existing private key…"), action: model.chooseExistingKey)
                    Button(t("新密钥保存位置…", "Location for a new key…"), action: model.chooseNewKeyLocation)
                    Divider()
                    Button(t("使用默认路径", "Use default path"), action: model.useDefaultKeyPath)
                }
                .fixedSize()
            }

            if let key = model.keyInfo {
                LabeledContent(t("指纹", "Fingerprint")) {
                    Text(key.sha256Fingerprint)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            HStack {
                Button(model.keyInfo == nil ? t("生成密钥", "Generate key") : t("校验密钥", "Check key"),
                       action: model.generateOrLoadKey)
                Button(t("复制公钥", "Copy public key"), action: model.copyPublicKey)
                    .disabled(model.keyInfo == nil)
                Button(t("在访达中显示", "Show in Finder"), action: model.revealKeyInFinder)
            }
        } header: {
            Text(t("本地密钥", "Local key"))
        } footer: {
            Text(t("路径不存在时会生成新的 Ed25519 密钥对（私钥权限 0600）；已有密钥绝不会被覆盖。",
                   "A new Ed25519 pair (private key mode 0600) is created when the path does not exist; existing keys are never overwritten."))
        }
        .disabled(model.isBusy)
    }

    private var progressSection: some View {
        Section(t("部署进度", "Deployment progress")) {
            VStack(alignment: .leading, spacing: 8) {
                ProgressView(value: model.progress)
                Text(model.status(language))
                    .foregroundStyle(.secondary)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), alignment: .leading)], alignment: .leading, spacing: 6) {
                ForEach(DeploymentStep.allCases) { step in
                    StepLabel(title: step.title(language), state: model.stepStates[step] ?? .pending)
                }
            }

            HStack {
                Spacer()
                if model.isDeploying {
                    Button(t("取消并回滚", "Cancel and roll back"), role: .cancel, action: model.cancelDeployment)
                } else {
                    Button(t("开始部署", "Start deployment"), action: model.deploy)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.canDeploy)
                }
            }

            if !model.log.isEmpty {
                LogView(entries: model.log, language: language)
            }
        }
    }

    private var aboutSection: some View {
        Section {
            Text(t("仅用于你拥有或获准管理的 Debian 12/13 服务器。如果主机指纹与独立渠道核实的不一致，请取消部署。",
                   "Use only on Debian 12/13 servers you own or are authorized to manage. Cancel if the host fingerprint does not match an independent check."))
                .foregroundStyle(.secondary)
            Link(t("GitHub 项目主页", "Project on GitHub"),
                 destination: URL(string: "https://github.com/tuolaji996/windows-ssh-key-deployer")!)
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Picker(t("语言", "Language"), selection: $language) {
                Text("中文").tag(AppLanguage.chinese)
                Text("English").tag(AppLanguage.english)
            }
            .pickerStyle(.segmented)

            Picker(t("外观", "Appearance"), selection: $theme) {
                Label(t("跟随系统", "System"), systemImage: "circle.lefthalf.filled").tag(AppTheme.system)
                Label(t("浅色", "Light"), systemImage: "sun.max").tag(AppTheme.light)
                Label(t("深色", "Dark"), systemImage: "moon").tag(AppTheme.dark)
            }
            .pickerStyle(.menu)
        }
    }
}

private struct IdentifiedHostKey: Identifiable {
    let info: HostKeyInfo
    var id: String { info.sha256Fingerprint }
}

private struct StepLabel: View {
    let title: String
    let state: StepState

    var body: some View {
        Label {
            Text(title)
        } icon: {
            switch state {
            case .pending: Image(systemName: "circle").foregroundStyle(.tertiary)
            case .active: ProgressView().controlSize(.small)
            case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            }
        }
    }
}

private struct LogView: View {
    let entries: [LogEntry]
    let language: AppLanguage

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(entries) { entry in
                        HStack(alignment: .firstTextBaseline) {
                            Text(entry.time, style: .time)
                                .foregroundStyle(.secondary)
                            Text(entry.text(language))
                                .foregroundStyle(entry.isError ? Color.red : Color.primary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .id(entry.id)
                    }
                }
                .font(.system(.callout, design: .monospaced))
                .padding(8)
            }
            .frame(minHeight: 120, maxHeight: 220)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            .onChange(of: entries.count) { _ in
                if let last = entries.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
    }
}
