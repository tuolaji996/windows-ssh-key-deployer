import DeployerCore
import SwiftUI

/// The window root: language/theme settings, toolbar and the approval sheets.
struct ContentView: View {
    @EnvironmentObject private var model: DeployerViewModel
    @AppStorage("language") private var language = AppLanguage.systemDefault
    @AppStorage("theme") private var theme = AppTheme.system

    var body: some View {
        MainWindowContent()
            .environment(\.appLanguage, language)
            .toolbar { toolbar }
            .navigationTitle("SSH Key Deployer")
            .sheet(item: Binding(
                get: { model.pendingHostKey },
                set: { if $0 == nil && model.pendingHostKey != nil { model.resolveHostKey(approved: false) } }
            )) { prompt in
                HostKeySheet(hostKey: prompt) { approved in model.resolveHostKey(approved: approved) }
                    .environment(\.appLanguage, language)
            }
            .background(
                // A second sheet must hang off a different view.
                Color.clear.sheet(item: Binding(
                    get: { model.pendingPlan },
                    set: { if $0 == nil && model.pendingPlan != nil { model.resolvePlan(approved: false) } }
                )) { prompt in
                    PlanSheet(plan: prompt.plan) { approved in model.resolvePlan(approved: approved) }
                        .environment(\.appLanguage, language)
                })
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Picker(language.t("语言", "Language"), selection: $language) {
                Text("中文").tag(AppLanguage.chinese)
                Text("English").tag(AppLanguage.english)
            }
            .pickerStyle(.segmented)

            Picker(language.t("外观", "Appearance"), selection: $theme) {
                Label(language.t("跟随系统", "System"), systemImage: "circle.lefthalf.filled").tag(AppTheme.system)
                Label(language.t("浅色", "Light"), systemImage: "sun.max").tag(AppTheme.light)
                Label(language.t("深色", "Dark"), systemImage: "moon").tag(AppTheme.dark)
            }
            .pickerStyle(.menu)
        }
    }
}

/// Everything inside the window: the form on the left, live progress on the right.
struct MainWindowContent: View {
    var body: some View {
        HStack(spacing: 0) {
            FormColumn()
                .frame(minWidth: 450, idealWidth: 500, maxWidth: 540)
                .background(Palette.sidebar)
            Divider()
            ProgressColumn()
                .frame(minWidth: 420, maxWidth: .infinity)
                .background(Palette.page)
        }
    }
}

// MARK: - Form column

struct FormColumn: View {
    @EnvironmentObject private var model: DeployerViewModel
    @Environment(\.appLanguage) private var language

    private func t(_ chinese: String, _ english: String) -> String { language.t(chinese, english) }
    private var labelWidth: CGFloat { language == .chinese ? 64 : 92 }
    private func issue(_ field: FormField) -> String? { model.visibleIssues[field]?(language) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    connectionCard
                    policyCard
                    keyCard
                    optionsCard
                    about
                }
                .padding(16)
                .disabled(model.isBusy)
            }
            Divider()
            actionBar
        }
    }

    // MARK: Connection

    private var connectionCard: some View {
        Card(title: t("服务器连接", "Server connection"), systemImage: "server.rack") {
            recentMenu
        } content: {
            VStack(alignment: .leading, spacing: 10) {
                FieldRow(label: t("地址", "Host"), error: issue(.host) ?? issue(.port), labelWidth: labelWidth) {
                    HStack(spacing: 6) {
                        TextField("", text: $model.host, prompt: Text("203.0.113.10"))
                            .textFieldStyle(.roundedBorder)
                            .errorOutline(issue(.host) != nil)
                        Text(t("端口", "Port")).foregroundStyle(.secondary)
                        TextField("", text: $model.port, prompt: Text("22"))
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 64)
                            .errorOutline(issue(.port) != nil)
                    }
                }
                FieldRow(label: t("账号", "Account"), error: issue(.username), labelWidth: labelWidth) {
                    TextField("", text: $model.username, prompt: Text("root"))
                        .textFieldStyle(.roundedBorder)
                        .errorOutline(issue(.username) != nil)
                }
                FieldRow(label: t("密码", "Password"), error: issue(.password), labelWidth: labelWidth) {
                    SecureField("", text: $model.password, prompt: Text(t("该账号的当前密码", "This account's current password")))
                        .textFieldStyle(.roundedBorder)
                        .errorOutline(issue(.password) != nil)
                }
                if model.needsRootPasswordOption {
                    rootPasswordDisclosure
                }
                Text(t("密码只保存在内存中，仅用于本次连接和 sudo，部署结束后立即清除。",
                       "Passwords stay in memory for this connection and sudo only, and are cleared when the deployment ends."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var rootPasswordDisclosure: some View {
        DisclosureGroup(isExpanded: $model.showRootPassword) {
            VStack(alignment: .leading, spacing: 8) {
                FieldRow(label: t("root 密码", "Root password"), error: issue(.rootPassword), labelWidth: labelWidth) {
                    SecureField("", text: $model.rootPassword, prompt: Text(t("可选", "Optional")))
                        .textFieldStyle(.roundedBorder)
                        .errorOutline(issue(.rootPassword) != nil)
                }
                Text(t("仅在账号没有 sudo 时通过 su 使用：安装 sudo 或临时授予 sudo 权限（结束后移除）。不会保存，也不会写入日志。",
                       "Used only through su when the account has no sudo: to install sudo or grant temporary sudo, which is removed afterwards. Never stored or logged."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, labelWidth + 12)
            }
            .padding(.top, 8)
        } label: {
            Text(t("如果此账号没有 sudo", "If this account has no sudo"))
                .font(.callout)
        }
    }

    private var recentMenu: some View {
        Menu {
            if model.recentServers.isEmpty {
                Text(t("暂无最近使用的服务器", "No recent servers"))
            } else {
                Section(t("填入表单", "Fill in the form")) {
                    ForEach(model.recentServers) { server in
                        Button(server.title) { model.fill(from: server) }
                    }
                }
                Menu(t("移除", "Remove")) {
                    ForEach(model.recentServers) { server in
                        Button(server.title) { model.removeRecent(server) }
                    }
                    Divider()
                    Button(t("全部清除", "Clear all"), role: .destructive) { model.clearRecent() }
                }
            }
        } label: {
            Label(t("最近", "Recent"), systemImage: "clock.arrow.circlepath")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(model.recentServers.isEmpty)
        .help(t("最近使用的服务器（不保存密码）", "Recent servers (passwords are never saved)"))
    }

    // MARK: Login policy

    private var policyCard: some View {
        Card(title: t("登录策略", "Login policy"), systemImage: "person.badge.shield.checkmark") {
            VStack(alignment: .leading, spacing: 12) {
                FieldRow(label: t("root 登录", "Root login"), error: issue(.rootLogin), labelWidth: labelWidth) {
                    Picker("", selection: $model.rootLogin) {
                        ForEach(RootLoginChoice.allCases) { choice in
                            Text(choice.title(language)).tag(choice)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
                FieldRow(label: t("密码登录", "Passwords"), labelWidth: labelWidth) {
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(t("其他账号可以用密码登录", "Other accounts can log in with a password"), isOn: Binding(
                            get: { model.effectivePasswordLogin },
                            set: { model.passwordLoginForOthers = $0 }))
                            .disabled(model.rootLogin != .disabled)
                        if model.rootLogin != .disabled {
                            Text(model.rootLogin == .keyOnly
                                 ? t("root 仅密钥登录时，所有账号都会关闭密码登录。", "Key-only root login turns password login off for every account.")
                                 : t("root 允许密码登录时，密码登录对所有账号保持开启。", "Allowing root's password keeps password login on for every account."))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Callout(text: model.policySummary(language), systemImage: "info.circle.fill")
                if !model.effectivePasswordLogin {
                    Callout(
                        text: t("密码登录将被关闭。关闭前会先验证新密钥可以登录；请保持现有会话或服务器控制台打开，直到部署完成。",
                                "Password login will be turned off. The new key is verified first; keep an existing session or the server console open until the deployment finishes."),
                        systemImage: "exclamationmark.triangle.fill",
                        tint: Palette.caution)
                }
            }
        }
    }

    // MARK: Key

    private var keyCard: some View {
        Card(title: t("本地密钥", "Local key"), systemImage: "key.fill") {
            VStack(alignment: .leading, spacing: 10) {
                FieldRow(label: t("私钥", "Private key"), error: issue(.keyPath), labelWidth: labelWidth) {
                    HStack(spacing: 6) {
                        TextField("", text: $model.keyPath, prompt: Text("~/.ssh/id_ed25519"))
                            .textFieldStyle(.roundedBorder)
                            .errorOutline(issue(.keyPath) != nil)
                            .onSubmit { Task { await model.refreshKeyInfo() } }
                        Menu(t("选择", "Choose")) {
                            Button(t("选择现有私钥…", "Existing private key…"), action: model.chooseExistingKey)
                            Button(t("新密钥保存位置…", "Location for a new key…"), action: model.chooseNewKeyLocation)
                            Divider()
                            Button(t("使用默认路径", "Use default path"), action: model.useDefaultKeyPath)
                        }
                        .fixedSize()
                    }
                }
                FieldRow(label: t("指纹", "Fingerprint"), labelWidth: labelWidth) {
                    if let key = model.keyInfo {
                        Text(key.fingerprint)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    } else {
                        Text(t("尚无密钥，部署时会自动生成 Ed25519 密钥。", "No key yet; an Ed25519 key is generated when you deploy."))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                HStack(spacing: 8) {
                    Button(model.keyInfo == nil ? t("生成密钥", "Generate key") : t("校验密钥", "Check key"),
                           action: model.generateOrLoadKey)
                    Button(t("复制公钥", "Copy public key"), action: model.copyPublicKey)
                        .disabled(model.keyInfo == nil)
                    Button(t("在访达中显示", "Show in Finder"), action: model.revealKeyInFinder)
                }
                .controlSize(.small)
                .padding(.leading, labelWidth + 12)
            }
        }
    }

    // MARK: Options

    private var optionsCard: some View {
        Card(title: t("选项", "Options"), systemImage: "slider.horizontal.3") {
            VStack(alignment: .leading, spacing: 10) {
                Toggle(isOn: $model.changePort) {
                    Text(t("更改 SSH 端口", "Change the SSH port"))
                }
                .toggleStyle(.switch)
                if model.changePort {
                    FieldRow(label: t("新端口", "New port"), error: issue(.newSSHPort), labelWidth: labelWidth) {
                        TextField("", text: $model.newPort, prompt: Text("2222"))
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 90)
                            .errorOutline(issue(.newSSHPort) != nil)
                    }
                }
                Text(t("会自动放行防火墙（ufw/firewalld）和 SELinux 端口；新端口验证可以登录后才关闭旧端口。",
                       "The firewall (ufw/firewalld) and SELinux are updated for you; the old port closes only after key login works on the new one."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var about: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(t("仅用于你拥有或获准管理的 Linux 服务器。如果主机指纹与独立渠道核实的不一致，请取消部署。",
                   "Use only on Linux servers you own or are authorized to manage. Cancel if the host fingerprint doesn't match an independent check."))
                .fixedSize(horizontal: false, vertical: true)
            Link(t("GitHub 项目主页", "Project on GitHub"),
                 destination: URL(string: "https://github.com/tuolaji996/windows-ssh-key-deployer")!)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
    }

    // MARK: Action bar

    private var actionBar: some View {
        HStack(spacing: 12) {
            if model.isDeploying {
                Label(t("部署进行中，请勿关闭窗口。", "Deploying; keep this window open."), systemImage: "hourglass")
                    .foregroundStyle(.secondary)
                Spacer()
                Button(t("取消并回滚", "Cancel and roll back"), role: .cancel, action: model.cancelDeployment)
                    .controlSize(.large)
            } else {
                let problems = model.allIssues.count
                if problems > 0 {
                    Label(t("还有 \(problems) 处需要填写或修正", "\(problems) field\(problems == 1 ? "" : "s") to complete or fix"),
                          systemImage: "exclamationmark.circle")
                        .foregroundStyle(.secondary)
                } else {
                    Label(t("准备就绪", "Ready to deploy"), systemImage: "checkmark.circle")
                        .foregroundStyle(Palette.success)
                }
                Spacer()
                Button(action: model.deploy) {
                    Label(t("开始部署", "Deploy"), systemImage: "paperplane.fill")
                        .padding(.horizontal, 6)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canDeploy)
            }
        }
        .font(.callout)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}
