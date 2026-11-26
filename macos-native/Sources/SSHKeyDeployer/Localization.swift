import DeployerCore
import Foundation
import SwiftUI

enum AppLanguage: String, CaseIterable {
    case chinese = "zh-Hans"
    case english = "en"

    static var systemDefault: AppLanguage {
        Locale.preferredLanguages.first?.hasPrefix("zh") == true ? .chinese : .english
    }

    /// Picks the string for this language.
    func t(_ chinese: String, _ english: String) -> String {
        self == .chinese ? chinese : english
    }
}

enum AppTheme: String, CaseIterable {
    case system, light, dark
}

private struct AppLanguageKey: EnvironmentKey {
    static let defaultValue = AppLanguage.english
}

extension EnvironmentValues {
    /// The UI language, injected once at the window root (and by the snapshot renderer).
    var appLanguage: AppLanguage {
        get { self[AppLanguageKey.self] }
        set { self[AppLanguageKey.self] = newValue }
    }
}

/// Text kept in both languages so the log and status re-render when the language changes.
struct LocalizedText: Hashable {
    let chinese: String
    let english: String

    init(_ chinese: String, _ english: String) {
        self.chinese = chinese
        self.english = english
    }

    /// The same text in both languages (e.g. raw server output).
    init(verbatim text: String) {
        self.init(text, text)
    }

    func callAsFunction(_ language: AppLanguage) -> String {
        language == .chinese ? chinese : english
    }
}

// MARK: - Steps

/// The user-facing steps shown in the progress timeline.
enum DeploymentStep: Int, CaseIterable, Identifiable {
    case localKey, hostKey, inspect, privileges, publicKey, configuration, validation, reload, changePort, keyLogin

    var id: Int { rawValue }

    var title: LocalizedText {
        switch self {
        case .localKey: return .init("检查本地密钥", "Check local key")
        case .hostKey: return .init("确认主机指纹", "Confirm host key")
        case .inspect: return .init("检测服务器并确认计划", "Inspect server and approve plan")
        case .privileges: return .init("准备管理员权限", "Prepare admin access")
        case .publicKey: return .init("安装公钥", "Install public key")
        case .configuration: return .init("写入 SSH 策略", "Write SSH policy")
        case .validation: return .init("验证 sshd 配置", "Validate sshd configuration")
        case .reload: return .init("重新加载 SSH", "Reload SSH")
        case .changePort: return .init("更改 SSH 端口", "Change SSH port")
        case .keyLogin: return .init("验证密钥登录", "Verify key login")
        }
    }

    init?(stage: DeploymentStage) {
        switch stage {
        case .validating, .securingPrivateKey: self = .localKey
        case .connecting, .awaitingHostKeyApproval: self = .hostKey
        case .inspectingServer, .awaitingPlanApproval: self = .inspect
        case .preparingPrivileges, .checkingPrivileges: self = .privileges
        case .installingPublicKey: self = .publicKey
        case .writingSshdConfiguration: self = .configuration
        case .validatingSshdConfiguration: self = .validation
        case .reloadingSsh, .verifyingEffectiveConfiguration: self = .reload
        case .changingPort: self = .changePort
        case .verifyingKeyLogin: self = .keyLogin
        default: return nil
        }
    }
}

enum StepState {
    case pending, active, done, failed
}

// MARK: - Login policy

/// The single root-login choice shown in the form.
enum RootLoginChoice: String, CaseIterable, Identifiable {
    case disabled, keyOnly, keyAndPassword

    var id: String { rawValue }

    var title: LocalizedText {
        switch self {
        case .disabled: return .init("禁止", "Disabled")
        case .keyOnly: return .init("仅密钥", "Key only")
        case .keyAndPassword: return .init("密钥 + 密码", "Key + password")
        }
    }
}

enum PolicyText {
    /// "After deployment: …" in plain language.
    static func summary(root: RootLoginChoice, passwordLogin: Bool, account: String, prefixed: Bool = true) -> LocalizedText {
        let rootPart: LocalizedText
        switch root {
        case .disabled: rootPart = .init("root 不能通过 SSH 登录", "root cannot log in over SSH")
        case .keyOnly: rootPart = .init("root 只能用密钥登录", "root can log in with the key only")
        case .keyAndPassword: rootPart = .init("root 可以用密钥或密码登录", "root can log in with the key or its password")
        }
        let passwordPart: LocalizedText = passwordLogin
            ? .init("其他账号仍可使用密码登录", "other accounts can still use their passwords")
            : .init("所有账号都关闭密码登录", "password login is off for everyone")
        var chinese = (prefixed ? "部署后：" : "") + "\(rootPart.chinese)；\(passwordPart.chinese)。"
        let sentence = "\(rootPart.english); \(passwordPart.english)."
        var english = prefixed ? "After deployment: " + sentence : sentence.prefix(1).uppercased() + sentence.dropFirst()
        let name = account.trimmingCharacters(in: .whitespaces)
        if root == .disabled, !name.isEmpty, name != "root" {
            chinese += "\(name) 使用这把密钥登录。"
            english += " \(name) logs in with this key."
        }
        return .init(chinese, english)
    }

    static func rootPolicy(_ policy: RootLoginPolicy) -> LocalizedText {
        switch policy {
        case .disabled: return RootLoginChoice.disabled.title
        case .keyOnly: return RootLoginChoice.keyOnly.title
        case .passwordAndKey: return RootLoginChoice.keyAndPassword.title
        }
    }
}

// MARK: - Validation messages

enum ValidationText {
    private static let known: [String: LocalizedText] = [
        "Host is required.": .init("请填写服务器地址。", "Host is required."),
        "Host must be a valid DNS name or IP address without a URL scheme or port.":
            .init("请填写有效的域名或 IP，不要带 http:// 或端口。", "Enter a DNS name or IP address, without http:// or a port."),
        "Port must be between 1 and 65535.": .init("端口必须在 1–65535 之间。", "Port must be between 1 and 65535."),
        "Username must be a valid Debian account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters).":
            .init("账号名只能包含小写字母、数字、下划线或连字符，最多 32 个字符。",
                  "Use lowercase letters, digits, _ or - (at most 32 characters)."),
        "Root login cannot be disabled when the deployment account is root.":
            .init("用 root 账号部署时不能禁止 root 登录。", "Root login can't be disabled when you deploy as root."),
        "A password is required for the initial SSH connection and sudo authentication.":
            .init("需要当前密码，用于首次连接和 sudo。", "Required for the first connection and sudo."),
        "Password cannot contain line breaks or null characters.":
            .init("密码不能包含换行或空字符。", "Password can't contain line breaks or null characters."),
        "Password cannot exceed 1024 characters.": .init("密码不能超过 1024 个字符。", "Password can't exceed 1024 characters."),
        "Private-key path is required.": .init("请填写私钥路径。", "Private-key path is required."),
        "Private-key path must be absolute.": .init("私钥路径必须是绝对路径（可用 ~ 开头）。", "Use an absolute path (~ is fine)."),
        "Select the private key, not the .pub file.": .init("请选择私钥，而不是 .pub 公钥。", "Select the private key, not the .pub file."),
        "Private-key path is invalid.": .init("私钥路径无效。", "Private-key path is invalid."),
    ]

    static func localize(_ message: String) -> LocalizedText {
        known[message] ?? LocalizedText(verbatim: message)
    }

    static let portNotNumeric = LocalizedText("端口必须是 1–65535 之间的数字。", "Port must be a number from 1 to 65535.")
    static let newPortInvalid = LocalizedText("新端口必须是 1–65535 之间的数字。", "New port must be a number from 1 to 65535.")
    static let newPortSame = LocalizedText("新端口与当前端口相同。", "The new port is the same as the current one.")
    static let rootPasswordInvalid = LocalizedText("root 密码不能包含换行或空字符。", "Root password can't contain line breaks or null characters.")
}

// MARK: - Server inspection and plan

extension ServerInfo {
    var displayName: String {
        if !osName.isEmpty { return osName }
        let joined = [osID, osVersion].filter { !$0.isEmpty }.joined(separator: " ")
        return joined.isEmpty ? "Linux" : joined
    }
}

extension PrivilegeMode {
    var text: LocalizedText {
        switch self {
        case .root: return .init("已是 root 账号", "Logged in as root")
        case .sudo: return .init("sudo（使用当前账号密码）", "sudo (with the account's password)")
        case .su: return .init("su + root 密码，临时授予 sudo", "su with the root password, temporary sudo")
        case .none: return .init("无法获得 root 权限", "No way to become root")
        }
    }
}

extension PlannedAction {
    var systemImage: String {
        switch self {
        case .installPackages: return "shippingbox"
        case .temporarySudoViaSu: return "clock.arrow.circlepath"
        case .installPublicKey: return "key"
        case .writeSshdPolicy: return "doc.badge.gearshape"
        case .changePort: return "arrow.left.arrow.right"
        case .openFirewallPort: return "flame"
        case .labelSelinuxPort: return "checkmark.shield"
        default: return "gearshape"
        }
    }

    /// Package installs stay on the server even if the deployment is rolled back.
    var isPersistent: Bool {
        if case .installPackages = self { return true }
        return false
    }

    var isTemporary: Bool {
        if case .temporarySudoViaSu = self { return true }
        return false
    }

    var text: LocalizedText {
        switch self {
        case let .installPackages(manager, packages):
            let list = packages.joined(separator: ", ")
            return .init("用 \(manager.rawValue) 安装软件包：\(list)", "Install packages with \(manager.rawValue): \(list)")
        case let .temporarySudoViaSu(account):
            return .init("通过 su 临时授予 \(account) sudo 权限", "Grant \(account) temporary sudo through su")
        case let .installPublicKey(account):
            return .init("把公钥加入 \(account) 的 authorized_keys", "Add the public key to \(account)'s authorized_keys")
        case let .writeSshdPolicy(rootLogin, passwordLogin):
            let root = PolicyText.rootPolicy(rootLogin)
            return .init("写入 SSH 策略：root 登录“\(root.chinese)”，密码登录\(passwordLogin ? "开启" : "关闭")",
                         "Write the SSH policy: root login \(root.english.lowercased()); password login \(passwordLogin ? "on" : "off")")
        case let .changePort(from, to):
            let old = from.map(String.init).joined(separator: ", ")
            return .init("把 SSH 端口从 \(old.isEmpty ? "22" : old) 改为 \(to)（新端口验证通过后才关闭旧端口）",
                         "Move SSH from port \(old.isEmpty ? "22" : old) to \(to) (the old port closes only after the new one works)")
        case let .openFirewallPort(firewall, port):
            return .init("在 \(firewall.rawValue) 中放行端口 \(port)", "Open port \(port) in \(firewall.rawValue)")
        case let .labelSelinuxPort(port):
            return .init("在 SELinux 中把端口 \(port) 标记为 ssh_port_t", "Label port \(port) as ssh_port_t in SELinux")
        default:
            return .init(verbatim: String(describing: self))
        }
    }
}

// MARK: - Errors

extension DeploymentError {
    /// A short headline for the error card.
    var localizedTitle: LocalizedText {
        switch kind {
        case .validation: return .init("输入有误", "Invalid input")
        case .key: return .init("本地密钥有问题", "Problem with the local key")
        case .hostKeyRejected: return .init("未批准主机指纹", "Host key not approved")
        case .hostKeyChanged: return .init("主机密钥已改变", "The host key changed")
        case .authenticationRejected: return .init("密码登录被拒绝", "Password login rejected")
        case .connectionTimedOut: return .init("连接超时", "Connection timed out")
        case .networkUnavailable, .connectionFailed: return .init("无法连接服务器", "Couldn't connect to the server")
        case .sudoNotAuthorized: return .init("账号没有 sudo 权限", "The account can't use sudo")
        case .sudoUnavailable: return .init("服务器未安装 sudo", "sudo isn't installed")
        case .sudoPasswordRejected: return .init("sudo 拒绝了密码", "sudo rejected the password")
        case .unsupportedServer: return .init("暂不支持此服务器", "This server isn't supported")
        case .noPrivilege: return .init("无法获得管理员权限", "No admin access")
        case .rootPasswordRejected: return .init("root 密码错误", "Root password rejected")
        case .suUnavailable: return .init("无法使用 su", "su isn't available")
        case .planRejected: return .init("已取消变更计划", "Plan not approved")
        case .packageInstallFailed: return .init("软件包安装失败", "Package installation failed")
        case .portChangeFailed: return .init("更改 SSH 端口失败", "Changing the SSH port failed")
        default: return .init("部署失败", "Deployment failed")
        }
    }

    /// What it means and what to do next, or nil when the core message says it all.
    var localizedHint: LocalizedText? {
        switch kind {
        case .authenticationRejected:
            return .init("请检查账号和当前密码，并确认该账号允许密码登录。服务器未做任何修改。",
                         "Check the account and its current password, and that it may log in with a password. Nothing on the server was changed.")
        case .connectionTimedOut, .networkUnavailable:
            return .init("请检查地址、端口、防火墙、VPN/局域网，以及 sshd 是否运行。服务器未做任何修改。",
                         "Check the address, port, firewall and VPN, and that sshd is running. Nothing on the server was changed.")
        case .hostKeyRejected:
            return .init("部署已停止，服务器未做任何修改。", "The deployment stopped. Nothing on the server was changed.")
        case .hostKeyChanged:
            return .init("服务器主机密钥与已批准的指纹不一致，已中止。请立即通过独立渠道核实服务器。",
                         "The server's host key no longer matches the approved fingerprint. Verify the server through an independent channel now.")
        case .sudoNotAuthorized:
            return .init("能用 su 切换 root 不等于有 sudo 权限。可以在“如果此账号没有 sudo”中填写 root 密码，或在 root 控制台把账号加入 sudo 组。",
                         "Being able to su is not the same as sudo rights. Enter the root password under \"If this account has no sudo\", or add the account to the sudo group from a root console.")
        case .sudoUnavailable:
            return .init("在“如果此账号没有 sudo”中填写 root 密码，工具会通过 su 安装 sudo。",
                         "Enter the root password under \"If this account has no sudo\" and sudo will be installed through su.")
        case .sudoPasswordRejected:
            return .init("sudo 需要的是当前账号的密码，而不是 root 密码。", "sudo needs this account's own password, not the root password.")
        case .unsupportedServer:
            return .init("该服务器的 sshd 不加载 /etc/ssh/sshd_config.d（例如 CentOS/RHEL 7–8）。服务器未做任何修改。",
                         "This server's sshd doesn't load /etc/ssh/sshd_config.d (e.g. CentOS/RHEL 7–8). Nothing on the server was changed.")
        case .noPrivilege:
            return .init("该账号没有 sudo 权限，且未提供 root 密码。请在“如果此账号没有 sudo”中填写 root 密码后重试。",
                         "The account has no sudo rights and no root password was given. Enter it under \"If this account has no sudo\" and try again.")
        case .rootPasswordRejected:
            return .init("su 拒绝了 root 密码，请确认填写的是 root 账号的密码。",
                         "su rejected the root password. Check that it is the password of the root account.")
        case .suUnavailable:
            return .init("su 未安装，或不允许该账号使用。请改用有 sudo 权限的账号。",
                         "su is missing or not allowed for this account. Use an account with sudo rights instead.")
        case .planRejected:
            return .init("你没有批准变更计划，服务器未做任何修改。", "You didn't approve the plan. Nothing on the server was changed.")
        case .packageInstallFailed:
            return .init("请检查服务器的软件源和网络连接。已经装好的软件包不会被回滚。",
                         "Check the server's package sources and network. Packages that were already installed stay installed.")
        case .portChangeFailed:
            return .init("新端口未能验证通过，SSH 仍使用原来的端口。", "The new port could not be verified; SSH keeps using the original port.")
        default:
            return nil
        }
    }

    /// The full text for the log: hint, original detail and rollback note.
    var localized: LocalizedText {
        let hint = localizedHint
        let rollbackNote: LocalizedText?
        switch rollback {
        case .notNeeded: rollbackNote = nil
        case .succeeded: rollbackNote = LocalizedText("远端修改已回滚。", "Server changes were rolled back.")
        case .incomplete:
            rollbackNote = LocalizedText("远端回滚未确认！请立即通过现有会话或服务器控制台检查 SSH。",
                                         "Rollback was not confirmed! Check SSH now from an existing session or the server console.")
        }
        let headline = hint.map { localizedTitle.chinese + "：" + $0.chinese } ?? localizedTitle.chinese
        let chinese = [headline, message, rollbackNote?.chinese]
            .compactMap { $0 }.joined(separator: "\n")
        // The core message already states the rollback result; only add emphasis when it failed.
        let englishWarning: String?
        if case .incomplete = rollback { englishWarning = rollbackNote?.english } else { englishWarning = nil }
        let english = [message, englishWarning].compactMap { $0 }.joined(separator: "\n")
        return .init(chinese, english)
    }
}
