import DeployerCore
import Foundation

enum AppLanguage: String, CaseIterable {
    case chinese = "zh-Hans"
    case english = "en"

    static var systemDefault: AppLanguage {
        Locale.preferredLanguages.first?.hasPrefix("zh") == true ? .chinese : .english
    }
}

enum AppTheme: String, CaseIterable {
    case system, light, dark
}

/// Text kept in both languages so the log and status re-render when the language changes.
struct LocalizedText: Hashable {
    let chinese: String
    let english: String

    init(_ chinese: String, _ english: String) {
        self.chinese = chinese
        self.english = english
    }

    func callAsFunction(_ language: AppLanguage) -> String {
        language == .chinese ? chinese : english
    }
}

/// The user-facing steps shown in the progress list.
enum DeploymentStep: Int, CaseIterable, Identifiable {
    case localKey, hostKey, privileges, publicKey, configuration, validation, reload, keyLogin

    var id: Int { rawValue }

    var title: LocalizedText {
        switch self {
        case .localKey: return .init("检查本地密钥", "Check local key")
        case .hostKey: return .init("确认主机指纹", "Confirm host key")
        case .privileges: return .init("检查 sudo 权限", "Check sudo access")
        case .publicKey: return .init("安装公钥", "Install public key")
        case .configuration: return .init("写入 SSH 策略", "Write SSH policy")
        case .validation: return .init("验证 sshd 配置", "Validate sshd")
        case .reload: return .init("重新加载 SSH", "Reload SSH")
        case .keyLogin: return .init("验证密钥登录", "Verify key login")
        }
    }

    init?(stage: DeploymentStage) {
        switch stage {
        case .validating, .securingPrivateKey: self = .localKey
        case .connecting, .awaitingHostKeyApproval: self = .hostKey
        case .checkingPrivileges: self = .privileges
        case .installingPublicKey: self = .publicKey
        case .writingSshdConfiguration: self = .configuration
        case .validatingSshdConfiguration: self = .validation
        case .reloadingSsh, .verifyingEffectiveConfiguration: self = .reload
        case .verifyingKeyLogin: self = .keyLogin
        case .rollingBack, .completed: return nil
        }
    }
}

enum StepState {
    case pending, active, done, failed
}

extension DeploymentError {
    /// A translated summary for the common failures, followed by the original detail.
    var localized: LocalizedText {
        let summary: LocalizedText?
        switch kind {
        case .authenticationRejected:
            summary = LocalizedText("服务器拒绝了密码登录：请检查账号和当前密码，并确认该账号允许密码登录。服务器未做任何修改。",
                            "Password authentication was rejected. No server changes were made.")
        case .connectionTimedOut:
            summary = LocalizedText("SSH 连接超时：请检查地址、端口、防火墙、VPN/局域网，以及 sshd 是否运行。服务器未做任何修改。",
                            "The SSH connection timed out. No server changes were made.")
        case .networkUnavailable:
            summary = LocalizedText("无法建立 SSH 连接：请检查地址、端口、防火墙、VPN/局域网，以及 sshd 是否运行。服务器未做任何修改。",
                            "The SSH connection could not be opened. No server changes were made.")
        case .hostKeyRejected:
            summary = LocalizedText("未批准服务器主机指纹，部署已停止。服务器未做任何修改。",
                            "The host key was not approved. No server changes were made.")
        case .hostKeyChanged:
            summary = LocalizedText("服务器主机密钥与已批准的指纹不一致，已中止。请立即通过独立渠道核实服务器。",
                            "The server host key no longer matches the approved fingerprint.")
        case .sudoNotAuthorized:
            summary = LocalizedText("密码登录成功，但该账号没有 sudo 权限（能用 su 切换 root 不等于有 sudo 权限）。请在 root 控制台运行 adduser 用户名 sudo，完全退出后重新登录再试。",
                            "The account is not authorized to use sudo.")
        case .sudoUnavailable:
            summary = LocalizedText("密码登录成功，但服务器未安装 sudo。请在 root 控制台运行：apt-get update && apt-get install -y sudo && adduser 用户名 sudo。",
                            "sudo is not installed on the server.")
        case .sudoPasswordRejected:
            summary = LocalizedText("sudo 拒绝了密码：sudo 需要的是当前账号的密码，而不是 root 密码。",
                            "sudo rejected the password.")
        case .validation, .key, .connectionFailed, .remote:
            summary = nil
        }

        let rollbackNote: LocalizedText?
        switch rollback {
        case .notNeeded: rollbackNote = nil
        case .succeeded: rollbackNote = LocalizedText("远端修改已回滚。", "Server changes were rolled back.")
        case .incomplete:
            rollbackNote = LocalizedText("远端回滚未确认！请立即通过现有会话或服务器控制台检查 SSH。",
                                 "Rollback was not confirmed! Check SSH now from an existing session or the server console.")
        }

        let chinese = [summary?.chinese, message, rollbackNote?.chinese].compactMap { $0 }.joined(separator: "\n")
        // The core message already states the rollback result; only add emphasis when it failed.
        let englishWarning: String?
        if case .incomplete = rollback { englishWarning = rollbackNote?.english } else { englishWarning = nil }
        let english = [message, englishWarning].compactMap { $0 }.joined(separator: "\n")
        return .init(chinese, english)
    }
}
