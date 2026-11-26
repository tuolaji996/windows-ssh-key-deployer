import Foundation

/// Everything the user enters before a deployment starts.
public struct DeploymentRequest: Sendable, CustomStringConvertible {
    public let host: String
    public let port: Int
    public let username: String
    public let password: String
    public let keyPath: String
    public let enableRootLogin: Bool
    public let allowPasswordLogin: Bool
    /// Root password, used only with `su` when the account cannot use sudo. Never logged.
    public let rootPassword: String?
    /// Move sshd to this port (verified before the old port is closed); nil keeps the current port.
    public let newSSHPort: Int?

    public init(
        host: String,
        port: Int,
        username: String,
        password: String,
        keyPath: String,
        enableRootLogin: Bool,
        allowPasswordLogin: Bool,
        rootPassword: String? = nil,
        newSSHPort: Int? = nil
    ) {
        self.host = Self.normalizeHost(host)
        self.port = port
        self.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        self.password = password
        self.keyPath = Self.expandPath(keyPath)
        self.enableRootLogin = enableRootLogin
        self.allowPasswordLogin = allowPasswordLogin
        self.rootPassword = (rootPassword?.isEmpty ?? true) ? nil : rootPassword
        self.newSSHPort = newSSHPort
    }

    /// The account whose key login is verified at the end of the deployment.
    public var targetUsername: String { enableRootLogin ? "root" : username }

    public var rootLoginPolicy: RootLoginPolicy {
        guard enableRootLogin else { return .disabled }
        return allowPasswordLogin ? .passwordAndKey : .keyOnly
    }

    // The password must never leak through string interpolation or logging.
    public var description: String {
        "\(username)@\(host):\(port), keyPath=\(keyPath), password=[redacted], rootPassword=\(rootPassword == nil ? "none" : "[redacted]"), newSSHPort=\(newSSHPort.map(String.init) ?? "unchanged")"
    }

    private static func normalizeHost(_ host: String) -> String {
        let value = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.count >= 2, value.hasPrefix("["), value.hasSuffix("]") {
            return String(value.dropFirst().dropLast())
        }
        return value
    }

    /// Trims the path and expands a leading `~`, which users commonly type on macOS.
    public static func expandPath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix("~") ? NSString(string: trimmed).expandingTildeInPath : trimmed
    }
}

public enum RootLoginPolicy: Sendable, Equatable {
    case disabled
    case passwordAndKey
    case keyOnly

    /// The value written to `PermitRootLogin`.
    var sshdValue: String {
        switch self {
        case .disabled: return "no"
        case .passwordAndKey: return "yes"
        case .keyOnly: return "prohibit-password"
        }
    }
}

public enum DeploymentStage: Int, Sendable, CaseIterable {
    case validating
    case securingPrivateKey
    case connecting
    case awaitingHostKeyApproval
    /// Detecting privileges, OS release, package manager, init system, firewall, SELinux.
    case inspectingServer
    case awaitingPlanApproval
    /// Installing missing packages and/or granting temporary sudo through `su`.
    case preparingPrivileges
    case checkingPrivileges
    case installingPublicKey
    case writingSshdConfiguration
    case validatingSshdConfiguration
    case reloadingSsh
    case verifyingEffectiveConfiguration
    /// Opening the new port (firewall, SELinux), verifying it, then closing the old one.
    case changingPort
    case verifyingKeyLogin
    case rollingBack
    case completed
}

public struct DeploymentProgress: Sendable {
    public let stage: DeploymentStage
    public let message: String
    public let percent: Int
}

public struct HostKeyInfo: Sendable, Equatable {
    public let host: String
    public let port: Int
    public let algorithm: String
    public let keyLength: Int
    public let sha256Fingerprint: String
    public let md5Fingerprint: String
}

public struct KeyPairInfo: Sendable, Equatable {
    public let privateKeyPath: String
    public let publicKeyPath: String
    public let publicKey: String
    public let sha256Fingerprint: String
}

// MARK: - Server inspection and plan

public enum LinuxFamily: String, Sendable, Equatable {
    case debian, rhel, suse, arch, alpine, unknown
}

public enum PackageManager: String, Sendable, Equatable {
    case apt, dnf, yum, zypper, pacman, apk
}

public enum InitSystem: String, Sendable, Equatable {
    case systemd, openrc, other
}

public enum Firewall: String, Sendable, Equatable {
    case ufw, firewalld
}

/// How root commands will be run for this deployment.
public enum PrivilegeMode: String, Sendable, Equatable {
    /// Logged in as UID 0.
    case root
    /// The account can use sudo with its own password.
    case sudo
    /// sudo is missing or not permitted; `su` with the root password bootstraps temporary sudo.
    case su
    /// No usable way to become root (no sudo rights and no root password given).
    case none
}

/// Everything learned about the server before any change is made.
public struct ServerInfo: Sendable, Equatable {
    /// `ID` from /etc/os-release, e.g. "debian", "ubuntu", "rocky".
    public let osID: String
    /// `PRETTY_NAME`, e.g. "Ubuntu 24.04.1 LTS".
    public let osName: String
    /// `VERSION_ID`, e.g. "24.04".
    public let osVersion: String
    public let family: LinuxFamily
    public let packageManager: PackageManager?
    public let initSystem: InitSystem
    public let privilege: PrivilegeMode
    public let sudoInstalled: Bool
    /// The main sshd_config loads /etc/ssh/sshd_config.d/*.conf (required).
    public let sshdIncludesDropIns: Bool
    public let selinuxEnforcing: Bool
    /// An active firewall that would block a new SSH port.
    public let firewall: Firewall?
    /// sshd is started by ssh.socket (Ubuntu 22.10+), so ports come from the socket unit.
    public let socketActivated: Bool
    /// Ports sshd currently listens on (from `sshd -T`).
    public let currentPorts: [Int]

    public init(
        osID: String, osName: String, osVersion: String, family: LinuxFamily,
        packageManager: PackageManager?, initSystem: InitSystem, privilege: PrivilegeMode,
        sudoInstalled: Bool, sshdIncludesDropIns: Bool, selinuxEnforcing: Bool,
        firewall: Firewall?, socketActivated: Bool, currentPorts: [Int]
    ) {
        self.osID = osID
        self.osName = osName
        self.osVersion = osVersion
        self.family = family
        self.packageManager = packageManager
        self.initSystem = initSystem
        self.privilege = privilege
        self.sudoInstalled = sudoInstalled
        self.sshdIncludesDropIns = sshdIncludesDropIns
        self.selinuxEnforcing = selinuxEnforcing
        self.firewall = firewall
        self.socketActivated = socketActivated
        self.currentPorts = currentPorts
    }
}

/// One change the deployment will make, shown to the user before anything happens.
public enum PlannedAction: Sendable, Equatable {
    /// Persistent: packages are not removed on rollback.
    case installPackages(manager: PackageManager, packages: [String])
    /// A sudoers drop-in for this account, created through `su` and always removed afterwards.
    case temporarySudoViaSu(account: String)
    case installPublicKey(account: String)
    case writeSshdPolicy(rootLogin: RootLoginPolicy, passwordLogin: Bool)
    case changePort(from: [Int], to: Int)
    case openFirewallPort(Firewall, port: Int)
    case labelSelinuxPort(port: Int)
}

public struct DeploymentPlan: Sendable, Equatable {
    public let server: ServerInfo
    public let actions: [PlannedAction]

    public init(server: ServerInfo, actions: [PlannedAction]) {
        self.server = server
        self.actions = actions
    }
}

public struct DeploymentResult: Sendable {
    public let verifiedUsername: String
    public let privateKeyPath: String
    public let publicKeyFingerprint: String
    public let approvedHostKey: HostKeyInfo
    public let managedConfigPath: String
    public let rootLoginPolicy: RootLoginPolicy
    public let passwordLoginAllowed: Bool
    public let warnings: [String]
    /// What the inspection found (nil only if the deployment never got that far).
    public let server: ServerInfo?
    /// The port key login was verified on; equals `newSSHPort` when the port was changed.
    public let sshPort: Int
}

public struct ValidationIssue: Sendable, Equatable {
    public enum Field: Sendable { case host, port, username, password, keyPath, rootLogin }

    public let field: Field
    public let message: String
}

/// What happened to server-side changes after a failed deployment.
public enum RollbackOutcome: Sendable, Equatable {
    /// Nothing on the server had been changed yet.
    case notNeeded
    case succeeded
    case incomplete(String)
}

public struct DeploymentError: Error, Sendable, LocalizedError {
    public enum Kind: Sendable, Equatable {
        case validation
        case key
        case hostKeyRejected
        case hostKeyChanged
        case authenticationRejected
        case connectionTimedOut
        case networkUnavailable
        case connectionFailed
        case sudoNotAuthorized
        case sudoUnavailable
        case sudoPasswordRejected
        /// sshd does not load /etc/ssh/sshd_config.d (e.g. CentOS/RHEL 7-8); nothing was changed.
        case unsupportedServer
        /// No sudo rights and no root password was given.
        case noPrivilege
        case rootPasswordRejected
        /// `su` is missing or not permitted for this account.
        case suUnavailable
        case planRejected
        case packageInstallFailed
        case portChangeFailed
        case remote
    }

    public let kind: Kind
    public let message: String
    public let rollback: RollbackOutcome
    public let issues: [ValidationIssue]

    public init(
        _ kind: Kind,
        _ message: String,
        rollback: RollbackOutcome = .notNeeded,
        issues: [ValidationIssue] = []
    ) {
        self.kind = kind
        self.message = message
        self.rollback = rollback
        self.issues = issues
    }

    public var errorDescription: String? { message }
}

public typealias ProgressHandler = @Sendable (DeploymentProgress) -> Void
public typealias HostKeyApproval = @Sendable (HostKeyInfo) async -> Bool
/// Shown after inspection and before any server change; returning false stops with `.planRejected`.
public typealias PlanApproval = @Sendable (DeploymentPlan) async -> Bool
