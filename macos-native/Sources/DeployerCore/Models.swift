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

    public init(
        host: String,
        port: Int,
        username: String,
        password: String,
        keyPath: String,
        enableRootLogin: Bool,
        allowPasswordLogin: Bool
    ) {
        self.host = Self.normalizeHost(host)
        self.port = port
        self.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        self.password = password
        self.keyPath = Self.expandPath(keyPath)
        self.enableRootLogin = enableRootLogin
        self.allowPasswordLogin = allowPasswordLogin
    }

    /// The account whose key login is verified at the end of the deployment.
    public var targetUsername: String { enableRootLogin ? "root" : username }

    public var rootLoginPolicy: RootLoginPolicy {
        guard enableRootLogin else { return .disabled }
        return allowPasswordLogin ? .passwordAndKey : .keyOnly
    }

    // The password must never leak through string interpolation or logging.
    public var description: String {
        "\(username)@\(host):\(port), keyPath=\(keyPath), password=[redacted]"
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

public enum RootLoginPolicy: Sendable {
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
    case checkingPrivileges
    case installingPublicKey
    case writingSshdConfiguration
    case validatingSshdConfiguration
    case reloadingSsh
    case verifyingEffectiveConfiguration
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

public struct DeploymentResult: Sendable {
    public let verifiedUsername: String
    public let privateKeyPath: String
    public let publicKeyFingerprint: String
    public let approvedHostKey: HostKeyInfo
    public let managedConfigPath: String
    public let rootLoginPolicy: RootLoginPolicy
    public let passwordLoginAllowed: Bool
    public let warnings: [String]
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
