import DeployerCore
import Foundation

/// What the success card shows. Built from `DeploymentResult` (or sample data for snapshots).
struct ResultSummary: Equatable {
    var host: String
    var username: String
    var keyPath: String
    var sshPort: Int
    var previousPort: Int
    var osName: String?
    var rootLogin: RootLoginChoice
    var passwordLogin: Bool
    var warnings: [String]

    init(host: String, username: String, keyPath: String, sshPort: Int, previousPort: Int,
         osName: String?, rootLogin: RootLoginChoice, passwordLogin: Bool, warnings: [String] = []) {
        self.host = host
        self.username = username
        self.keyPath = keyPath
        self.sshPort = sshPort
        self.previousPort = previousPort
        self.osName = osName
        self.rootLogin = rootLogin
        self.passwordLogin = passwordLogin
        self.warnings = warnings
    }

    init(result: DeploymentResult, request: DeploymentRequest) {
        let choice: RootLoginChoice
        switch result.rootLoginPolicy {
        case .disabled: choice = .disabled
        case .keyOnly: choice = .keyOnly
        case .passwordAndKey: choice = .keyAndPassword
        }
        self.init(
            host: request.host,
            username: result.verifiedUsername,
            keyPath: result.privateKeyPath,
            sshPort: result.sshPort,
            previousPort: request.port,
            osName: result.server?.displayName,
            rootLogin: choice,
            passwordLogin: result.passwordLoginAllowed,
            warnings: result.warnings)
    }

    var sshCommand: String {
        SSHSnippets.command(keyPath: keyPath, port: sshPort, username: username, host: host)
    }

    var sshConfig: String {
        SSHSnippets.configBlock(keyPath: keyPath, port: sshPort, username: username, host: host)
    }
}

/// What the failure card shows.
struct FailureSummary: Equatable {
    enum Rollback: Equatable { case notNeeded, rolledBack, incomplete }

    var title: LocalizedText
    var hint: LocalizedText?
    var detail: String
    var rollback: Rollback
    var isCancellation: Bool

    init(title: LocalizedText, hint: LocalizedText?, detail: String, rollback: Rollback, isCancellation: Bool = false) {
        self.title = title
        self.hint = hint
        self.detail = detail
        self.rollback = rollback
        self.isCancellation = isCancellation
    }

    init(_ error: Error) {
        if let error = error as? DeploymentError {
            let rollback: Rollback
            switch error.rollback {
            case .notNeeded: rollback = .notNeeded
            case .succeeded: rollback = .rolledBack
            case .incomplete: rollback = .incomplete
            }
            self.init(title: error.localizedTitle, hint: error.localizedHint, detail: error.message, rollback: rollback,
                      isCancellation: error.kind == .planRejected || error.kind == .hostKeyRejected)
        } else if error is CancellationError {
            self.init(title: .init("部署已取消", "Deployment cancelled"),
                      hint: .init("已开始的远端修改已回滚。", "Any server changes that had started were rolled back."),
                      detail: "", rollback: .rolledBack, isCancellation: true)
        } else {
            self.init(title: .init("部署失败", "Deployment failed"), hint: nil,
                      detail: error.localizedDescription, rollback: .notNeeded)
        }
    }
}

/// Copyable `ssh` command line and `~/.ssh/config` block.
enum SSHSnippets {
    private static let shellSafe = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_")

    static func shellQuote(_ value: String) -> String {
        if !value.isEmpty, value.unicodeScalars.allSatisfy({ shellSafe.contains($0) }) {
            return value
        }
        return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// `~/…` when the path is inside the home folder.
    static func abbreviated(_ path: String) -> String {
        let home = NSHomeDirectory()
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }

    static func command(keyPath: String, port: Int, username: String, host: String) -> String {
        // `~/` only expands when unquoted, so fall back to the quoted absolute path.
        let short = abbreviated(keyPath)
        let keyArgument: String
        if short.hasPrefix("~/"), shellQuote(String(short.dropFirst(2))) == String(short.dropFirst(2)) {
            keyArgument = short
        } else {
            keyArgument = shellQuote(keyPath)
        }
        var parts = ["ssh", "-i", keyArgument]
        if port != 22 { parts += ["-p", String(port)] }
        parts.append(shellQuote("\(username)@\(host)"))
        return parts.joined(separator: " ")
    }

    static func configBlock(keyPath: String, port: Int, username: String, host: String) -> String {
        let alias = String(host.map { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" ? $0 : "-" })
        let identity = abbreviated(keyPath)
        let quotedIdentity = identity.contains(" ") ? "\"\(identity)\"" : identity
        return """
        Host \(alias)
            HostName \(host)
            Port \(port)
            User \(username)
            IdentityFile \(quotedIdentity)
            IdentitiesOnly yes
        """
    }
}

/// A server the user deployed to before. Never contains a password.
struct RecentServer: Codable, Identifiable, Equatable {
    var host: String
    var port: Int
    var username: String
    var keyPath: String
    var lastUsed: Date

    var id: String { "\(username)@\(host)" }

    var title: String { port == 22 ? "\(username)@\(host)" : "\(username)@\(host):\(port)" }
}

/// Keeps up to eight recent servers as JSON in UserDefaults (or only in memory).
final class RecentServersStore {
    static let limit = 8
    private static let key = "recentServers.v1"
    private let defaults: UserDefaults?

    /// Pass nil to keep the list in memory only (used by the snapshot renderer).
    init(defaults: UserDefaults?) {
        self.defaults = defaults
    }

    func load() -> [RecentServer] {
        guard let data = defaults?.data(forKey: Self.key),
              let servers = try? JSONDecoder().decode([RecentServer].self, from: data) else { return [] }
        return Array(servers.sorted { $0.lastUsed > $1.lastUsed }.prefix(Self.limit))
    }

    func save(_ servers: [RecentServer]) {
        guard let defaults else { return }
        if let data = try? JSONEncoder().encode(Array(servers.prefix(Self.limit))) {
            defaults.set(data, forKey: Self.key)
        }
    }

    /// Inserts or refreshes `server` at the top of `servers`.
    static func remembering(_ server: RecentServer, in servers: [RecentServer]) -> [RecentServer] {
        var list = servers.filter { $0.id != server.id }
        list.insert(server, at: 0)
        return Array(list.prefix(limit))
    }
}
