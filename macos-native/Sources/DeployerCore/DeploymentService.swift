import Foundation

/// Installs a public key on a Debian server, applies the requested SSH login policy,
/// verifies it with a fresh key-based login, and rolls everything back on failure.
public struct DeploymentService: Sendable {
    public static let managedConfigPath = RemoteScripts.managedConfigPath

    private let keyStore = KeyStore()

    public init() {}

    public func deploy(
        _ request: DeploymentRequest,
        approveHostKey: HostKeyApproval,
        progress: ProgressHandler? = nil
    ) async throws -> DeploymentResult {
        let report: (DeploymentStage, String, Int) -> Void = { stage, message, percent in
            progress?(DeploymentProgress(stage: stage, message: message, percent: percent))
        }

        report(.validating, "Validating deployment settings...", 2)
        try RequestValidator.ensureValid(request)
        try Task.checkCancellation()

        report(.securingPrivateKey, "Securing the private key...", 6)
        let privateKeyPath = (request.keyPath as NSString).standardizingPath
        let publicKey = try KeyStore.readPublicKey(path: privateKeyPath + ".pub")
        try KeyStore.protectPrivateKey(privateKeyPath)
        try await keyStore.ensureMatchingPair(privateKeyPath: privateKeyPath, publicKey: publicKey)

        report(.connecting, "Reading the server host key...", 10)
        let session = try SSHSession(
            host: request.host,
            port: request.port,
            username: request.username,
            password: request.password)

        let hostKey = try await session.scanHostKey()
        report(.awaitingHostKeyApproval, "Confirm the server host key (\(hostKey.sha256Fingerprint)).", 14)
        let approved = await approveHostKey(hostKey)
        try Task.checkCancellation()
        guard approved else {
            throw DeploymentError(.hostKeyRejected, "The server host key was not approved. No server changes were made.")
        }
        try session.trustScannedHostKey()

        report(.connecting, "Connecting with password authentication...", 16)
        try await session.connect()

        let run = Deployment(
            request: request,
            session: session,
            publicKey: publicKey,
            privateKeyPath: privateKeyPath,
            report: report)
        do {
            let warnings = try await run.execute()
            await Self.uncancellable { await session.close() }
            report(.completed, "SSH key deployment verified.", 100)
            return DeploymentResult(
                verifiedUsername: request.targetUsername,
                privateKeyPath: privateKeyPath,
                publicKeyFingerprint: publicKey.sha256Fingerprint,
                approvedHostKey: hostKey,
                managedConfigPath: Self.managedConfigPath,
                rootLoginPolicy: request.rootLoginPolicy,
                passwordLoginAllowed: request.allowPasswordLogin,
                warnings: warnings)
        } catch {
            // Recovery must finish even if the user cancelled, so it runs detached
            // from this task's cancellation.
            let rollback = await Self.uncancellable { await run.recover() }
            await Self.uncancellable { await session.close() }
            throw Self.finalError(error, rollback: rollback, redact: session.redact)
        }
    }

    static func uncancellable<T: Sendable>(_ work: @escaping @Sendable () async -> T) async -> T {
        await Task.detached(priority: .userInitiated, operation: work).value
    }

    private static func finalError(
        _ error: Error,
        rollback: RollbackOutcome,
        redact: (String) -> String
    ) -> Error {
        // A clean cancellation stays a cancellation; one whose rollback failed must
        // still surface that failure to the user.
        if error is CancellationError {
            guard case .incomplete = rollback else { return error }
        }

        let deploymentError = error as? DeploymentError
        if rollback == .notNeeded, let deploymentError {
            return deploymentError
        }

        let detail = redact(deploymentError?.message ?? error.localizedDescription)
        let recovery: String
        switch rollback {
        case .notNeeded: recovery = "No server-side change required rollback."
        case .succeeded: recovery = "Server changes were rolled back."
        case let .incomplete(reason): recovery = "Automatic rollback was incomplete: \(reason)"
        }
        return DeploymentError(
            deploymentError?.kind ?? .remote,
            "Deployment failed: \(detail) \(recovery)",
            rollback: rollback)
    }
}

/// The server-side portion of one deployment, with everything needed to undo it.
private final class Deployment: @unchecked Sendable {
    private static let recoveryCommandTimeout: TimeInterval = 45

    private let request: DeploymentRequest
    private let session: SSHSession
    private let publicKey: Ed25519PublicKey
    private let privateKeyPath: String
    private let report: (DeploymentStage, String, Int) -> Void

    // Rollback bookkeeping. A flag is raised *before* a command whose outcome could be
    // uncertain (for example when the network drops mid-command), so recovery always
    // assumes the worst.
    private var sessionIsRoot = false
    private let currentUserIsRoot: Bool
    private let configBackupPath = "/etc/ssh/sshd_config.d/.ssh-key-deployer-backup-\(Deployment.randomHex())"
    private let currentUserSnapshot = "/tmp/ssh-key-deployer-authorized-\(Deployment.randomHex())"
    private let rootSnapshot = "/tmp/ssh-key-deployer-authorized-\(Deployment.randomHex())"
    private var currentUserSnapshotMayExist = false
    private var currentUserKeysMayHaveChanged = false
    private var rootSnapshotMayExist = false
    private var rootKeysMayHaveChanged = false
    private var configBackupMayExist = false
    private var configOriginallyExisted = false
    private var configModified = false
    private var connection = ConnectionContext(clientHost: "", clientAddress: "", localAddress: "", localPort: 0)

    init(
        request: DeploymentRequest,
        session: SSHSession,
        publicKey: Ed25519PublicKey,
        privateKeyPath: String,
        report: @escaping (DeploymentStage, String, Int) -> Void
    ) {
        self.request = request
        self.session = session
        self.publicKey = publicKey
        self.privateKeyPath = privateKeyPath
        self.report = report
        currentUserIsRoot = request.username == "root"
    }

    // MARK: - Forward path

    /// Returns non-fatal warnings from cleanup after a verified deployment.
    func execute() async throws -> [String] {
        report(.checkingPrivileges, "Checking Debian SSH and sudo access...", 20)
        let uid = try await runChecked("checking the remote account", "id -u")
        sessionIsRoot = uid.stdout == "0"
        if currentUserIsRoot && !sessionIsRoot {
            throw DeploymentError(.remote, "The remote root account did not report UID 0.")
        }
        if !sessionIsRoot {
            try await checkSudoAccess()
        }
        try await runChecked("locating the OpenSSH server", "test -x \(RemoteScripts.sshdPath)", asRoot: true)
        connection = try await readConnectionContext()

        report(.installingPublicKey, "Installing the public key...", 32)
        currentUserSnapshotMayExist = true
        try await runChecked(
            "snapshotting authorized_keys before modification",
            RemoteScripts.snapshotAuthorizedKeys(backupPath: currentUserSnapshot, root: currentUserIsRoot),
            asRoot: currentUserIsRoot)
        currentUserKeysMayHaveChanged = true
        try await installKey(snapshot: currentUserSnapshot, root: currentUserIsRoot)

        if request.targetUsername == "root" && !currentUserIsRoot {
            rootSnapshotMayExist = true
            try await runChecked(
                "snapshotting root authorized_keys before modification",
                RemoteScripts.snapshotAuthorizedKeys(backupPath: rootSnapshot, root: true),
                asRoot: true)
            rootKeysMayHaveChanged = true
            try await installKey(snapshot: rootSnapshot, root: true)
        }

        report(.installingPublicKey, "Verifying key login as \(request.username) before changing sshd...", 39)
        try await verifyKeyLogin(as: request.username)

        report(.writingSshdConfiguration, "Writing the managed SSH configuration...", 45)
        try await writeManagedConfig()

        report(.validatingSshdConfiguration, "Validating sshd syntax and effective settings...", 58)
        try await runChecked("validating sshd syntax", "\(RemoteScripts.sshdPath) -t", asRoot: true)
        try await validateEffectiveSettings()

        report(.reloadingSsh, "Reloading the SSH service...", 70)
        try await runChecked("reloading the SSH service", RemoteScripts.reloadSsh, asRoot: true)

        report(.verifyingEffectiveConfiguration, "Verifying effective settings after reload...", 78)
        try await validateEffectiveSettings()

        report(.verifyingKeyLogin, "Verifying key login as \(request.targetUsername)...", 88)
        try await verifyKeyLogin(as: request.targetUsername)

        // Everything is verified. Cleanup is best effort and must not trigger rollback
        // after a snapshot has already been deleted.
        try Task.checkCancellation()
        return await DeploymentService.uncancellable { await self.commit() }
    }

    private func installKey(snapshot: String, root: Bool) async throws {
        try await runChecked(
            "installing the public key",
            RemoteScripts.installPublicKey(root: root),
            input: snapshot + "\n" + publicKey.normalizedText + "\n",
            asRoot: root)
    }

    private func verifyKeyLogin(as account: String) async throws {
        let identity = try await session.verifyKeyLogin(as: account, privateKeyPath: privateKeyPath)
        guard identity == account else {
            throw DeploymentError(.remote, "Key authentication connected as an unexpected account.")
        }
    }

    private func writeManagedConfig() async throws {
        configBackupMayExist = true
        let inspection = try await runChecked(
            "checking the managed SSH configuration",
            RemoteScripts.inspectManagedConfig(backupPath: configBackupPath),
            asRoot: true)
        switch inspection.stdout {
        case "BACKUP": configOriginallyExisted = true
        case "NEW":
            configOriginallyExisted = false
            configBackupMayExist = false
        default:
            throw DeploymentError(.remote, "The server returned an unexpected response while checking the SSH configuration.")
        }

        // From here the outcome may be uncertain if the network drops, so recovery
        // must assume the managed file could already have been replaced.
        configModified = true
        try await runChecked(
            "activating the managed SSH configuration",
            RemoteScripts.activateManagedConfig,
            input: RemoteScripts.managedConfig(
                rootLogin: request.rootLoginPolicy,
                allowPasswordLogin: request.allowPasswordLogin),
            asRoot: true)
    }

    private func commit() async -> [String] {
        var warnings: [String] = []
        if currentUserSnapshotMayExist {
            if await tryRemoveSnapshot(currentUserSnapshot, root: currentUserIsRoot) {
                currentUserSnapshotMayExist = false
                currentUserKeysMayHaveChanged = false
            } else {
                warnings.append("Deployment is verified, but the temporary authorized_keys snapshot \(currentUserSnapshot) could not be removed.")
            }
        }
        if rootSnapshotMayExist {
            if await tryRemoveSnapshot(rootSnapshot, root: true) {
                rootSnapshotMayExist = false
                rootKeysMayHaveChanged = false
            } else {
                warnings.append("Deployment is verified, but the temporary root authorized_keys snapshot \(rootSnapshot) could not be removed.")
            }
        }
        if configBackupMayExist {
            if (try? await run(RemoteScripts.removeFile(configBackupPath), asRoot: true).status) == 0 {
                configBackupMayExist = false
            } else {
                warnings.append("Deployment is verified, but the temporary backup \(configBackupPath) could not be removed.")
            }
        }
        return warnings
    }

    // MARK: - Recovery

    func recover() async -> RollbackOutcome {
        let needed = configModified || configBackupMayExist ||
            currentUserSnapshotMayExist || rootSnapshotMayExist
        guard needed else { return .notNeeded }

        report(.rollingBack, "Rolling back server changes...", 94)
        var errors: [String] = []

        var configRestored = !configModified
        if configModified {
            do {
                try await runChecked(
                    "restoring the SSH configuration",
                    RemoteScripts.restoreManagedConfig(
                        originalExisted: configOriginallyExisted,
                        backupPath: configBackupPath),
                    asRoot: true,
                    timeout: Self.recoveryCommandTimeout)
                configModified = false
                if configOriginallyExisted { configBackupMayExist = false }
                try await runChecked(
                    "validating the restored SSH configuration",
                    "\(RemoteScripts.sshdPath) -t",
                    asRoot: true,
                    timeout: Self.recoveryCommandTimeout)
                try await runChecked(
                    "reloading the SSH service",
                    RemoteScripts.reloadSsh,
                    asRoot: true,
                    timeout: Self.recoveryCommandTimeout)
                configRestored = true
            } catch {
                errors.append("SSH configuration recovery failed (\(describe(error))).")
            }
        }

        // authorized_keys is only touched once sshd is back to its previous state, in
        // reverse mutation order, so a key is never removed while it is the only way in.
        if configRestored {
            if rootKeysMayHaveChanged {
                if let error = await restoreKeys(snapshot: rootSnapshot, root: true) {
                    errors.append("The root authorized_keys snapshot could not be restored (\(error)).")
                } else {
                    rootKeysMayHaveChanged = false
                    rootSnapshotMayExist = false
                }
            }
            if currentUserKeysMayHaveChanged {
                if let error = await restoreKeys(snapshot: currentUserSnapshot, root: currentUserIsRoot) {
                    errors.append("The authorized_keys snapshot could not be restored (\(error)).")
                } else {
                    currentUserKeysMayHaveChanged = false
                    currentUserSnapshotMayExist = false
                }
            }
            if rootSnapshotMayExist && !rootKeysMayHaveChanged {
                if await tryRemoveSnapshot(rootSnapshot, root: true) {
                    rootSnapshotMayExist = false
                } else {
                    errors.append("The unused root authorized_keys snapshot could not be removed.")
                }
            }
            if currentUserSnapshotMayExist && !currentUserKeysMayHaveChanged {
                if await tryRemoveSnapshot(currentUserSnapshot, root: currentUserIsRoot) {
                    currentUserSnapshotMayExist = false
                } else {
                    errors.append("The unused authorized_keys snapshot could not be removed.")
                }
            }
        }

        if !configModified && configBackupMayExist {
            do {
                try await runChecked(
                    "removing the temporary configuration backup",
                    RemoteScripts.removeFile(configBackupPath),
                    asRoot: true,
                    timeout: Self.recoveryCommandTimeout)
                configBackupMayExist = false
            } catch {
                errors.append("Temporary recovery files could not be removed (\(describe(error))).")
            }
        }

        return errors.isEmpty ? .succeeded : .incomplete(errors.joined(separator: " "))
    }

    private func restoreKeys(snapshot: String, root: Bool) async -> String? {
        do {
            try await runChecked(
                "restoring the authorized_keys snapshot",
                RemoteScripts.restoreAuthorizedKeys(backupPath: snapshot, root: root),
                input: publicKey.normalizedText + "\n",
                asRoot: root,
                timeout: Self.recoveryCommandTimeout)
            return nil
        } catch {
            return describe(error)
        }
    }

    private func tryRemoveSnapshot(_ snapshot: String, root: Bool) async -> Bool {
        (try? await run(RemoteScripts.removeSnapshot(backupPath: snapshot), asRoot: root).status) == 0
    }

    // MARK: - Privileges and sshd checks

    private func checkSudoAccess() async throws {
        let result = try await run("true", asRoot: true)
        guard result.status != 0 else { return }

        let diagnostic = session.redact(result.diagnostic)
        let text = diagnostic.lowercased()
        let username = request.username
        if ["not in the sudoers file", "is not allowed to run sudo", "may not run sudo", "is not in the sudoers"]
            .contains(where: { text.contains($0) }) {
            throw DeploymentError(
                .sudoNotAuthorized,
                "SSH password login succeeded, but account '\(username)' is not authorized to use sudo. " +
                    "Using 'su' with the root password is different from having sudo permission. " +
                    "From a root console, run: adduser \(username) sudo. Then fully sign out of '\(username)', sign in again, and retry.")
        }
        if ["sudo: command not found", "sudo: not found", "sudo: no such file or directory"]
            .contains(where: { text.contains($0) }) {
            throw DeploymentError(
                .sudoUnavailable,
                "SSH password login succeeded, but sudo is not installed on the server. " +
                    "From a root console, run: apt-get update && apt-get install -y sudo && adduser \(username) sudo. " +
                    "Then fully sign out of '\(username)', sign in again, and retry.")
        }
        if ["incorrect password attempt", "sorry, try again", "authentication failure", "a password is required", "no password was provided"]
            .contains(where: { text.contains($0) }) {
            throw DeploymentError(
                .sudoPasswordRejected,
                "SSH password login succeeded, but sudo rejected the password for account '\(username)'. " +
                    "sudo normally requires the current account password, not the root password. " +
                    "Verify 'sudo -k true' in a new login session and retry.")
        }
        throw remoteFailure("checking sudo access", result)
    }

    private func readConnectionContext() async throws -> ConnectionContext {
        let result = try await runChecked(
            "reading the SSH connection context",
            "printf '%s\\n' \"$SSH_CONNECTION\"")
        let fields = result.stdout.split(whereSeparator: \.isWhitespace).map(String.init)
        guard fields.count == 4,
              HostName.ipAddressBytes(fields[0]) != nil,
              Int(fields[1]) != nil,
              HostName.ipAddressBytes(fields[2]) != nil,
              let localPort = Int(fields[3]), (1...65_535).contains(localPort) else {
            throw DeploymentError(
                .remote,
                "The server returned an invalid SSH connection context; effective Match settings cannot be verified safely.")
        }
        return ConnectionContext(
            clientHost: fields[0],
            clientAddress: fields[0],
            localAddress: fields[2],
            localPort: localPort)
    }

    private func validateEffectiveSettings() async throws {
        let global = try await runChecked(
            "reading global effective sshd settings",
            "\(RemoteScripts.sshdPath) -T",
            asRoot: true)
        let useDNS = SshdSettings.parse(global.stdout)["usedns"]?.lowercased()
        guard useDNS == "yes" || useDNS == "no" else {
            throw DeploymentError(.remote, "Effective sshd setting usedns is '\(useDNS ?? "missing")', expected 'yes' or 'no'.")
        }
        if useDNS == "yes" {
            connection.clientHost = await resolveClientHost(connection.clientAddress)
        } else {
            connection.clientHost = connection.clientAddress
        }

        // Always check root too: a later `Match User root` block must not be able to
        // silently override the requested root-login policy.
        for account in Array(Set([request.username, "root"])).sorted() {
            let result = try await runChecked(
                "reading effective sshd settings for \(account)",
                "\(RemoteScripts.sshdPath) -T -C \(RemoteScripts.shellQuote(connection.matchSpec(user: account)))",
                asRoot: true)
            try SshdSettings.verify(result.stdout, request: request, account: account)
        }
    }

    /// Mirrors sshd's UseDNS behaviour: a reverse lookup that is forward-confirmed.
    private func resolveClientHost(_ address: String) async -> String {
        guard let clientBytes = HostName.ipAddressBytes(address),
              let reverse = try? await run("getent hosts \(RemoteScripts.shellQuote(address))"),
              reverse.status == 0 else { return address }

        var seen = Set<String>()
        let candidates = reverse.stdout.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 2 else { return nil }
            let name = String(fields[1])
            guard name.count <= 253, !name.contains(","), HostName.isValid(name),
                  seen.insert(name.lowercased()).inserted else { return nil }
            return name
        }

        for candidate in candidates {
            guard let forward = try? await run("getent ahosts \(RemoteScripts.shellQuote(candidate))"),
                  forward.status == 0 else { continue }
            let confirmed = forward.stdout.split(whereSeparator: \.isNewline).contains { line in
                guard let first = line.split(whereSeparator: \.isWhitespace).first else { return false }
                return HostName.ipAddressBytes(String(first)) == clientBytes
            }
            if confirmed { return candidate }
        }
        return address
    }

    // MARK: - Remote execution

    /// Runs `command`, elevating with sudo when needed. The password is only ever sent
    /// on standard input, never on a command line.
    @discardableResult
    private func run(
        _ command: String,
        input: String? = nil,
        asRoot: Bool = false,
        timeout: TimeInterval = SSHSession.commandTimeout
    ) async throws -> RemoteResult {
        guard asRoot && !sessionIsRoot else {
            return try await session.run(command, input: input, timeout: timeout)
        }
        let passwordLine = request.password + "\n"
        if let input {
            return try await session.run(RemoteScripts.sudoWithPayload(command), input: passwordLine + input, timeout: timeout)
        }
        return try await session.run(RemoteScripts.sudo(command), input: passwordLine, timeout: timeout)
    }

    @discardableResult
    private func runChecked(
        _ operation: String,
        _ command: String,
        input: String? = nil,
        asRoot: Bool = false,
        timeout: TimeInterval = SSHSession.commandTimeout
    ) async throws -> RemoteResult {
        let result: RemoteResult
        do {
            result = try await run(command, input: input, asRoot: asRoot, timeout: timeout)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw DeploymentError(.remote, "Remote operation failed while \(operation). \(describe(error))")
        }
        guard result.status == 0 else { throw remoteFailure(operation, result) }
        return result
    }

    private func remoteFailure(_ operation: String, _ result: RemoteResult) -> DeploymentError {
        let diagnostic = session.redact(result.diagnostic)
        let base = "Remote operation failed while \(operation) (exit \(result.status))"
        return DeploymentError(.remote, diagnostic.isEmpty ? base + "." : "\(base): \(diagnostic)")
    }

    private func describe(_ error: Error) -> String {
        session.redact((error as? DeploymentError)?.message ?? error.localizedDescription)
    }

    private static func randomHex() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }
}

private struct ConnectionContext {
    var clientHost: String
    let clientAddress: String
    let localAddress: String
    let localPort: Int

    func matchSpec(user: String) -> String {
        "user=\(user),host=\(clientHost),addr=\(clientAddress),laddr=\(localAddress),lport=\(localPort)"
    }
}

/// Parses `sshd -T` output and checks it against the requested policy.
enum SshdSettings {
    static func parse(_ output: String) -> [String: String] {
        var settings: [String: String] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.trimmingCharacters(in: .whitespaces)
                .split(maxSplits: 1, whereSeparator: \.isWhitespace)
            guard parts.count == 2 else { continue }
            let key = parts[0].lowercased()
            if settings[key] == nil {
                settings[key] = parts[1].trimmingCharacters(in: .whitespaces)
            }
        }
        return settings
    }

    static func verify(_ output: String, request: DeploymentRequest, account: String) throws {
        let settings = parse(output)
        func require(_ name: String, _ expected: String, alsoAccept: String? = nil) throws {
            let actual = settings[name]?.lowercased()
            guard actual == expected || (alsoAccept != nil && actual == alsoAccept) else {
                throw DeploymentError(
                    .remote,
                    "Effective sshd setting \(name) is '\(settings[name] ?? "missing")', expected '\(expected)'.")
            }
        }

        try require("pubkeyauthentication", "yes")
        let isRoot = account == "root"
        if !isRoot || request.enableRootLogin {
            try require("passwordauthentication", request.allowPasswordLogin ? "yes" : "no")
            try require("kbdinteractiveauthentication", "no")
        }
        if isRoot {
            let expected = request.rootLoginPolicy.sshdValue
            try require(
                "permitrootlogin",
                expected,
                alsoAccept: expected == "prohibit-password" ? "without-password" : nil)
        }
    }
}
