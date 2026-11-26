import Foundation

/// Installs a public key on a Linux server (Debian/Ubuntu, RHEL family, openSUSE, Arch,
/// Alpine), applies the requested SSH login policy and optionally a new SSH port,
/// verifies everything with fresh key-based logins, and rolls back on failure.
public struct DeploymentService: Sendable {
    public static let managedConfigPath = RemoteScripts.managedConfigPath

    private let keyStore = KeyStore()

    public init() {}

    public func deploy(
        _ request: DeploymentRequest,
        approveHostKey: HostKeyApproval,
        approvePlan: PlanApproval = { _ in true },
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
            password: request.password,
            rootPassword: request.rootPassword)

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
            let outcome = try await run.execute(approvePlan: approvePlan)
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
                warnings: outcome.warnings,
                server: outcome.server,
                sshPort: outcome.sshPort)
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
            return DeploymentError(
                deploymentError.kind,
                redact(deploymentError.message),
                rollback: deploymentError.rollback,
                issues: deploymentError.issues)
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

struct DeploymentOutcome: Sendable {
    let warnings: [String]
    let server: ServerInfo?
    let sshPort: Int
}

/// The server-side portion of one deployment, with everything needed to undo it.
private final class Deployment: @unchecked Sendable {
    private static let recoveryCommandTimeout: TimeInterval = 45
    private static let packageInstallTimeout: TimeInterval = 300
    private static let selinuxTimeout: TimeInterval = 180

    /// How root commands are executed right now.
    private enum RootPath {
        case direct
        case sudo
        case su
    }

    private let request: DeploymentRequest
    private let session: SSHSession
    private let publicKey: Ed25519PublicKey
    private let privateKeyPath: String
    private let report: (DeploymentStage, String, Int) -> Void

    private var rootPath: RootPath = .sudo
    private var privilege: PrivilegeMode = .none
    private var server: ServerInfo?
    private var rootProbe = ServerInspection.RootProbe()
    private var warnings: [String] = []
    private var finalPort: Int

    // Rollback bookkeeping. A flag is raised *before* a command whose outcome could be
    // uncertain (for example when the network drops mid-command), so recovery always
    // assumes the worst.
    private let currentUserIsRoot: Bool
    private let configBackupPath = "/etc/ssh/sshd_config.d/.ssh-key-deployer-backup-\(Deployment.randomHex())"
    private let currentUserSnapshot = "/tmp/ssh-key-deployer-authorized-\(Deployment.randomHex())"
    private let rootSnapshot = "/tmp/ssh-key-deployer-authorized-\(Deployment.randomHex())"
    private let temporarySudoersPath = RemoteScripts.temporarySudoersPrefix + Deployment.randomHex()
    private var currentUserSnapshotMayExist = false
    private var currentUserKeysMayHaveChanged = false
    private var rootSnapshotMayExist = false
    private var rootKeysMayHaveChanged = false
    private var configBackupMayExist = false
    private var configOriginallyExisted = false
    private var configModified = false
    /// The managed config may hold `Port` lines for the new port, so a restore must
    /// also rebind sockets.
    private var portConfigChanged = false
    private var selinuxPortMayBeAdded = false
    private var ufwRuleMayBeAdded = false
    private var firewalldRuntimeMayBeAdded = false
    private var firewalldPermanentMayBeAdded = false
    private var temporarySudoersMayExist = false
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
        finalPort = request.port
    }

    // MARK: - Forward path

    /// Returns the verified outcome, with non-fatal warnings.
    func execute(approvePlan: PlanApproval) async throws -> DeploymentOutcome {
        // 1. Inspect (read-only) and decide how to become root.
        report(.inspectingServer, "Inspecting the server and account privileges...", 18)
        let probe = try await inspectUnprivileged()
        if currentUserIsRoot && probe.uid != 0 {
            throw DeploymentError(.remote, "The remote root account did not report UID 0.")
        }
        privilege = try await decidePrivilege(probe)
        switch privilege {
        case .root: rootPath = .direct
        case .sudo: rootPath = .sudo
        case .su: rootPath = .su
        case .none: throw DeploymentError(.noPrivilege, "No way to run commands as root was found.")
        }

        report(.inspectingServer, "Inspecting the SSH service, firewall and SELinux...", 20)
        let serverInfo = try await inspectAsRoot(probe)
        server = serverInfo
        let portTarget = ServerInspection.portToChange(current: serverInfo.currentPorts, requested: request.newSSHPort)
        let plan = try ServerInspection.buildPlan(
            server: serverInfo,
            request: request,
            semanageInstalled: probe.tools.contains("semanage"))

        // 2. Nothing changes on the server until the user approves the plan.
        report(.awaitingPlanApproval, "Review the planned server changes.", 22)
        let approved = await approvePlan(plan)
        try Task.checkCancellation()
        guard approved else {
            throw DeploymentError(.planRejected, "The deployment plan was not approved. No server changes were made.")
        }

        // 3. Packages and temporary sudo.
        try await preparePrivileges(plan)

        report(.checkingPrivileges, "Checking sudo access and the SSH connection...", 30)
        if privilege == .su {
            let check = try await run("true", asRoot: true)
            guard check.status == 0 else {
                throw DeploymentError(
                    .sudoNotAuthorized,
                    "The temporary sudo rule was created, but sudo still refused account '\(request.username)': " +
                        session.redact(check.diagnostic))
            }
        }
        connection = try await readConnectionContext()

        // 4. Key and sshd policy.
        report(.installingPublicKey, "Installing the public key...", 34)
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

        report(.installingPublicKey, "Verifying key login as \(request.username) before changing sshd...", 40)
        try await verifyKeyLogin(as: request.username)

        report(.writingSshdConfiguration, "Writing the managed SSH configuration...", 46)
        try await writeManagedConfig()

        report(.validatingSshdConfiguration, "Validating sshd syntax and effective settings...", 54)
        try await runChecked("validating sshd syntax", "\(RemoteScripts.sshdPath) -t", asRoot: true)
        try await validateEffectiveSettings()

        report(.reloadingSsh, "Reloading the SSH service...", 60)
        try await runChecked("reloading the SSH service", RemoteScripts.reloadSshd(), asRoot: true)

        report(.verifyingEffectiveConfiguration, "Verifying effective settings after reload...", 66)
        try await validateEffectiveSettings()

        // 5. Port change: open and verify the new port before closing the old one.
        if let portTarget {
            try await changePort(to: portTarget, server: serverInfo)
        }

        report(.verifyingKeyLogin, "Verifying key login as \(request.targetUsername) on port \(finalPort)...", 90)
        try await verifyKeyLogin(as: request.targetUsername, port: finalPort)

        // Everything is verified. Cleanup is best effort and must not trigger rollback
        // after a snapshot has already been deleted.
        try Task.checkCancellation()
        let cleanupWarnings = await DeploymentService.uncancellable { await self.commit() }
        return DeploymentOutcome(warnings: warnings + cleanupWarnings, server: serverInfo, sshPort: finalPort)
    }

    private func installKey(snapshot: String, root: Bool) async throws {
        try await runChecked(
            "installing the public key",
            RemoteScripts.installPublicKey(root: root),
            input: snapshot + "\n" + publicKey.normalizedText + "\n",
            asRoot: root)
    }

    /// sshd re-executes asynchronously after a reload, so a fresh listener can refuse
    /// connections for a moment; transient failures are retried with a short backoff.
    private func verifyKeyLogin(as account: String, port: Int? = nil) async throws {
        var identity = ""
        let delays: [UInt64] = [500, 1_000, 1_500, 2_000, 3_000]
        for attempt in 0...delays.count {
            do {
                identity = try await session.verifyKeyLogin(as: account, privateKeyPath: privateKeyPath, port: port)
                break
            } catch let error as DeploymentError where error.kind != .hostKeyChanged && attempt < delays.count {
                try await Task.sleep(nanoseconds: delays[attempt] * 1_000_000)
            }
        }
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
        // Ports set by an earlier deployment stay as they are unless a change was requested.
        try await activateManagedConfig(ports: rootProbe.managedPorts)
    }

    private func activateManagedConfig(ports: [Int]) async throws {
        try await runChecked(
            "activating the managed SSH configuration",
            RemoteScripts.activateManagedConfig,
            input: RemoteScripts.managedConfig(
                rootLogin: request.rootLoginPolicy,
                allowPasswordLogin: request.allowPasswordLogin,
                ports: ports),
            asRoot: true)
    }

    // MARK: - Inspection and privileges

    private func inspectUnprivileged() async throws -> ServerInspection.Probe {
        let result = try await runChecked("inspecting the server", RemoteScripts.inspectServer)
        let probe = ServerInspection.parseProbe(result.stdout)
        guard probe.uid != nil else {
            throw DeploymentError(.remote, "The server did not report the account's user ID.")
        }
        return probe
    }

    private func decidePrivilege(_ probe: ServerInspection.Probe) async throws -> PrivilegeMode {
        var sudo: ServerInspection.SudoOutcome?
        var diagnostic = ""
        if probe.uid != 0 {
            if probe.tools.contains("sudo") {
                let result = try await session.run(RemoteScripts.sudo("true"), input: request.password + "\n")
                diagnostic = session.redact(result.diagnostic)
                sudo = ServerInspection.classifySudo(status: result.status, diagnostic: diagnostic)
            } else {
                sudo = .unavailable
            }
        }
        let decision = ServerInspection.decidePrivilege(
            uid: probe.uid ?? -1,
            sudo: sudo,
            rootPasswordGiven: request.rootPassword != nil,
            suInstalled: probe.tools.contains("su"))
        switch decision {
        case let .use(mode):
            return mode
        case let .fail(kind):
            throw ServerInspection.privilegeError(
                kind,
                family: probe.family,
                osName: probe.osName,
                username: request.username,
                sudoInstalled: probe.tools.contains("sudo"),
                diagnostic: diagnostic)
        }
    }

    private func inspectAsRoot(_ probe: ServerInspection.Probe) async throws -> ServerInfo {
        let result = try await runChecked("inspecting the SSH server as root", RemoteScripts.inspectServerAsRoot, asRoot: true)
        rootProbe = ServerInspection.parseRootProbe(result.stdout)

        guard rootProbe.sshdPresent else {
            throw DeploymentError(
                .unsupportedServer,
                "The OpenSSH server was not found at \(RemoteScripts.sshdPath). Nothing was changed.")
        }
        guard !rootProbe.ports.isEmpty else {
            let detail = rootProbe.sshdTestErrors.joined(separator: " ")
            throw DeploymentError(
                .unsupportedServer,
                "The effective sshd configuration could not be read ('sshd -T' failed\(detail.isEmpty ? "" : ": \(detail)")). Nothing was changed.")
        }
        guard ServerInspection.includesManagedDropIn(rootProbe.includes) else {
            throw DeploymentError(
                .unsupportedServer,
                ServerInspection.missingIncludeMessage(mainConfig: rootProbe.mainConfig))
        }

        return ServerInfo(
            osID: probe.osID,
            osName: probe.osName,
            osVersion: probe.osVersion,
            family: probe.family,
            packageManager: probe.packageManager,
            initSystem: probe.initSystem,
            privilege: privilege,
            sudoInstalled: probe.tools.contains("sudo"),
            sshdIncludesDropIns: true,
            selinuxEnforcing: rootProbe.selinuxEnforcing,
            firewall: rootProbe.firewall,
            socketActivated: rootProbe.socketActivated,
            currentPorts: rootProbe.ports)
    }

    private func preparePrivileges(_ plan: DeploymentPlan) async throws {
        var installs: [(PackageManager, [String])] = []
        for action in plan.actions {
            if case let .installPackages(manager, packages) = action { installs.append((manager, packages)) }
        }
        guard !installs.isEmpty || privilege == .su else { return }

        for (manager, packages) in installs {
            report(.preparingPrivileges, "Installing \(packages.joined(separator: ", ")) with \(manager.rawValue)...", 24)
            let result: RemoteResult
            do {
                result = try await run(
                    RemoteScripts.installPackages(manager, packages),
                    asRoot: true,
                    timeout: Self.packageInstallTimeout)
            } catch let error as DeploymentError where error.kind == .remote {
                throw DeploymentError(.packageInstallFailed, "Installing \(packages.joined(separator: ", ")) failed. \(error.message)")
            }
            guard result.status == 0 else {
                let tail = String(session.redact(result.diagnostic).suffix(1_500))
                throw DeploymentError(
                    .packageInstallFailed,
                    "Installing \(packages.joined(separator: ", ")) with \(manager.rawValue) failed (exit \(result.status)): \(tail)")
            }
        }

        if privilege == .su {
            report(.preparingPrivileges, "Granting \(request.username) temporary sudo rights through su...", 27)
            temporarySudoersMayExist = true
            let result = try await run(
                RemoteScripts.createTemporarySudoers(path: temporarySudoersPath, username: request.username),
                asRoot: true)
            guard result.status == 0, result.stdout.contains("SUDOERS=ok") else {
                let kind: DeploymentError.Kind = (90...92).contains(result.status) ? .unsupportedServer : .remote
                let diagnostic = session.redact(result.diagnostic)
                throw DeploymentError(
                    kind,
                    "Temporary sudo rights could not be granted through su (exit \(result.status))" +
                        (diagnostic.isEmpty ? "." : ": \(diagnostic)"))
            }
            // Everything else runs through sudo with the account password, like a sudo account.
            rootPath = .sudo
        }
    }

    // MARK: - Port change

    private func changePort(to newPort: Int, server: ServerInfo) async throws {
        do {
            try await performPortChange(to: newPort, server: server)
        } catch let error as DeploymentError where error.kind == .remote {
            throw DeploymentError(.portChangeFailed, "Changing the SSH port to \(newPort) failed. \(error.message)")
        }
    }

    private func performPortChange(to newPort: Int, server: ServerInfo) async throws {
        report(.changingPort, "Preparing port \(newPort) (SELinux and firewall)...", 70)
        if server.selinuxEnforcing {
            let listing = try await runChecked(
                "reading SELinux port labels",
                RemoteScripts.selinuxPortTypes(newPort),
                asRoot: true,
                timeout: Self.selinuxTimeout)
            let types = ServerInspection.values("TYPE", in: listing.stdout)
            if !types.contains("ssh_port_t") {
                if let other = types.first {
                    throw DeploymentError(
                        .portChangeFailed,
                        "SELinux already assigns port \(newPort) to \(other) (another service). Choose a different port.")
                }
                selinuxPortMayBeAdded = true
                try await runChecked(
                    "labeling port \(newPort) for SSH in SELinux",
                    RemoteScripts.selinuxAddSshPort(newPort),
                    asRoot: true,
                    timeout: Self.selinuxTimeout)
            }
        }

        switch server.firewall {
        case .ufw?:
            ufwRuleMayBeAdded = true
            let result = try await runChecked("opening port \(newPort) in ufw", RemoteScripts.ufwAllow(newPort), asRoot: true)
            if !ServerInspection.ufwAddedRule(result.stdout) { ufwRuleMayBeAdded = false }
        case .firewalld?:
            let query = try await runChecked("checking firewalld", RemoteScripts.firewalldQuery(newPort), asRoot: true)
            if ServerInspection.values("RUNTIME", in: query.stdout).first != "yes" {
                firewalldRuntimeMayBeAdded = true
                try await runChecked(
                    "opening port \(newPort) in firewalld",
                    RemoteScripts.firewalld(add: true, permanent: false, newPort),
                    asRoot: true)
            }
            if ServerInspection.values("PERMANENT", in: query.stdout).first != "yes" {
                firewalldPermanentMayBeAdded = true
                try await runChecked(
                    "opening port \(newPort) permanently in firewalld",
                    RemoteScripts.firewalld(add: true, permanent: true, newPort),
                    asRoot: true)
            }
        case nil:
            break
        }

        // Phase 1: listen on the old and the new port, and prove the new one works.
        report(.changingPort, "Opening port \(newPort) alongside the current port...", 74)
        portConfigChanged = true
        try await activateManagedConfig(ports: ServerInspection.transitionPorts(
            current: server.currentPorts,
            mainPorts: rootProbe.mainPorts,
            newPort: newPort))
        try await runChecked("validating sshd syntax", "\(RemoteScripts.sshdPath) -t", asRoot: true)
        try await runChecked(
            "reloading the SSH service",
            RemoteScripts.reloadSshd(restartSocket: server.socketActivated),
            asRoot: true)
        report(.changingPort, "Verifying key login on port \(newPort)...", 77)
        try await verifyKeyLogin(as: request.username, port: newPort)

        // Phase 2: only the new port. The master connection on the old port survives.
        report(.changingPort, "Closing the previous port...", 80)
        try await activateManagedConfig(ports: [newPort])
        try await runChecked("validating sshd syntax", "\(RemoteScripts.sshdPath) -t", asRoot: true)
        try await runChecked(
            "reloading the SSH service",
            RemoteScripts.reloadSshd(restartSocket: server.socketActivated),
            asRoot: true)
        let effective = try await runChecked("reading the effective sshd ports", "\(RemoteScripts.sshdPath) -T", asRoot: true)
        let ports = ServerInspection.sshdPorts(effective.stdout)
        guard ports.contains(newPort) else {
            throw DeploymentError(
                .portChangeFailed,
                "sshd does not report port \(newPort) after the change (ports: \(ports.map(String.init).joined(separator: ", "))).")
        }
        report(.changingPort, "Verifying key login on port \(newPort) after closing the previous port...", 84)
        try await verifyKeyLogin(as: request.username, port: newPort)
        finalPort = newPort

        let lingering = ports.filter { $0 != newPort }
        if !lingering.isEmpty {
            let list = lingering.map(String.init).joined(separator: ", ")
            let source = rootProbe.mainConfig ?? "/etc/ssh/sshd_config"
            warnings.append(
                "SSH now listens on port \(newPort), but port \(list) also stays open because it is set outside the managed file " +
                    "(for example a 'Port' line in \(source)). Remove that line yourself if the old port should close.")
        }
    }

    // MARK: - Commit

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
        // Last: everything above still needs sudo.
        if temporarySudoersMayExist {
            if let error = await removeTemporarySudoers() {
                warnings.append(
                    "Deployment is verified, but the temporary sudo rule \(temporarySudoersPath) could not be removed (\(error)). " +
                        "Remove it as root now: rm -f \(temporarySudoersPath)")
            }
        }
        return warnings
    }

    // MARK: - Recovery

    func recover() async -> RollbackOutcome {
        let needed = configModified || configBackupMayExist ||
            currentUserSnapshotMayExist || rootSnapshotMayExist ||
            selinuxPortMayBeAdded || ufwRuleMayBeAdded ||
            firewalldRuntimeMayBeAdded || firewalldPermanentMayBeAdded ||
            temporarySudoersMayExist
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
                    RemoteScripts.reloadSshd(restartSocket: portConfigChanged && (server?.socketActivated ?? false)),
                    asRoot: true,
                    timeout: Self.recoveryCommandTimeout)
                configRestored = true
            } catch {
                errors.append("SSH configuration recovery failed (\(describe(error))).")
            }
        }

        // The new port is only closed again once sshd no longer depends on it.
        if configRestored, let port = request.newSSHPort {
            errors.append(contentsOf: await closeNewPort(port))
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

        // Always last: every step above may need the temporary sudo rule.
        if temporarySudoersMayExist, let error = await removeTemporarySudoers() {
            errors.append("The temporary sudo rule \(temporarySudoersPath) could not be removed (\(error)); remove it as root.")
        }

        return errors.isEmpty ? .succeeded : .incomplete(errors.joined(separator: " "))
    }

    /// Removes firewall and SELinux entries this deployment added for the new port.
    private func closeNewPort(_ port: Int) async -> [String] {
        var errors: [String] = []
        let timeout = Self.recoveryCommandTimeout
        if ufwRuleMayBeAdded {
            if (try? await run(RemoteScripts.ufwDelete(port), asRoot: true, timeout: timeout).status) == 0 {
                ufwRuleMayBeAdded = false
            } else {
                errors.append("The ufw rule for port \(port) could not be removed (ufw delete allow \(port)/tcp).")
            }
        }
        if firewalldRuntimeMayBeAdded {
            if (try? await run(RemoteScripts.firewalld(add: false, permanent: false, port), asRoot: true, timeout: timeout).status) == 0 {
                firewalldRuntimeMayBeAdded = false
            } else {
                errors.append("The firewalld runtime rule for port \(port)/tcp could not be removed.")
            }
        }
        if firewalldPermanentMayBeAdded {
            if (try? await run(RemoteScripts.firewalld(add: false, permanent: true, port), asRoot: true, timeout: timeout).status) == 0 {
                firewalldPermanentMayBeAdded = false
            } else {
                errors.append("The permanent firewalld rule for port \(port)/tcp could not be removed.")
            }
        }
        if selinuxPortMayBeAdded {
            if (try? await run(RemoteScripts.selinuxRemoveSshPort(port), asRoot: true, timeout: Self.selinuxTimeout).status) == 0 {
                selinuxPortMayBeAdded = false
            } else {
                // The label may never have been added (uncertain outcome); check before reporting.
                let listing = try? await run(RemoteScripts.selinuxPortTypes(port), asRoot: true, timeout: Self.selinuxTimeout)
                if let listing, listing.status == 0,
                   !ServerInspection.values("TYPE", in: listing.stdout).contains("ssh_port_t") {
                    selinuxPortMayBeAdded = false
                } else {
                    errors.append("The SELinux label for port \(port) could not be removed (semanage port -d -t ssh_port_t -p tcp \(port)).")
                }
            }
        }
        return errors
    }

    /// Returns nil on success. Tries the current root path, then `su` when sudo itself
    /// depends on the rule being removed or never worked.
    private func removeTemporarySudoers() async -> String? {
        let script = RemoteScripts.removeTemporarySudoers(path: temporarySudoersPath)
        var lastError = "unknown error"
        do {
            let result = try await run(script, asRoot: true, timeout: Self.recoveryCommandTimeout)
            if result.status == 0 {
                temporarySudoersMayExist = false
                return nil
            }
            lastError = session.redact(result.diagnostic)
        } catch {
            lastError = describe(error)
        }
        if privilege == .su && rootPath != .su {
            do {
                let result = try await runViaSu(script, timeout: Self.recoveryCommandTimeout)
                if result.status == 0 {
                    temporarySudoersMayExist = false
                    return nil
                }
                lastError = session.redact(result.diagnostic)
            } catch {
                lastError = describe(error)
            }
        }
        return lastError
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

    // MARK: - sshd checks

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

    /// Runs `command`, elevating with sudo (or su while bootstrapping) when needed.
    /// Passwords are only ever sent on standard input, never on a command line.
    @discardableResult
    private func run(
        _ command: String,
        input: String? = nil,
        asRoot: Bool = false,
        timeout: TimeInterval = SSHSession.commandTimeout
    ) async throws -> RemoteResult {
        guard asRoot else {
            return try await session.run(command, input: input, timeout: timeout)
        }
        switch rootPath {
        case .direct:
            return try await session.run(command, input: input, timeout: timeout)
        case .sudo:
            let passwordLine = request.password + "\n"
            if let input {
                return try await session.run(RemoteScripts.sudoWithPayload(command), input: passwordLine + input, timeout: timeout)
            }
            return try await session.run(RemoteScripts.sudo(command), input: passwordLine, timeout: timeout)
        case .su:
            guard input == nil else {
                throw DeploymentError(.remote, "Internal error: commands with input cannot run through su.")
            }
            return try await runViaSu(command, timeout: timeout)
        }
    }

    /// Runs `command` as root through `su` on a remote terminal; the root password is
    /// typed at su's prompt and never appears in the command.
    private func runViaSu(_ command: String, timeout: TimeInterval) async throws -> RemoteResult {
        guard let rootPassword = request.rootPassword else {
            throw DeploymentError(.noPrivilege, "A root password is required to use su.")
        }
        let output = try await session.runWithTerminal(
            RemoteScripts.su(command),
            secret: rootPassword,
            startMarker: RemoteScripts.suStartMarker,
            timeout: timeout)
        guard output.started else {
            let text = [output.beforeStart, output.stderr]
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: " ")
            throw ServerInspection.suError(output: text, promptAnswered: output.promptAnswered)
        }
        return RemoteResult(status: output.status, stdout: output.afterStart, stderr: "")
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
        } catch let error as DeploymentError where error.kind != .remote {
            throw error
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

// MARK: - Server inspection (pure parsing and decisions)

/// Parses the inspection probes and makes the privilege and plan decisions. Free of
/// I/O so every rule can be unit tested.
enum ServerInspection {
    struct Probe: Equatable {
        var uid: Int?
        var osRelease: [String: String] = [:]
        var tools: Set<String> = []
        var initSystem: InitSystem = .other

        var osID: String { osRelease["ID"] ?? "linux" }
        var osName: String { osRelease["PRETTY_NAME"] ?? osRelease["NAME"] ?? "Linux" }
        var osVersion: String { osRelease["VERSION_ID"] ?? "" }
        var family: LinuxFamily { ServerInspection.family(id: osRelease["ID"] ?? "", idLike: osRelease["ID_LIKE"] ?? "") }
        var packageManager: PackageManager? { ServerInspection.packageManager(family: family, tools: tools) }
    }

    struct RootProbe: Equatable {
        var sshdPresent = false
        /// Effective ports from `sshd -T`.
        var ports: [Int] = []
        var sshdTestErrors: [String] = []
        /// The main sshd_config that was inspected (nil when none exists).
        var mainConfig: String?
        /// Arguments of `Include` lines before the first `Match` of the main config.
        var includes: [String] = []
        /// `Port` lines of the main config (they stay in force whatever the drop-in says).
        var mainPorts: [Int] = []
        /// `Port` lines of the managed drop-in from an earlier deployment.
        var managedPorts: [Int] = []
        var selinuxEnforcing = false
        var firewall: Firewall?
        var socketActivated = false
    }

    // MARK: Parsing

    static func keyValues(_ output: String) -> [(key: String, value: String)] {
        output.split(whereSeparator: \.isNewline).compactMap { line -> (key: String, value: String)? in
            guard let equals = line.firstIndex(of: "=") else { return nil }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { return nil }
            return (key, String(line[line.index(after: equals)...]))
        }
    }

    /// Every value of `key` in `KEY=VALUE` output, trimmed.
    static func values(_ key: String, in output: String) -> [String] {
        keyValues(output).filter { $0.key == key }.map { $0.value.trimmingCharacters(in: .whitespaces) }
    }

    static func parseProbe(_ output: String) -> Probe {
        var probe = Probe()
        for (key, value) in keyValues(output) {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            switch key {
            case "UID": probe.uid = Int(trimmed)
            case "HAS": probe.tools.insert(trimmed)
            case "INIT": probe.initSystem = InitSystem(rawValue: trimmed) ?? .other
            default:
                if key.hasPrefix("OS_") {
                    let name = String(key.dropFirst(3))
                    if probe.osRelease[name] == nil { probe.osRelease[name] = osReleaseValue(value) }
                }
            }
        }
        return probe
    }

    /// Decodes an os-release value: unquoted, "double quoted" (with backslash escapes)
    /// or 'single quoted'.
    static func osReleaseValue(_ raw: String) -> String {
        let value = raw.trimmingCharacters(in: .whitespaces)
        guard value.count >= 2, let first = value.first, value.last == first, first == "\"" || first == "'" else {
            return value
        }
        let inner = value.dropFirst().dropLast()
        guard first == "\"" else { return String(inner) }
        var result = ""
        var escaped = false
        for character in inner {
            if escaped {
                result.append(character)
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else {
                result.append(character)
            }
        }
        return result
    }

    static func parseRootProbe(_ output: String) -> RootProbe {
        var probe = RootProbe()
        for (key, rawValue) in keyValues(output) {
            let value = rawValue.trimmingCharacters(in: .whitespaces)
            switch key {
            case "SSHD": probe.sshdPresent = value == "yes"
            case "PORT": if let port = port(value) { probe.ports.append(port) }
            case "SSHD_T_ERROR": probe.sshdTestErrors.append(value)
            case "MAIN_CONFIG": probe.mainConfig = value.isEmpty ? nil : value
            case "INCLUDE": probe.includes.append(value)
            case "MAIN_PORT": if let port = port(value) { probe.mainPorts.append(port) }
            case "MANAGED_PORT": if let port = port(value) { probe.managedPorts.append(port) }
            case "SELINUX": probe.selinuxEnforcing = value.lowercased() == "enforcing"
            case "FIREWALL": probe.firewall = Firewall(rawValue: value)
            case "SOCKET": probe.socketActivated = value == "active"
            default: break
            }
        }
        return probe
    }

    /// Ports listed by `sshd -T`.
    static func sshdPorts(_ output: String) -> [Int] {
        output.split(whereSeparator: \.isNewline).compactMap { line -> Int? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count == 2, fields[0].lowercased() == "port" else { return nil }
            return port(String(fields[1]))
        }
    }

    private static func port(_ text: String) -> Int? {
        guard let value = Int(text.trimmingCharacters(in: .whitespaces)), (1...65_535).contains(value) else { return nil }
        return value
    }

    /// True when ufw reports that `ufw allow` created or changed a rule.
    static func ufwAddedRule(_ output: String) -> Bool {
        let text = output.lowercased()
        return text.contains("rule added") || text.contains("rules updated")
    }

    // MARK: Distribution

    static func family(id: String, idLike: String) -> LinuxFamily {
        let tokens = [id.lowercased()] + idLike.lowercased().split(whereSeparator: \.isWhitespace).map(String.init)
        for token in tokens {
            switch token {
            case "debian", "ubuntu", "raspbian", "linuxmint", "pop", "kali", "devuan", "elementary", "zorin":
                return .debian
            case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "circle", "eurolinux",
                 "cloudlinux", "scientific", "navy":
                return .rhel
            case "suse", "sles", "sled", "opensuse":
                return .suse
            case "arch", "archarm", "manjaro", "endeavouros", "garuda":
                return .arch
            case "alpine", "postmarketos":
                return .alpine
            default:
                if token.hasPrefix("opensuse") { return .suse }
            }
        }
        return .unknown
    }

    static func tool(for manager: PackageManager) -> String {
        manager == .apt ? "apt-get" : manager.rawValue
    }

    static func packageManager(family: LinuxFamily, tools: Set<String>) -> PackageManager? {
        let preferred: [PackageManager]
        switch family {
        case .debian: preferred = [.apt]
        case .rhel: preferred = [.dnf, .yum]
        case .suse: preferred = [.zypper]
        case .arch: preferred = [.pacman]
        case .alpine: preferred = [.apk]
        case .unknown: preferred = []
        }
        let all: [PackageManager] = [.apt, .dnf, .yum, .zypper, .pacman, .apk]
        return (preferred + all).first { tools.contains(tool(for: $0)) }
    }

    /// The package that provides `semanage`, where the distribution ships SELinux tooling.
    static func semanagePackage(_ manager: PackageManager) -> String? {
        switch manager {
        case .apt, .dnf, .zypper: return "policycoreutils-python-utils"
        case .yum: return "policycoreutils-python"
        case .pacman, .apk: return nil
        }
    }

    // MARK: sshd drop-in support

    /// True when one of the `Include` arguments matches the managed drop-in. Relative
    /// paths are relative to /etc/ssh, as in sshd.
    static func includesManagedDropIn(_ includes: [String], managedPath: String = RemoteScripts.managedConfigPath) -> Bool {
        for line in includes {
            for token in line.split(whereSeparator: \.isWhitespace) {
                var pattern = String(token)
                if pattern.count >= 2, let first = pattern.first, first == "\"" || first == "'", pattern.last == first {
                    pattern = String(pattern.dropFirst().dropLast())
                }
                if !pattern.hasPrefix("/") { pattern = "/etc/ssh/" + pattern }
                if fnmatch(pattern, managedPath, FNM_PATHNAME) == 0 { return true }
            }
        }
        return false
    }

    static let requiredIncludeLine = "Include /etc/ssh/sshd_config.d/*.conf"

    static func missingIncludeMessage(mainConfig: String?) -> String {
        var message =
            "This server's SSH configuration does not load /etc/ssh/sshd_config.d/*.conf, so settings written there would be ignored. " +
            "Nothing was changed. As root, add this line near the top of /etc/ssh/sshd_config (before any Match block):\n" +
            "\(requiredIncludeLine)\n" +
            "then run 'sshd -t', reload the SSH service and retry."
        if let mainConfig, mainConfig != "/etc/ssh/sshd_config" {
            message += " Because /etc/ssh/sshd_config does not exist, first copy \(mainConfig) to /etc/ssh/sshd_config."
        } else if mainConfig == nil {
            message += " (No sshd_config was found at all.)"
        }
        return message
    }

    // MARK: Privileges

    enum SudoOutcome: Equatable {
        case ok
        case notAuthorized
        case unavailable
        case passwordRejected
        case other
    }

    static func classifySudo(status: Int32, diagnostic: String) -> SudoOutcome {
        guard status != 0 else { return .ok }
        let text = diagnostic.lowercased()
        // Wording of classic sudo and of sudo-rs (Ubuntu 25.10+).
        if ["not in the sudoers file", "is not allowed to run sudo", "may not run sudo", "is not in the sudoers",
            "afraid i can't do that", "afraid i can\u{2019}t do that"]
            .contains(where: { text.contains($0) }) {
            return .notAuthorized
        }
        if ["sudo: command not found", "sudo: not found", "sudo: no such file or directory"]
            .contains(where: { text.contains($0) }) {
            return .unavailable
        }
        if ["incorrect password attempt", "sorry, try again", "authentication failure", "a password is required",
            "no password was provided", "authentication failed", "incorrect authentication attempt"]
            .contains(where: { text.contains($0) }) {
            return .passwordRejected
        }
        return .other
    }

    enum PrivilegeDecision: Equatable {
        case use(PrivilegeMode)
        case fail(DeploymentError.Kind)
    }

    /// uid 0 → root; working sudo → sudo; root password and su → su (also when sudo
    /// rejects the account password, e.g. openSUSE's targetpw); otherwise an error that
    /// tells the user what to change. `.noPrivilege` means a root password would help.
    static func decidePrivilege(uid: Int, sudo: SudoOutcome?, rootPasswordGiven: Bool, suInstalled: Bool) -> PrivilegeDecision {
        if uid == 0 { return .use(.root) }
        if sudo == .ok { return .use(.sudo) }
        if rootPasswordGiven {
            return suInstalled ? .use(.su) : .fail(.suUnavailable)
        }
        switch sudo {
        case .notAuthorized?: return .fail(suInstalled ? .noPrivilege : .sudoNotAuthorized)
        case .unavailable?, nil: return .fail(suInstalled ? .noPrivilege : .sudoUnavailable)
        case .passwordRejected?: return .fail(.sudoPasswordRejected)
        case .other?, .ok?: return .fail(.noPrivilege)
        }
    }

    /// Distribution-specific root-console commands that give `username` sudo rights.
    static func grantSudoInstructions(family: LinuxFamily, username: String, sudoInstalled: Bool) -> String {
        switch family {
        case .debian:
            return (sudoInstalled ? "" : "apt-get update && apt-get install -y sudo && ") + "usermod -aG sudo \(username)"
        case .rhel:
            return (sudoInstalled ? "" : "dnf install -y sudo && ") + "usermod -aG wheel \(username)"
        case .suse:
            return (sudoInstalled ? "" : "zypper --non-interactive install sudo && ") +
                "usermod -aG wheel \(username), then run 'visudo -f /etc/sudoers.d/wheel' and add the lines " +
                "'%wheel ALL=(ALL:ALL) ALL' and 'Defaults:%wheel !targetpw, !rootpw, !runaspw' " +
                "(openSUSE's default 'Defaults targetpw' otherwise makes sudo ask for the root password)"
        case .arch:
            return (sudoInstalled ? "" : "pacman -S --needed sudo && ") +
                "usermod -aG wheel \(username), then run 'EDITOR=vi visudo' and uncomment the line '%wheel ALL=(ALL:ALL) ALL'"
        case .alpine:
            return (sudoInstalled ? "" : "apk add sudo && ") +
                "adduser \(username) wheel && echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/wheel && chmod 0440 /etc/sudoers.d/wheel"
        case .unknown:
            return (sudoInstalled ? "" : "install sudo with the system package manager, then ") +
                "add \(username) to the group that may use sudo (usually sudo or wheel)"
        }
    }

    static let rootPasswordAlternative =
        "Alternatively, enter the root password: the deployer then uses su to grant this account temporary sudo rights, " +
        "which are removed when the deployment ends."

    static func privilegeError(
        _ kind: DeploymentError.Kind,
        family: LinuxFamily,
        osName: String,
        username: String,
        sudoInstalled: Bool,
        diagnostic: String
    ) -> DeploymentError {
        let instructions = grantSudoInstructions(family: family, username: username, sudoInstalled: sudoInstalled)
        let relogin = "Then fully sign out of '\(username)', sign in again, and retry."
        let reason = sudoInstalled
            ? "account '\(username)' is not authorized to use sudo. Using 'su' with the root password is different from having sudo permission."
            : "sudo is not installed on the server."
        switch kind {
        case .noPrivilege:
            let sudoSaid = sudoInstalled && !diagnostic.isEmpty ? " (sudo said: \(diagnostic))" : ""
            return DeploymentError(
                .noPrivilege,
                "SSH password login succeeded, but \(reason) From a root console on \(osName), run: \(instructions). \(relogin) " +
                    rootPasswordAlternative + sudoSaid)
        case .sudoNotAuthorized, .sudoUnavailable:
            return DeploymentError(
                kind,
                "SSH password login succeeded, but \(reason) From a root console on \(osName), run: \(instructions). \(relogin)")
        case .sudoPasswordRejected:
            let note = family == .suse
                ? " openSUSE and SLES configure sudo to ask for the root password ('Defaults targetpw'); enter the root password so the deployer can use su instead."
                : " If sudo on this server asks for the root password, enter the root password so the deployer can use su instead."
            return DeploymentError(
                .sudoPasswordRejected,
                "SSH password login succeeded, but sudo rejected the password for account '\(username)'. " +
                    "sudo normally requires the current account password, not the root password." + note)
        case .suUnavailable:
            return DeploymentError(
                .suUnavailable,
                "A root password was entered, but su is not installed on the server, so it cannot be used. " +
                    "From a root console on \(osName), run: \(instructions). \(relogin)")
        default:
            return DeploymentError(kind, "Root privileges could not be obtained. \(diagnostic)")
        }
    }

    /// Classifies a failed `su` (the start marker never appeared) from its terminal output.
    static func suError(output: String, promptAnswered: Bool) -> DeploymentError {
        let text = output.lowercased()
        let detail = output.isEmpty ? "" : " (su said: \(output))"
        if ["expired", "change your password", "new password"].contains(where: { text.contains($0) }) {
            return DeploymentError(
                .rootPasswordRejected,
                "su requires the root password to be changed before it can be used. " +
                    "Sign in as root on the console, change the password, and retry." + detail)
        }
        if ["authentication failure", "incorrect password", "sorry", "authentication token", "password incorrect"]
            .contains(where: { text.contains($0) }) {
            return DeploymentError(
                .rootPasswordRejected,
                "su rejected the root password. Enter the password of the root account (not the account password) and retry." + detail)
        }
        if ["permission denied", "not permitted", "not allowed", "must be suid", "not found", "no such file",
            "currently not available", "cannot open session", "module is unknown"]
            .contains(where: { text.contains($0) }) {
            return DeploymentError(
                .suUnavailable,
                "su refused to switch to root. Some systems only allow members of the wheel group to use su (pam_wheel), " +
                    "and BusyBox su must be installed setuid. Ask an administrator to grant sudo rights instead." + detail)
        }
        if !promptAnswered {
            return DeploymentError(.suUnavailable, "su did not ask for the root password and did not run the command." + detail)
        }
        return DeploymentError(.rootPasswordRejected, "su did not accept the root password." + detail)
    }

    // MARK: Plan

    /// The port to move to, or nil when no change is requested or sshd already uses only it.
    static func portToChange(current: [Int], requested: Int?) -> Int? {
        guard let requested, (1...65_535).contains(requested) else { return nil }
        return Set(current) == [requested] ? nil : requested
    }

    /// Ports for the first phase of a port change: everything sshd listens on now that
    /// the main config does not already pin (those stay in force regardless), plus the new port.
    static func transitionPorts(current: [Int], mainPorts: [Int], newPort: Int) -> [Int] {
        var seen = Set<Int>()
        return (current.filter { !mainPorts.contains($0) } + [newPort]).filter { seen.insert($0).inserted }
    }

    static func buildPlan(server: ServerInfo, request: DeploymentRequest, semanageInstalled: Bool) throws -> DeploymentPlan {
        var packages: [String] = []
        if server.privilege == .su && !server.sudoInstalled {
            packages.append("sudo")
        }
        let newPort = portToChange(current: server.currentPorts, requested: request.newSSHPort)
        if newPort != nil && server.selinuxEnforcing && !semanageInstalled {
            guard let manager = server.packageManager, let package = semanagePackage(manager) else {
                throw DeploymentError(
                    .unsupportedServer,
                    "SELinux is enforcing, so the new SSH port must be labeled with semanage, but semanage is not installed " +
                        "and no package for it is known on \(server.osName). Install semanage and retry. Nothing was changed.")
            }
            packages.append(package)
        }

        var actions: [PlannedAction] = []
        if !packages.isEmpty {
            guard let manager = server.packageManager else {
                throw DeploymentError(
                    .unsupportedServer,
                    "The packages \(packages.joined(separator: ", ")) are required, but no supported package manager " +
                        "(apt-get, dnf, yum, zypper, pacman, apk) was found. Install them and retry. Nothing was changed.")
            }
            actions.append(.installPackages(manager: manager, packages: packages))
        }
        if server.privilege == .su {
            actions.append(.temporarySudoViaSu(account: request.username))
        }
        actions.append(.installPublicKey(account: request.username))
        if request.targetUsername == "root" && request.username != "root" {
            actions.append(.installPublicKey(account: "root"))
        }
        actions.append(.writeSshdPolicy(rootLogin: request.rootLoginPolicy, passwordLogin: request.allowPasswordLogin))
        if let newPort {
            actions.append(.changePort(from: server.currentPorts, to: newPort))
            if let firewall = server.firewall {
                actions.append(.openFirewallPort(firewall, port: newPort))
            }
            if server.selinuxEnforcing {
                actions.append(.labelSelinuxPort(port: newPort))
            }
        }
        return DeploymentPlan(server: server, actions: actions)
    }
}
