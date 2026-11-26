import Foundation

struct RemoteResult: Sendable {
    let status: Int32
    let stdout: String
    let stderr: String

    /// The most useful diagnostic text: stderr when present, otherwise stdout.
    var diagnostic: String {
        let error = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        return error.isEmpty ? stdout.trimmingCharacters(in: .whitespacesAndNewlines) : error
    }
}

/// A password-authenticated SSH connection built on the system OpenSSH client.
///
/// The first `ssh` process becomes a ControlMaster, so the password is sent to the
/// server exactly once; every later command is multiplexed over the local control
/// socket. Host keys are pinned to the fingerprint the user approved, and the user's
/// own `~/.ssh/config`, agent and `known_hosts` are never consulted or modified.
final class SSHSession: @unchecked Sendable {
    static let sshPath = "/usr/bin/ssh"
    static let sshKeyscanPath = "/usr/bin/ssh-keyscan"

    static let connectTimeout = 20
    static let commandTimeout: TimeInterval = 30
    private static let maximumOutputLength = 16 * 1024
    /// Every connection checks the server against this alias in the private known_hosts file.
    private static let hostAlias = "ssh-key-deployer-target"

    let host: String
    let port: Int
    let username: String
    private let password: String
    private let workDirectory: URL
    private var hostKey: ScannedHostKey?
    private var masterStarted = false

    private var knownHostsPath: String { workDirectory.appendingPathComponent("known_hosts").path }
    private var controlPath: String { workDirectory.appendingPathComponent("ctl").path }
    private var askpassPath: String { workDirectory.appendingPathComponent("askpass").path }

    init(host: String, port: Int, username: String, password: String) throws {
        self.host = host
        self.port = port
        self.username = username
        self.password = password

        // A short path under /tmp keeps the control socket within the 104-byte
        // sun_path limit; mkdtemp creates the directory with mode 0700.
        var template = Array("/tmp/ssh-key-deployer.XXXXXXXX".utf8CString)
        guard let created = mkdtemp(&template) else {
            throw DeploymentError(.connectionFailed, "A private temporary directory could not be created.")
        }
        workDirectory = URL(fileURLWithPath: String(cString: created))

        // The askpass helper reads the password from its environment, which only this
        // user (and root) can inspect; the password is never written to disk.
        let script = "#!/bin/sh\nprintf '%s\\n' \"$SSH_KEY_DEPLOYER_SECRET\"\n"
        guard FileManager.default.createFile(
            atPath: askpassPath,
            contents: Data(script.utf8),
            attributes: [.posixPermissions: 0o700]) else {
            throw DeploymentError(.connectionFailed, "The SSH password helper could not be created.")
        }
    }

    deinit {
        try? FileManager.default.removeItem(at: workDirectory)
    }

    // MARK: - Host key

    /// Fetches the server's host key without authenticating.
    func scanHostKey() async throws -> HostKeyInfo {
        let result = try await ProcessRunner.run(
            Self.sshKeyscanPath,
            ["-T", String(Self.connectTimeout), "-p", String(port), "-t", "ed25519,ecdsa,rsa", "--", host],
            timeout: TimeInterval(Self.connectTimeout + 10))

        guard let key = ScannedHostKey.parseBest(keyscanOutput: result.stdout) else {
            let reason = Self.classifyConnectionFailure(result.stderr, timedOut: result.timedOut)
            throw DeploymentError(
                reason == .connectionFailed ? .networkUnavailable : reason,
                Self.connectionFailureMessage(reason, host: host, port: port, username: username))
        }
        hostKey = key
        return key.info(host: host, port: port)
    }

    /// Pins the scanned key; every later connection refuses any other key.
    func trustScannedHostKey() throws {
        guard let hostKey else {
            throw DeploymentError(.hostKeyRejected, "No server host key has been scanned.")
        }
        try Data(hostKey.knownHostsLine(alias: Self.hostAlias).utf8)
            .write(to: URL(fileURLWithPath: knownHostsPath), options: .atomic)
    }

    // MARK: - Password connection

    func connect() async throws {
        guard let hostKey else {
            throw DeploymentError(.hostKeyRejected, "The server host key has not been approved.")
        }

        var environment = ProcessInfo.processInfo.environment
        environment["SSH_ASKPASS"] = askpassPath
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment["DISPLAY"] = environment["DISPLAY"] ?? ":0"
        environment["SSH_KEY_DEPLOYER_SECRET"] = password
        environment.removeValue(forKey: "SSH_AUTH_SOCK")

        let options = baseOptions(hostKey: hostKey) + [
            "-M", "-N", "-f",
            "-o", "ControlPath=\(controlPath)",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
        ]

        let result = try await ProcessRunner.run(
            Self.sshPath,
            options + ["-l", username, "--", host],
            environment: environment,
            timeout: TimeInterval(Self.connectTimeout + 20),
            stderrFile: workDirectory.appendingPathComponent("connect.log"))

        guard result.status == 0, !result.timedOut else {
            let reason = Self.classifyConnectionFailure(result.stderr, timedOut: result.timedOut)
            throw DeploymentError(
                reason,
                Self.connectionFailureMessage(reason, host: host, port: port, username: username))
        }
        masterStarted = true
    }

    /// Runs `command` through the remote login shell over the authenticated master connection.
    func run(_ command: String, input: String? = nil, timeout: TimeInterval = SSHSession.commandTimeout) async throws -> RemoteResult {
        guard masterStarted, let hostKey else {
            throw DeploymentError(.remote, "The SSH connection is not open.")
        }
        let options = baseOptions(hostKey: hostKey) + [
            "-o", "ControlMaster=no",
            "-o", "ControlPath=\(controlPath)",
            "-o", "BatchMode=yes",
            "-o", "PubkeyAuthentication=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "HostbasedAuthentication=no",
            "-o", "GSSAPIAuthentication=no",
            "-T",
        ]
        let output = try await ProcessRunner.run(
            Self.sshPath,
            options + ["-l", username, "--", host, command],
            input: input.map { Data($0.utf8) } ?? Data(),
            timeout: timeout)

        guard !output.timedOut else {
            throw DeploymentError(.remote, "The remote command timed out.")
        }
        // 255 is reserved by ssh itself for transport errors.
        if output.status == 255 {
            throw DeploymentError(.remote, "The SSH connection was lost: \(redact(Self.limit(output.stderr)))")
        }
        return RemoteResult(
            status: output.status,
            stdout: Self.limit(output.stdout),
            stderr: Self.limit(output.stderr))
    }

    func close() async {
        guard masterStarted, let hostKey else { return }
        masterStarted = false
        _ = try? await ProcessRunner.run(
            Self.sshPath,
            baseOptions(hostKey: hostKey) + ["-o", "ControlPath=\(controlPath)", "-O", "exit", "-l", username, "--", host],
            timeout: 10)
    }

    // MARK: - Key login verification

    /// Opens an independent connection with only `privateKeyPath` and returns `id -un`.
    func verifyKeyLogin(as account: String, privateKeyPath: String) async throws -> String {
        guard let hostKey else {
            throw DeploymentError(.hostKeyRejected, "The server host key has not been approved.")
        }
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "SSH_AUTH_SOCK")
        environment.removeValue(forKey: "SSH_ASKPASS")

        let options = baseOptions(hostKey: hostKey) + [
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-i", privateKeyPath,
            "-T",
        ]
        let output = try await ProcessRunner.run(
            Self.sshPath,
            options + ["-l", account, "--", host, "id -un"],
            environment: environment,
            input: Data(),
            timeout: TimeInterval(Self.connectTimeout + 15))

        if output.stderr.contains("Host key verification failed") ||
            output.stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
            throw DeploymentError(.hostKeyChanged, "The server host key changed during key-login verification.")
        }
        guard output.status == 0, !output.timedOut else {
            let detail = output.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw DeploymentError(
                .remote,
                "Key authentication as \(account) could not be verified." + (detail.isEmpty ? "" : " \(detail)"))
        }
        return output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Helpers

    func redact(_ text: String) -> String {
        password.isEmpty ? text : text.replacingOccurrences(of: password, with: "[redacted]")
    }

    /// Options shared by every connection: no user configuration, a private
    /// known_hosts file and strict checking against the single approved key.
    private func baseOptions(hostKey: ScannedHostKey) -> [String] {
        [
            "-F", "/dev/null",
            "-p", String(port),
            "-o", "HostKeyAlias=\(Self.hostAlias)",
            "-o", "UserKnownHostsFile=\(knownHostsPath)",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no",
            "-o", "CheckHostIP=no",
            "-o", "HostKeyAlgorithms=\(hostKey.negotiationAlgorithms)",
            "-o", "ConnectTimeout=\(Self.connectTimeout)",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "LogLevel=ERROR",
        ]
    }

    static func classifyConnectionFailure(_ stderr: String, timedOut: Bool) -> DeploymentError.Kind {
        let text = stderr.lowercased()
        if text.contains("host key verification failed") || text.contains("remote host identification has changed") {
            return .hostKeyChanged
        }
        if text.contains("permission denied") || text.contains("too many authentication failures") {
            return .authenticationRejected
        }
        if timedOut || text.contains("timed out") {
            return .connectionTimedOut
        }
        let networkMarkers = [
            "connection refused", "no route to host", "network is unreachable",
            "could not resolve hostname", "name or service not known",
            "nodename nor servname", "connection reset", "connection closed",
        ]
        if networkMarkers.contains(where: { text.contains($0) }) {
            return .networkUnavailable
        }
        return .connectionFailed
    }

    static func connectionFailureMessage(
        _ kind: DeploymentError.Kind,
        host: String,
        port: Int,
        username: String
    ) -> String {
        let endpoint = "\(host):\(port)"
        switch kind {
        case .hostKeyChanged:
            return "The server host key no longer matches the approved fingerprint. No server changes were made."
        case .authenticationRejected:
            return "The SSH server at \(endpoint) was reached, but password authentication was rejected for account '\(username)'. " +
                "Verify the account name and current account password, and confirm that password authentication is enabled for this account. " +
                "No server changes were made."
        case .connectionTimedOut:
            return "The SSH connection to \(endpoint) timed out. Verify the address, port, firewall, VPN or LAN connection, and that sshd is running. " +
                "No server changes were made."
        case .networkUnavailable:
            return "An SSH connection to \(endpoint) could not be opened. Verify the address, port, firewall, VPN or LAN connection, and that sshd is running. " +
                "No server changes were made."
        default:
            return "The initial password-authenticated SSH connection failed. Verify the server address, port, account, password, and SSH service. " +
                "No server changes were made."
        }
    }

    private static func limit(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.count <= maximumOutputLength ? trimmed : String(trimmed.prefix(maximumOutputLength)) + "..."
    }
}
