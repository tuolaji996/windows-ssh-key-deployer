import Foundation

/// Creates and validates local Ed25519 key pairs with the system `ssh-keygen`.
public struct KeyStore: Sendable {
    // Never resolved through PATH: /usr/bin is protected by System Integrity Protection.
    static let sshKeygenPath = "/usr/bin/ssh-keygen"
    private static let toolTimeout: TimeInterval = 30

    public init() {}

    public static var defaultKeyPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/ssh-key-deployer/server_ed25519")
            .path
    }

    /// Returns the existing pair at `keyPath`, or generates a new one when neither file exists.
    public func ensureKeyPair(at keyPath: String) async throws -> KeyPairInfo {
        let path = try Self.validatedPath(keyPath)
        let privateExists = FileManager.default.fileExists(atPath: path)
        let publicExists = FileManager.default.fileExists(atPath: path + ".pub")

        switch (privateExists, publicExists) {
        case (true, true):
            return try await readExisting(at: path)
        case (false, false):
            return try await generate(at: path)
        default:
            throw DeploymentError(
                .key,
                "The private key and .pub file must exist as a pair. Choose a new filename; existing keys will not be overwritten.")
        }
    }

    public func generate(at keyPath: String) async throws -> KeyPairInfo {
        let path = try Self.validatedPath(keyPath)
        let publicPath = path + ".pub"
        let fileManager = FileManager.default
        let parent = (path as NSString).deletingLastPathComponent

        if !fileManager.fileExists(atPath: parent) {
            try fileManager.createDirectory(
                atPath: parent,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            // Intermediate directories may have been created with the default mode.
            try Self.setMode(0o700, path: parent)
        }

        guard !fileManager.fileExists(atPath: path), !fileManager.fileExists(atPath: publicPath) else {
            throw DeploymentError(
                .key,
                "The private-key path or matching .pub path already exists. Choose a new path to avoid overwriting a key.")
        }

        // Generate into a private staging directory on the same volume, then publish
        // with a rename so a half-written key never appears at the destination.
        let staging = parent + "/.ssh-key-deployer-" + UUID().uuidString.lowercased()
        try fileManager.createDirectory(
            atPath: staging,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? fileManager.removeItem(atPath: staging) }

        let stagedPrivate = staging + "/id_ed25519"
        let stagedPublic = stagedPrivate + ".pub"
        let result = try await ProcessRunner.run(
            Self.sshKeygenPath,
            ["-q", "-t", "ed25519", "-f", stagedPrivate, "-N", "", "-C", Ed25519PublicKey.comment],
            timeout: Self.toolTimeout)
        guard result.status == 0 else {
            throw DeploymentError(.key, Self.describe("ssh-keygen did not generate the key.", result.stderr))
        }
        guard fileManager.fileExists(atPath: stagedPrivate), fileManager.fileExists(atPath: stagedPublic) else {
            throw DeploymentError(
                .key,
                "ssh-keygen reported success but the private/public key pair was not created.")
        }

        try Self.protectPrivateKey(stagedPrivate)
        let publicKey = try Ed25519PublicKey.read(path: stagedPublic)
        try await ensureMatchingPair(privateKeyPath: stagedPrivate, publicKey: publicKey)
        try Task.checkCancellation()

        // Publish the public key first so a private key is never left behind if the
        // destination turns out to be taken at the last moment. moveItem refuses to overwrite.
        do {
            try fileManager.moveItem(atPath: stagedPublic, toPath: publicPath)
        } catch {
            throw DeploymentError(
                .key,
                "The generated key could not be published without overwriting an existing file.")
        }
        do {
            try fileManager.moveItem(atPath: stagedPrivate, toPath: path)
        } catch {
            // Whatever now occupies `path` is not ours; only withdraw our public key.
            try? fileManager.removeItem(atPath: publicPath)
            throw DeploymentError(
                .key,
                "The generated key could not be published without overwriting an existing file.")
        }
        do {
            try Self.protectPrivateKey(path)
        } catch {
            try? fileManager.removeItem(atPath: publicPath)
            try? fileManager.removeItem(atPath: path)
            throw error
        }

        return KeyPairInfo(
            privateKeyPath: path,
            publicKeyPath: publicPath,
            publicKey: publicKey.normalizedText,
            sha256Fingerprint: publicKey.sha256Fingerprint)
    }

    public func readExisting(at keyPath: String) async throws -> KeyPairInfo {
        let path = try Self.validatedPath(keyPath)
        let publicPath = path + ".pub"
        guard FileManager.default.fileExists(atPath: path),
              FileManager.default.fileExists(atPath: publicPath) else {
            throw DeploymentError(.key, "Both the private key and matching .pub file must exist.")
        }

        try Self.protectPrivateKey(path)
        let publicKey = try Self.readPublicKey(path: publicPath)
        try await ensureMatchingPair(privateKeyPath: path, publicKey: publicKey)
        return KeyPairInfo(
            privateKeyPath: path,
            publicKeyPath: publicPath,
            publicKey: publicKey.normalizedText,
            sha256Fingerprint: publicKey.sha256Fingerprint)
    }

    /// Confirms the private key is an unencrypted Ed25519 key that matches `publicKey`.
    func ensureMatchingPair(privateKeyPath: String, publicKey: Ed25519PublicKey) async throws {
        // An empty passphrase makes an encrypted key fail immediately instead of prompting.
        let result = try await ProcessRunner.run(
            Self.sshKeygenPath,
            ["-y", "-P", "", "-f", privateKeyPath],
            timeout: Self.toolTimeout)
        guard result.status == 0 else {
            throw DeploymentError(.key, Self.describe(
                "The private key could not be read by OpenSSH. Only an unencrypted Ed25519 key is supported.",
                result.stderr))
        }
        guard let derived = try? Ed25519PublicKey.parse(result.stdout) else {
            throw DeploymentError(.key, "The private key is not an Ed25519 OpenSSH key.")
        }
        guard derived.keyData == publicKey.keyData else {
            throw DeploymentError(.key, "The .pub file does not match the selected private key.")
        }
    }

    static func readPublicKey(path: String) throws -> Ed25519PublicKey {
        do {
            return try Ed25519PublicKey.read(path: path)
        } catch let error as DeploymentError {
            throw error
        } catch {
            throw DeploymentError(.key, "The Ed25519 public key could not be read.")
        }
    }

    /// Restricts the private key to owner read/write, which OpenSSH requires.
    static func protectPrivateKey(_ path: String) throws {
        var status = stat()
        guard lstat(path, &status) == 0, (status.st_mode & S_IFMT) == S_IFREG else {
            throw DeploymentError(.key, "The private key must be a regular file, not a link or directory.")
        }
        try setMode(0o600, path: path)
    }

    private static func setMode(_ mode: Int, path: String) throws {
        do {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
        } catch {
            throw DeploymentError(
                .key,
                "The operating system denied access while restricting permissions on \(path).")
        }
    }

    private static func validatedPath(_ keyPath: String) throws -> String {
        let expanded = DeploymentRequest.expandPath(keyPath)
        if let problem = RequestValidator.keyPathProblem(expanded) {
            throw DeploymentError(.key, problem)
        }
        return (expanded as NSString).standardizingPath
    }

    private static func describe(_ summary: String, _ diagnostic: String) -> String {
        let detail = diagnostic.trimmingCharacters(in: .whitespacesAndNewlines)
        return detail.isEmpty ? summary : "\(summary) \(detail)"
    }
}
