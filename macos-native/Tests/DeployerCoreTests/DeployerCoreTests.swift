import Foundation
import XCTest
@testable import DeployerCore

final class PublicKeyTests: XCTestCase {
    // 32 zero bytes behind the "ssh-ed25519" algorithm name.
    static let sampleBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    func testParsesAndNormalizesComment() throws {
        let key = try Ed25519PublicKey.parse("ssh-ed25519 \(Self.sampleBlob) someone@laptop\n")
        XCTAssertEqual(key.normalizedText, "ssh-ed25519 \(Self.sampleBlob) ssh-key-deployer")
        XCTAssertTrue(key.sha256Fingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(key.sha256Fingerprint.hasSuffix("="))
    }

    func testRejectsOtherAlgorithmsAndMultipleKeys() {
        XCTAssertThrowsError(try Ed25519PublicKey.parse("ssh-rsa \(Self.sampleBlob)"))
        XCTAssertThrowsError(try Ed25519PublicKey.parse("ssh-ed25519 !!!notbase64"))
        XCTAssertThrowsError(try Ed25519PublicKey.parse(
            "ssh-ed25519 \(Self.sampleBlob)\nssh-ed25519 \(Self.sampleBlob)"))
        // A blob that claims to be Ed25519 but has a 31-byte key.
        XCTAssertThrowsError(try Ed25519PublicKey.parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAHwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
    }

    func testKeyscanPrefersEd25519AndChecksBlobAlgorithm() throws {
        let output = """
        # 203.0.113.10:22 SSH-2.0-OpenSSH_9.2p1 Debian
        203.0.113.10 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAA
        203.0.113.10 ssh-ed25519 \(Self.sampleBlob)
        """
        let key = try XCTUnwrap(ScannedHostKey.parseBest(keyscanOutput: output))
        XCTAssertEqual(key.algorithm, "ssh-ed25519")
        XCTAssertEqual(key.keyLength, 256)
        XCTAssertEqual(key.knownHostsLine(alias: "alias"), "alias ssh-ed25519 \(Self.sampleBlob)\n")

        // Text column says ed25519 but the blob says otherwise: ignored.
        XCTAssertNil(ScannedHostKey.parseBest(keyscanOutput:
            "h ssh-ed25519 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAA"))
    }
}

final class ValidationTests: XCTestCase {
    private func request(
        host: String = "server.example.com",
        port: Int = 22,
        username: String = "deploy",
        password: String = "secret",
        keyPath: String = "/Users/me/.ssh/id_test",
        root: Bool = false
    ) -> DeploymentRequest {
        DeploymentRequest(
            host: host, port: port, username: username, password: password,
            keyPath: keyPath, enableRootLogin: root, allowPasswordLogin: true)
    }

    private func fields(_ request: DeploymentRequest) -> [ValidationIssue.Field] {
        RequestValidator.validate(request, requireExistingKey: false).map(\.field)
    }

    func testAcceptsValidInput() {
        XCTAssertEqual(fields(request()), [])
        XCTAssertEqual(fields(request(host: "[2001:db8::1]")), [])
        XCTAssertEqual(fields(request(host: "203.0.113.10")), [])
    }

    func testRejectsBadHostsPortsAndUsers() {
        XCTAssertEqual(fields(request(host: "")), [.host])
        XCTAssertEqual(fields(request(host: "ssh://server")), [.host])
        XCTAssertEqual(fields(request(host: "-oProxyCommand=x")), [.host])
        XCTAssertEqual(fields(request(port: 0)), [.port])
        XCTAssertEqual(fields(request(port: 65_536)), [.port])
        XCTAssertEqual(fields(request(username: "Admin")), [.username])
        XCTAssertEqual(fields(request(username: "-l")), [.username])
        XCTAssertEqual(fields(request(username: String(repeating: "a", count: 33))), [.username])
    }

    func testRootAccountRequiresRootLogin() {
        XCTAssertEqual(fields(request(username: "root", root: false)), [.rootLogin])
        XCTAssertEqual(fields(request(username: "root", root: true)), [])
    }

    func testRejectsBadPasswordsAndKeyPaths() {
        XCTAssertEqual(fields(request(password: "")), [.password])
        XCTAssertEqual(fields(request(password: "a\nb")), [.password])
        XCTAssertEqual(fields(request(keyPath: "relative/key")), [.keyPath])
        XCTAssertEqual(fields(request(keyPath: "/Users/me/.ssh/id.pub")), [.keyPath])
    }

    func testExpandsTildeAndRedactsPassword() {
        let value = request(password: "hunter2", keyPath: "~/.ssh/key")
        XCTAssertFalse(value.keyPath.hasPrefix("~"))
        XCTAssertFalse(value.description.contains("hunter2"))
    }
}

final class RemoteScriptTests: XCTestCase {
    func testShellQuoteSurvivesSingleQuotes() throws {
        let value = "it's $(rm -rf /) `x`"
        let output = try run("/bin/sh", ["-c", "printf '%s' \(RemoteScripts.shellQuote(value))"])
        XCTAssertEqual(output, value)
    }

    func testEveryRemoteScriptIsValidShell() throws {
        let scripts = [
            RemoteScripts.inspectManagedConfig(backupPath: "/etc/ssh/sshd_config.d/.backup"),
            RemoteScripts.activateManagedConfig,
            RemoteScripts.reloadSsh,
            RemoteScripts.snapshotAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: false),
            RemoteScripts.snapshotAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: true),
            RemoteScripts.installPublicKey(root: false),
            RemoteScripts.installPublicKey(root: true),
            RemoteScripts.restoreAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: false),
            RemoteScripts.restoreAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: true),
            RemoteScripts.removeSnapshot(backupPath: "/tmp/ssh-key-deployer-authorized-ab"),
            RemoteScripts.sudoWithPayload("sh -c 'cat'"),
        ]
        for script in scripts {
            XCTAssertTrue(script.hasPrefix("sh -c "))
            // `sh -n -c` parses the inner program without running it.
            _ = try run("/bin/sh", ["-c", "sh -n" + script.dropFirst(2)])
        }
    }

    func testManagedConfigMatchesPolicy() {
        let keyOnly = RemoteScripts.managedConfig(rootLogin: .keyOnly, allowPasswordLogin: false)
        XCTAssertTrue(keyOnly.hasPrefix(RemoteScripts.managedConfigMarker + "\n"))
        XCTAssertTrue(keyOnly.contains("PasswordAuthentication no\n"))
        XCTAssertTrue(keyOnly.contains("PermitRootLogin prohibit-password\n"))
        XCTAssertTrue(RemoteScripts.managedConfig(rootLogin: .disabled, allowPasswordLogin: true)
            .contains("PermitRootLogin no\n"))
    }

    func testEffectiveSettingsVerification() throws {
        let request = DeploymentRequest(
            host: "h", port: 22, username: "deploy", password: "p", keyPath: "/k",
            enableRootLogin: true, allowPasswordLogin: false)
        let good = "pubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\n"
        XCTAssertNoThrow(try SshdSettings.verify(good, request: request, account: "root"))
        let bad = good.replacingOccurrences(of: "passwordauthentication no", with: "passwordauthentication yes")
        XCTAssertThrowsError(try SshdSettings.verify(bad, request: request, account: "deploy"))
    }

    func testClassifiesConnectionFailures() {
        XCTAssertEqual(SSHSession.classifyConnectionFailure("deploy@h: Permission denied (publickey,password).", timedOut: false), .authenticationRejected)
        XCTAssertEqual(SSHSession.classifyConnectionFailure("ssh: connect to host h port 22: Operation timed out", timedOut: false), .connectionTimedOut)
        XCTAssertEqual(SSHSession.classifyConnectionFailure("ssh: connect to host h port 22: Connection refused", timedOut: false), .networkUnavailable)
        XCTAssertEqual(SSHSession.classifyConnectionFailure("Host key verification failed.", timedOut: false), .hostKeyChanged)
    }

    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "\(arguments)")
        return String(decoding: data, as: UTF8.self)
    }
}

final class KeyStoreTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: KeyStore.sshKeygenPath))
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("skd-tests-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    func testGeneratesProtectedPairAndReadsItBack() async throws {
        let path = directory.appendingPathComponent("nested/server_ed25519").path
        let store = KeyStore()

        let generated = try await store.ensureKeyPair(at: path)
        XCTAssertEqual(generated.privateKeyPath, path)
        XCTAssertTrue(generated.publicKey.hasSuffix(" ssh-key-deployer"))

        let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
        let parentMode = try FileManager.default.attributesOfItem(
            atPath: (path as NSString).deletingLastPathComponent)[.posixPermissions] as? NSNumber
        XCTAssertEqual(parentMode?.intValue, 0o700)

        let reread = try await store.ensureKeyPair(at: path)
        XCTAssertEqual(reread, generated)

        // No staging directories are left behind.
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: (path as NSString).deletingLastPathComponent)
        XCTAssertEqual(Set(leftovers), ["server_ed25519", "server_ed25519.pub"])
    }

    func testRefusesOverwriteAndMismatchedPairs() async throws {
        let store = KeyStore()
        let first = directory.appendingPathComponent("a").path
        let second = directory.appendingPathComponent("b").path
        _ = try await store.generate(at: first)
        _ = try await store.generate(at: second)

        do {
            _ = try await store.generate(at: first)
            XCTFail("Existing key was overwritten")
        } catch {}

        // Pair the private key of `a` with the public key of `b`.
        try FileManager.default.removeItem(atPath: first + ".pub")
        try FileManager.default.copyItem(atPath: second + ".pub", toPath: first + ".pub")
        do {
            _ = try await store.readExisting(at: first)
            XCTFail("Mismatched pair was accepted")
        } catch let error as DeploymentError {
            XCTAssertEqual(error.kind, .key)
        }

        // Only one half of a pair present.
        try FileManager.default.removeItem(atPath: second + ".pub")
        do {
            _ = try await store.ensureKeyPair(at: second)
            XCTFail("Half a pair was accepted")
        } catch {}
    }
}
