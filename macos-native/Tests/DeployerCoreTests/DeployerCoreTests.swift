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

    func testRootPasswordAndNewPort() {
        func make(rootPassword: String? = nil, newPort: Int? = nil) -> DeploymentRequest {
            DeploymentRequest(
                host: "h.example", port: 22, username: "deploy", password: "secret",
                keyPath: "/Users/me/.ssh/id_test", enableRootLogin: false, allowPasswordLogin: true,
                rootPassword: rootPassword, newSSHPort: newPort)
        }
        XCTAssertEqual(fields(make(rootPassword: "r00t", newPort: 2222)), [])
        XCTAssertNil(make(rootPassword: "").rootPassword)
        XCTAssertEqual(fields(make(rootPassword: "a\nb")), [.rootPassword])
        XCTAssertEqual(fields(make(newPort: 0)), [.newSSHPort])
        XCTAssertEqual(fields(make(newPort: 65_536)), [.newSSHPort])
        XCTAssertEqual(fields(make(newPort: 22)), [.newSSHPort])
        let request = make(rootPassword: "toor-secret")
        XCTAssertFalse(request.description.contains("toor-secret"))
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

    /// Every script must parse with the system sh and, where installed, dash (Debian's
    /// /bin/sh); BusyBox ash is checked by the remote E2E tests.
    func testEveryRemoteScriptIsValidShell() throws {
        var scripts: [String] = [
            RemoteScripts.inspectManagedConfig(backupPath: "/etc/ssh/sshd_config.d/.backup"),
            RemoteScripts.activateManagedConfig,
            RemoteScripts.restoreManagedConfig(originalExisted: true, backupPath: "/etc/ssh/sshd_config.d/.backup"),
            RemoteScripts.reloadSshd(),
            RemoteScripts.reloadSshd(restartSocket: true),
            RemoteScripts.inspectServer,
            RemoteScripts.inspectServerAsRoot,
            RemoteScripts.createTemporarySudoers(path: RemoteScripts.temporarySudoersPrefix + "0123abcd", username: "deploy"),
            RemoteScripts.removeTemporarySudoers(path: RemoteScripts.temporarySudoersPrefix + "0123abcd"),
            RemoteScripts.selinuxPortTypes(2222),
            RemoteScripts.selinuxAddSshPort(2222),
            RemoteScripts.selinuxRemoveSshPort(2222),
            RemoteScripts.ufwAllow(2222),
            RemoteScripts.ufwDelete(2222),
            RemoteScripts.firewalldQuery(2222),
            RemoteScripts.firewalld(add: true, permanent: true, 2222),
            RemoteScripts.firewalld(add: false, permanent: false, 2222),
        ]
        let managers: [PackageManager] = [.apt, .dnf, .yum, .zypper, .pacman, .apk]
        for manager in managers {
            scripts.append(RemoteScripts.installPackages(manager, ["sudo", "policycoreutils-python-utils"]))
        }
        scripts += [
            RemoteScripts.snapshotAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: false),
            RemoteScripts.snapshotAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: true),
            RemoteScripts.installPublicKey(root: false),
            RemoteScripts.installPublicKey(root: true),
            RemoteScripts.restoreAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: false),
            RemoteScripts.restoreAuthorizedKeys(backupPath: "/tmp/ssh-key-deployer-authorized-ab", root: true),
            RemoteScripts.removeSnapshot(backupPath: "/tmp/ssh-key-deployer-authorized-ab"),
            RemoteScripts.sudoWithPayload("sh -c 'cat'"),
        ]
        let shells = ["sh", "/bin/dash"].filter { $0 == "sh" || FileManager.default.isExecutableFile(atPath: $0) }
        for script in scripts {
            XCTAssertTrue(script.hasPrefix("sh -c "))
            // `sh -n -c` parses the inner program without running it.
            for shell in shells {
                _ = try run("/bin/sh", ["-c", "\(shell) -n" + script.dropFirst(2)])
            }
        }
    }

    func testSuWrapperQuotesTheScriptAndCarriesNoSecret() throws {
        let inner = RemoteScripts.inspectServerAsRoot
        let command = RemoteScripts.su(inner)
        XCTAssertTrue(command.hasPrefix("env LC_ALL=C su root -c '"))
        // The outer command line parses, and the root shell's argument is the marker plus the script.
        _ = try run("/bin/sh", ["-n", "-c", command])
        let argument = try run("/bin/sh", ["-c", command.replacingOccurrences(of: "env LC_ALL=C su root -c ", with: "printf '%s' ")])
        XCTAssertEqual(argument, "printf '%s\\n' \(RemoteScripts.suStartMarker) && \(inner)")
        _ = try run("/bin/sh", ["-n", "-c", argument])
    }

    func testUnprivilegedProbeRunsLocally() throws {
        // The probe is read-only; on the CI Mac it has no os-release but must report the uid.
        let output = try run("/bin/sh", ["-c", RemoteScripts.inspectServer])
        let probe = ServerInspection.parseProbe(output)
        XCTAssertEqual(probe.uid, Int(getuid()))
        XCTAssertTrue(probe.tools.contains("su"))
    }

    func testManagedConfigPorts() {
        let base = RemoteScripts.managedConfig(rootLogin: .keyOnly, allowPasswordLogin: false)
        XCTAssertFalse(base.contains("Port "))
        let transition = RemoteScripts.managedConfig(rootLogin: .keyOnly, allowPasswordLogin: false, ports: [22, 2222, 22, 0, 70_000])
        XCTAssertTrue(transition.hasPrefix(base))
        XCTAssertTrue(transition.hasSuffix("\nPort 22\nPort 2222\n"))
        XCTAssertEqual(transition.components(separatedBy: "Port ").count - 1, 2)
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

final class ServerInspectionTests: XCTestCase {
    private func request(
        username: String = "deploy",
        root: Bool = false,
        rootPassword: String? = nil,
        newPort: Int? = nil
    ) -> DeploymentRequest {
        DeploymentRequest(
            host: "h.example", port: 22, username: username, password: "account-pw",
            keyPath: "/k", enableRootLogin: root, allowPasswordLogin: false,
            rootPassword: rootPassword, newSSHPort: newPort)
    }

    private func server(
        family: LinuxFamily = .rhel,
        manager: PackageManager? = .dnf,
        privilege: PrivilegeMode = .sudo,
        sudoInstalled: Bool = true,
        selinux: Bool = false,
        firewall: Firewall? = nil,
        ports: [Int] = [22]
    ) -> ServerInfo {
        ServerInfo(
            osID: "rocky", osName: "Rocky Linux 9.4", osVersion: "9.4", family: family,
            packageManager: manager, initSystem: .systemd, privilege: privilege,
            sudoInstalled: sudoInstalled, sshdIncludesDropIns: true, selinuxEnforcing: selinux,
            firewall: firewall, socketActivated: false, currentPorts: ports)
    }

    func testParsesProbeAndOsRelease() {
        let output = """
        UID=1000
        OS_NAME="Rocky Linux"
        OS_ID="rocky"
        OS_ID_LIKE="rhel centos fedora"
        OS_PRETTY_NAME="Rocky Linux 9.4 (Blue \\"Onyx\\")"
        OS_VERSION_ID='9.4'
        HAS=sudo
        HAS=su
        HAS=dnf
        HAS=yum
        INIT=systemd
        noise without equals
        """
        let probe = ServerInspection.parseProbe(output)
        XCTAssertEqual(probe.uid, 1000)
        XCTAssertEqual(probe.osID, "rocky")
        XCTAssertEqual(probe.osName, "Rocky Linux 9.4 (Blue \"Onyx\")")
        XCTAssertEqual(probe.osVersion, "9.4")
        XCTAssertEqual(probe.family, .rhel)
        XCTAssertEqual(probe.packageManager, .dnf)
        XCTAssertEqual(probe.initSystem, .systemd)
        XCTAssertEqual(probe.tools, ["sudo", "su", "dnf", "yum"])
    }

    func testFamilyMapping() {
        XCTAssertEqual(ServerInspection.family(id: "debian", idLike: ""), .debian)
        XCTAssertEqual(ServerInspection.family(id: "ubuntu", idLike: "debian"), .debian)
        XCTAssertEqual(ServerInspection.family(id: "linuxmint", idLike: "ubuntu debian"), .debian)
        XCTAssertEqual(ServerInspection.family(id: "fedora", idLike: ""), .rhel)
        XCTAssertEqual(ServerInspection.family(id: "almalinux", idLike: "rhel centos fedora"), .rhel)
        XCTAssertEqual(ServerInspection.family(id: "opensuse-tumbleweed", idLike: "opensuse suse"), .suse)
        XCTAssertEqual(ServerInspection.family(id: "opensuse-leap", idLike: "suse opensuse"), .suse)
        XCTAssertEqual(ServerInspection.family(id: "sles", idLike: ""), .suse)
        XCTAssertEqual(ServerInspection.family(id: "arch", idLike: ""), .arch)
        XCTAssertEqual(ServerInspection.family(id: "manjaro", idLike: "arch"), .arch)
        XCTAssertEqual(ServerInspection.family(id: "alpine", idLike: ""), .alpine)
        XCTAssertEqual(ServerInspection.family(id: "something", idLike: "fedora"), .rhel)
        XCTAssertEqual(ServerInspection.family(id: "nixos", idLike: ""), .unknown)
    }

    func testPackageManagerSelection() {
        XCTAssertEqual(ServerInspection.packageManager(family: .rhel, tools: ["yum"]), .yum)
        XCTAssertEqual(ServerInspection.packageManager(family: .rhel, tools: ["yum", "dnf"]), .dnf)
        XCTAssertEqual(ServerInspection.packageManager(family: .debian, tools: ["apt-get"]), .apt)
        XCTAssertEqual(ServerInspection.packageManager(family: .unknown, tools: ["apk"]), .apk)
        XCTAssertNil(ServerInspection.packageManager(family: .arch, tools: []))
        XCTAssertEqual(ServerInspection.semanagePackage(.dnf), "policycoreutils-python-utils")
        XCTAssertNil(ServerInspection.semanagePackage(.apk))
    }

    func testParsesRootProbe() {
        let output = """
        SSHD=yes
        PORT=22
        PORT=2200
        MAIN_CONFIG=/usr/etc/ssh/sshd_config
        INCLUDE=/etc/ssh/sshd_config.d/*.conf
        MAIN_PORT=22
        MANAGED_PORT=2200
        SELINUX=Enforcing
        FIREWALL=firewalld
        SOCKET=active
        """
        let probe = ServerInspection.parseRootProbe(output)
        XCTAssertTrue(probe.sshdPresent)
        XCTAssertEqual(probe.ports, [22, 2200])
        XCTAssertEqual(probe.mainConfig, "/usr/etc/ssh/sshd_config")
        XCTAssertEqual(probe.mainPorts, [22])
        XCTAssertEqual(probe.managedPorts, [2200])
        XCTAssertTrue(probe.selinuxEnforcing)
        XCTAssertEqual(probe.firewall, .firewalld)
        XCTAssertTrue(probe.socketActivated)
        XCTAssertTrue(ServerInspection.includesManagedDropIn(probe.includes))

        let bare = ServerInspection.parseRootProbe("SSHD=yes\nSSHD_T_ERROR=no hostkeys available\nMAIN_CONFIG=\nSELINUX=Permissive\n")
        XCTAssertTrue(bare.ports.isEmpty)
        XCTAssertNil(bare.mainConfig)
        XCTAssertFalse(bare.selinuxEnforcing)
        XCTAssertNil(bare.firewall)
        XCTAssertEqual(ServerInspection.sshdPorts("port 22\nport 2222\naddressfamily any\n"), [22, 2222])
    }

    func testIncludeDetection() {
        XCTAssertTrue(ServerInspection.includesManagedDropIn(["/etc/ssh/sshd_config.d/*.conf"]))
        XCTAssertTrue(ServerInspection.includesManagedDropIn(["sshd_config.d/*.conf"]))
        XCTAssertTrue(ServerInspection.includesManagedDropIn(["\"/etc/ssh/sshd_config.d/*.conf\""]))
        XCTAssertTrue(ServerInspection.includesManagedDropIn(["/usr/etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config.d/*"]))
        XCTAssertFalse(ServerInspection.includesManagedDropIn([]))
        XCTAssertFalse(ServerInspection.includesManagedDropIn(["/usr/etc/ssh/sshd_config.d/*.conf"]))
        XCTAssertFalse(ServerInspection.includesManagedDropIn(["/etc/ssh/sshd_config.d/50-*.conf"]))
        XCTAssertFalse(ServerInspection.includesManagedDropIn(["/etc/ssh/*.conf"]))
        let message = ServerInspection.missingIncludeMessage(mainConfig: "/etc/ssh/sshd_config")
        XCTAssertTrue(message.contains("\nInclude /etc/ssh/sshd_config.d/*.conf\n"))
        XCTAssertTrue(ServerInspection.missingIncludeMessage(mainConfig: "/usr/etc/ssh/sshd_config").contains("copy /usr/etc/ssh/sshd_config"))
    }

    func testSudoClassification() {
        XCTAssertEqual(ServerInspection.classifySudo(status: 0, diagnostic: ""), .ok)
        XCTAssertEqual(ServerInspection.classifySudo(status: 1, diagnostic: "deploy is not in the sudoers file."), .notAuthorized)
        XCTAssertEqual(ServerInspection.classifySudo(status: 1, diagnostic: "sudo: I'm sorry deploy. I'm afraid I can't do that"), .notAuthorized)
        XCTAssertEqual(ServerInspection.classifySudo(status: 127, diagnostic: "sh: sudo: not found"), .unavailable)
        XCTAssertEqual(ServerInspection.classifySudo(status: 1, diagnostic: "sudo: 3 incorrect password attempts"), .passwordRejected)
        XCTAssertEqual(ServerInspection.classifySudo(status: 1, diagnostic: "sudo: Authentication failed, try again."), .passwordRejected)
        XCTAssertEqual(ServerInspection.classifySudo(status: 1, diagnostic: "weird"), .other)
    }

    func testPrivilegeDecision() {
        typealias I = ServerInspection
        XCTAssertEqual(I.decidePrivilege(uid: 0, sudo: nil, rootPasswordGiven: false, suInstalled: true), .use(.root))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .ok, rootPasswordGiven: true, suInstalled: true), .use(.sudo))
        // openSUSE targetpw: the account password is rejected, the root password works through su.
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .passwordRejected, rootPasswordGiven: true, suInstalled: true), .use(.su))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .unavailable, rootPasswordGiven: true, suInstalled: true), .use(.su))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .notAuthorized, rootPasswordGiven: true, suInstalled: false), .fail(.suUnavailable))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .notAuthorized, rootPasswordGiven: false, suInstalled: true), .fail(.noPrivilege))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .unavailable, rootPasswordGiven: false, suInstalled: true), .fail(.noPrivilege))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .notAuthorized, rootPasswordGiven: false, suInstalled: false), .fail(.sudoNotAuthorized))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .unavailable, rootPasswordGiven: false, suInstalled: false), .fail(.sudoUnavailable))
        XCTAssertEqual(I.decidePrivilege(uid: 1000, sudo: .passwordRejected, rootPasswordGiven: false, suInstalled: true), .fail(.sudoPasswordRejected))
    }

    func testPrivilegeMessagesAreDistroSpecific() {
        func message(_ family: LinuxFamily, sudo: Bool = true, kind: DeploymentError.Kind = .noPrivilege) -> String {
            ServerInspection.privilegeError(kind, family: family, osName: "X", username: "deploy", sudoInstalled: sudo, diagnostic: "").message
        }
        XCTAssertTrue(message(.debian).contains("usermod -aG sudo deploy"))
        XCTAssertTrue(message(.debian, sudo: false).contains("apt-get install -y sudo"))
        XCTAssertTrue(message(.rhel).contains("usermod -aG wheel deploy"))
        XCTAssertTrue(message(.rhel, sudo: false).contains("dnf install -y sudo"))
        XCTAssertTrue(message(.suse).contains("targetpw"))
        XCTAssertTrue(message(.suse, sudo: false).contains("zypper"))
        XCTAssertTrue(message(.arch).contains("visudo"))
        XCTAssertTrue(message(.arch, sudo: false).contains("pacman -S --needed sudo"))
        XCTAssertTrue(message(.alpine, sudo: false).contains("apk add sudo && adduser deploy wheel"))
        XCTAssertTrue(message(.alpine).contains("/etc/sudoers.d/wheel"))
        XCTAssertTrue(message(.debian).contains("root password"))
        XCTAssertFalse(message(.debian, kind: .sudoNotAuthorized).contains("Alternatively"))
        XCTAssertTrue(message(.suse, kind: .sudoPasswordRejected).contains("targetpw"))
    }

    func testSuErrorClassification() {
        XCTAssertEqual(ServerInspection.suError(output: "Password: su: Authentication failure", promptAnswered: true).kind, .rootPasswordRejected)
        XCTAssertEqual(ServerInspection.suError(output: "Password: su: incorrect password", promptAnswered: true).kind, .rootPasswordRejected)
        XCTAssertEqual(ServerInspection.suError(output: "Password: su: Permission denied", promptAnswered: true).kind, .suUnavailable)
        XCTAssertEqual(ServerInspection.suError(output: "su: must be suid to work properly", promptAnswered: false).kind, .suUnavailable)
        XCTAssertEqual(ServerInspection.suError(output: "You are required to change your password immediately", promptAnswered: true).kind, .rootPasswordRejected)
    }

    func testPortHelpers() {
        XCTAssertNil(ServerInspection.portToChange(current: [22], requested: nil))
        XCTAssertNil(ServerInspection.portToChange(current: [2222], requested: 2222))
        XCTAssertEqual(ServerInspection.portToChange(current: [22], requested: 2222), 2222)
        XCTAssertEqual(ServerInspection.portToChange(current: [22, 2222], requested: 2222), 2222)
        XCTAssertEqual(ServerInspection.transitionPorts(current: [22], mainPorts: [], newPort: 2222), [22, 2222])
        // A port pinned by the main config stays open by itself; repeating it would bind twice.
        XCTAssertEqual(ServerInspection.transitionPorts(current: [22, 2200], mainPorts: [22], newPort: 2222), [2200, 2222])
        XCTAssertEqual(ServerInspection.transitionPorts(current: [2222, 22], mainPorts: [], newPort: 2222), [2222, 22])
        XCTAssertTrue(ServerInspection.ufwAddedRule("Rule added\nRule added (v6)"))
        XCTAssertFalse(ServerInspection.ufwAddedRule("Skipping adding existing rule\nSkipping adding existing rule (v6)"))
        XCTAssertEqual(ServerInspection.values("TYPE", in: "TYPE=ssh_port_t\nTYPE= http_port_t\nX=1"), ["ssh_port_t", "http_port_t"])
    }

    func testPlanForSudoWithoutPortChange() throws {
        let plan = try ServerInspection.buildPlan(server: server(), request: request(), semanageInstalled: false)
        XCTAssertEqual(plan.actions, [
            .installPublicKey(account: "deploy"),
            .writeSshdPolicy(rootLogin: .disabled, passwordLogin: false),
        ])
    }

    func testPlanForSuWithPortChangeOnSelinux() throws {
        let info = server(privilege: .su, sudoInstalled: false, selinux: true, firewall: .firewalld)
        let plan = try ServerInspection.buildPlan(
            server: info,
            request: request(root: true, rootPassword: "toor", newPort: 2222),
            semanageInstalled: false)
        XCTAssertEqual(plan.server, info)
        XCTAssertEqual(plan.actions, [
            .installPackages(manager: .dnf, packages: ["sudo", "policycoreutils-python-utils"]),
            .temporarySudoViaSu(account: "deploy"),
            .installPublicKey(account: "deploy"),
            .installPublicKey(account: "root"),
            .writeSshdPolicy(rootLogin: .keyOnly, passwordLogin: false),
            .changePort(from: [22], to: 2222),
            .openFirewallPort(.firewalld, port: 2222),
            .labelSelinuxPort(port: 2222),
        ])
    }

    func testPlanSkipsInstalledToolsAndRejectsImpossibleOnes() throws {
        let withSemanage = try ServerInspection.buildPlan(
            server: server(selinux: true),
            request: request(newPort: 2222),
            semanageInstalled: true)
        XCTAssertFalse(withSemanage.actions.contains { if case .installPackages = $0 { return true } else { return false } })

        XCTAssertThrowsError(try ServerInspection.buildPlan(
            server: server(manager: nil, privilege: .su, sudoInstalled: false),
            request: request(rootPassword: "toor"),
            semanageInstalled: false)) { error in
            XCTAssertEqual((error as? DeploymentError)?.kind, .unsupportedServer)
        }
        XCTAssertThrowsError(try ServerInspection.buildPlan(
            server: server(family: .alpine, manager: .apk, selinux: true),
            request: request(newPort: 2222),
            semanageInstalled: false))
    }

    func testRedactsBothPasswords() {
        let text = "sudo said account-pw and su said toor-pw-long and toor"
        let redacted = SSHSession.redact(text, secrets: ["account-pw", "toor-pw-long", ""])
        XCTAssertFalse(redacted.contains("account-pw"))
        XCTAssertFalse(redacted.contains("toor-pw-long"))
        // Longest first: a secret that contains another is never partially revealed.
        XCTAssertEqual(SSHSession.redact("abcdef", secrets: ["abc", "abcdef"]), "[redacted]")
    }

    func testSessionRedactsRootPassword() throws {
        let session = try SSHSession(host: "h", port: 22, username: "u", password: "account-pw", rootPassword: "toor-pw")
        XCTAssertEqual(session.redact("x account-pw y toor-pw z"), "x [redacted] y [redacted] z")
    }
}

final class TerminalPrompterTests: XCTestCase {
    private let marker = RemoteScripts.suStartMarker

    func testAnswersOnceAfterPromptAndSplitsOutput() {
        var prompter = TerminalPrompter(startMarker: marker)
        XCTAssertEqual(prompter.feed(Data("Pass".utf8)), .none)
        XCTAssertEqual(prompter.feed(Data("word: ".utf8)), .answer)
        XCTAssertEqual(prompter.feed(Data("\r\n".utf8)), .none)
        XCTAssertEqual(prompter.feed(Data("\(marker)\r\nPORT=22\r\npassword: not a prompt\r\n".utf8)), .none)
        XCTAssertTrue(prompter.started)
        XCTAssertTrue(prompter.promptAnswered)
        XCTAssertEqual(prompter.beforeStart, "Password: \n")
        XCTAssertEqual(prompter.afterStart, "PORT=22\npassword: not a prompt\n")
    }

    func testNeverAnswersWithoutPromptOrAfterMarker() {
        var prompter = TerminalPrompter(startMarker: marker)
        XCTAssertEqual(prompter.feed(Data("\(marker)\nPassword: \n".utf8)), .none)
        XCTAssertFalse(prompter.promptAnswered)
    }

    func testAbortsOnSecondPrompt() {
        var prompter = TerminalPrompter(startMarker: marker)
        XCTAssertEqual(prompter.feed(Data("Password: ".utf8)), .answer)
        XCTAssertEqual(prompter.feed(Data("\nYou are required to change your password immediately\nCurrent password: ".utf8)), .abort)
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
