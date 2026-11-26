import DeployerCore
import Foundation

/// Headless driver for the deployment core, used by macos-native/e2e/run.sh.
///
/// Approves the host key and the plan automatically, prints the plan, and writes one
/// JSON result object to standard output. Passwords are read from environment
/// variables only, never from the command line.
///
/// Exit status: 0 when the outcome matched expectations (success, or the failure kind
/// named by --expect-failure), 1 otherwise, 2 for usage errors.
@main
struct DeployerE2E {
    static let usage = """
        usage: deployer-e2e --host HOST --port PORT --user USER --password-env VAR
                            --key PATH [--root-password-env VAR]
                            [--root-login off|key|keypass] [--password-login on|off]
                            [--new-port N] [--expect-failure KIND]

          --root-login key      root may log in with the key only (requires --password-login off)
          --root-login keypass  root may log in with key or password (requires --password-login on)
          --key PATH            private key; an Ed25519 pair is generated when neither file exists
          --expect-failure KIND exit 0 only if deployment fails with DeploymentError.Kind KIND
        """

    struct Options {
        var host = ""
        var port = 22
        var user = ""
        var passwordEnv = ""
        var rootPasswordEnv: String?
        var key = ""
        var rootLogin = "off"
        var passwordLogin = "on"
        var newPort: Int?
        var expectFailure: String?
    }

    static func main() async {
        let options: Options
        do {
            options = try parse(Array(CommandLine.arguments.dropFirst()))
        } catch {
            fail(usage: "\(error)")
        }
        exit(await run(options))
    }

    static func run(_ options: Options) async -> Int32 {
        let environment = ProcessInfo.processInfo.environment
        guard let password = environment[options.passwordEnv], !password.isEmpty else {
            fail(usage: "environment variable \(options.passwordEnv) is not set")
        }
        var rootPassword: String?
        if let name = options.rootPasswordEnv {
            guard let value = environment[name], !value.isEmpty else {
                fail(usage: "environment variable \(name) is not set")
            }
            rootPassword = value
        }

        let keyPath = DeploymentRequest.expandPath(options.key)
        do {
            let pair = try await KeyStore().ensureKeyPair(at: keyPath)
            log("key pair ready: \(pair.privateKeyPath) \(pair.sha256Fingerprint)")
        } catch {
            log("key pair could not be prepared: \(error.localizedDescription)")
            emit(["outcome": "error", "stage": "key", "message": error.localizedDescription])
            return 1
        }

        let request = DeploymentRequest(
            host: options.host,
            port: options.port,
            username: options.user,
            password: password,
            keyPath: keyPath,
            enableRootLogin: options.rootLogin != "off",
            allowPasswordLogin: options.passwordLogin == "on",
            rootPassword: rootPassword,
            newSSHPort: options.newPort)
        log("request: \(request)")

        let approvedHostKey = HostKeyBox()
        do {
            let result = try await DeploymentService().deploy(
                request,
                approveHostKey: { key in
                    approvedHostKey.value = key
                    DeployerE2E.log("approving host key \(key.algorithm) \(key.sha256Fingerprint) \(key.md5Fingerprint)")
                    return true
                },
                approvePlan: { plan in
                    DeployerE2E.log("plan for \(plan.server.osName) (privilege: \(plan.server.privilege.rawValue)):")
                    for action in plan.actions { DeployerE2E.log("  - \(action)") }
                    if plan.actions.isEmpty { DeployerE2E.log("  (no actions)") }
                    return true
                },
                progress: { progress in
                    let percent = String(progress.percent)
                    let padded = String(repeating: " ", count: max(0, 3 - percent.count)) + percent
                    DeployerE2E.log("[\(padded)%] \(progress.stage): \(progress.message)")
                })

            var json: [String: Any] = [
                "outcome": "success",
                "verifiedUsername": result.verifiedUsername,
                "sshPort": result.sshPort,
                "publicKeyFingerprint": result.publicKeyFingerprint,
                "managedConfigPath": result.managedConfigPath,
                "rootLoginPolicy": "\(result.rootLoginPolicy)",
                "passwordLoginAllowed": result.passwordLoginAllowed,
                "warnings": result.warnings,
                "hostKey": hostKeyJSON(result.approvedHostKey),
            ]
            json["server"] = orNull(result.server.map { serverJSON($0) })
            emit(json)

            if let expected = options.expectFailure {
                log("UNEXPECTED: deployment succeeded, but failure kind \(expected) was expected")
                return 1
            }
            return 0
        } catch let error as DeploymentError {
            let kind = "\(error.kind)"
            var json: [String: Any] = [
                "outcome": "failure",
                "kind": kind,
                "message": error.message,
                "rollback": "\(error.rollback)",
            ]
            json["hostKey"] = orNull(approvedHostKey.value.map { hostKeyJSON($0) })
            emit(json)
            log("deployment failed (\(kind)): \(error.message)")
            if options.expectFailure == kind { return 0 }
            log("UNEXPECTED: " + (options.expectFailure.map { "expected failure kind \($0), got \(kind)" } ?? "deployment failed"))
            return 1
        } catch {
            emit(["outcome": "failure", "kind": "unclassified", "message": "\(error)"])
            log("UNEXPECTED: deployment failed with a non-DeploymentError: \(error)")
            return 1
        }
    }

    // MARK: - Arguments

    struct UsageError: Error, CustomStringConvertible {
        let description: String
    }

    static func parse(_ arguments: [String]) throws -> Options {
        var options = Options()
        var index = 0
        func value(_ flag: String) throws -> String {
            index += 1
            guard index < arguments.count else { throw UsageError(description: "\(flag) needs a value") }
            return arguments[index]
        }
        func number(_ flag: String) throws -> Int {
            let text = try value(flag)
            guard let parsed = Int(text) else { throw UsageError(description: "\(flag) must be a number, got \(text)") }
            return parsed
        }

        while index < arguments.count {
            let flag = arguments[index]
            switch flag {
            case "--host": options.host = try value(flag)
            case "--port": options.port = try number(flag)
            case "--user": options.user = try value(flag)
            case "--password-env": options.passwordEnv = try value(flag)
            case "--root-password-env": options.rootPasswordEnv = try value(flag)
            case "--key": options.key = try value(flag)
            case "--root-login": options.rootLogin = try value(flag)
            case "--password-login": options.passwordLogin = try value(flag)
            case "--new-port": options.newPort = try number(flag)
            case "--expect-failure": options.expectFailure = try value(flag)
            case "-h", "--help":
                print(usage)
                exit(0)
            default:
                throw UsageError(description: "unknown argument \(flag)")
            }
            index += 1
        }

        if options.host.isEmpty || options.user.isEmpty || options.passwordEnv.isEmpty || options.key.isEmpty {
            throw UsageError(description: "--host, --user, --password-env and --key are required")
        }
        guard ["off", "key", "keypass"].contains(options.rootLogin) else {
            throw UsageError(description: "--root-login must be off, key or keypass")
        }
        guard ["on", "off"].contains(options.passwordLogin) else {
            throw UsageError(description: "--password-login must be on or off")
        }
        // The core derives the root policy from both switches: root may use a password
        // exactly when password login is allowed in general.
        if options.rootLogin == "key" && options.passwordLogin == "on" {
            throw UsageError(description: "--root-login key requires --password-login off (use keypass)")
        }
        if options.rootLogin == "keypass" && options.passwordLogin == "off" {
            throw UsageError(description: "--root-login keypass requires --password-login on (use key)")
        }
        return options
    }

    // MARK: - Output

    static func serverJSON(_ server: ServerInfo) -> [String: Any] {
        [
            "osID": server.osID,
            "osName": server.osName,
            "osVersion": server.osVersion,
            "family": server.family.rawValue,
            "packageManager": orNull(server.packageManager?.rawValue),
            "initSystem": server.initSystem.rawValue,
            "privilege": server.privilege.rawValue,
            "sudoInstalled": server.sudoInstalled,
            "sshdIncludesDropIns": server.sshdIncludesDropIns,
            "selinuxEnforcing": server.selinuxEnforcing,
            "firewall": orNull(server.firewall?.rawValue),
            "socketActivated": server.socketActivated,
            "currentPorts": server.currentPorts,
        ]
    }

    static func hostKeyJSON(_ key: HostKeyInfo) -> [String: Any] {
        [
            "algorithm": key.algorithm,
            "keyLength": key.keyLength,
            "sha256Fingerprint": key.sha256Fingerprint,
            "md5Fingerprint": key.md5Fingerprint,
        ]
    }

    static func orNull(_ value: Any?) -> Any { value ?? NSNull() }

    static func emit(_ object: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else {
            print("{\"outcome\":\"error\",\"message\":\"result could not be encoded\"}")
            return
        }
        print(String(decoding: data, as: UTF8.self))
    }

    static func log(_ message: String) {
        FileHandle.standardError.write(Data(("[deployer-e2e] " + message + "\n").utf8))
    }

    static func fail(usage message: String) -> Never {
        log(message)
        FileHandle.standardError.write(Data((usage + "\n").utf8))
        exit(2)
    }
}

/// Remembers the approved host key so failures can still report its fingerprints.
final class HostKeyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: HostKeyInfo?

    var value: HostKeyInfo? {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}
