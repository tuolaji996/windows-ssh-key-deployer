import AppKit
import DeployerCore
import SwiftUI

/// Renders the window content for sample states to PNG files (for CI review), without a
/// visible window or screen-recording permission, then exits.
@MainActor
enum SnapshotRenderer {
    private struct Shot {
        let name: String
        let size: CGSize?
        let makeView: (AppLanguage) -> AnyView
    }

    static func run(outputDirectory: String) -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)

        let directory = URL(fileURLWithPath: outputDirectory, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            FileHandle.standardError.write(Data("Cannot create \(directory.path): \(error)\n".utf8))
            exit(1)
        }

        let window = CGSize(width: 1080, height: 780)
        let shots: [Shot] = [
            Shot(name: "1-empty", size: window) { _ in SnapshotRenderer.mainContent(Samples.emptyModel()) },
            Shot(name: "2-invalid", size: window) { _ in SnapshotRenderer.mainContent(Samples.invalidModel()) },
            Shot(name: "3-deploying", size: window) { _ in SnapshotRenderer.mainContent(Samples.deployingModel()) },
            Shot(name: "3-deploying-minsize", size: SSHKeyDeployerApp.minimumSize) { _ in SnapshotRenderer.mainContent(Samples.deployingModel()) },
            Shot(name: "4-plan-sheet", size: nil) { _ in
                AnyView(PlanSheet(plan: Samples.plan) { _ in }.background(Palette.page))
            },
            Shot(name: "5-hostkey-sheet", size: nil) { _ in
                AnyView(HostKeySheet(hostKey: Samples.hostKey) { _ in }.background(Palette.page))
            },
            Shot(name: "6-success", size: window) { _ in SnapshotRenderer.mainContent(Samples.successModel()) },
            Shot(name: "7-failure", size: window) { _ in SnapshotRenderer.mainContent(Samples.failureModel()) },
        ]

        var written = 0
        for shot in shots {
            for language in AppLanguage.allCases {
                for dark in [false, true] {
                    let name = "\(shot.name)-\(language == .chinese ? "zh" : "en")-\(dark ? "dark" : "light").png"
                    let view = shot.makeView(language).environment(\.appLanguage, language)
                    if render(view, size: shot.size, dark: dark, to: directory.appendingPathComponent(name)) {
                        written += 1
                    } else {
                        FileHandle.standardError.write(Data("Failed to render \(name)\n".utf8))
                    }
                }
            }
        }
        print("Wrote \(written) snapshots to \(directory.path)")
        exit(written == shots.count * 4 ? 0 : 1)
    }

    private static func mainContent(_ model: DeployerViewModel) -> AnyView {
        AnyView(MainWindowContent().environmentObject(model))
    }

    private static func render<V: View>(_ view: V, size: CGSize?, dark: Bool, to url: URL) -> Bool {
        let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        let hosting = NSHostingView(rootView: view)
        hosting.appearance = appearance
        let contentSize = size ?? hosting.fittingSize
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .fullSizeContentView],
            backing: .buffered,
            defer: false)
        window.appearance = appearance
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.contentView = hosting
        hosting.frame = NSRect(origin: .zero, size: contentSize)

        // Let SwiftUI lay out and draw (twice, so late updates such as scroll positions settle).
        for _ in 0..<2 {
            hosting.layoutSubtreeIfNeeded()
            hosting.display()
            RunLoop.main.run(until: Date().addingTimeInterval(0.25))
        }

        guard let bitmap = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return false }
        hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
        guard let data = bitmap.representation(using: .png, properties: [:]) else { return false }
        do {
            try data.write(to: url)
            window.contentView = nil
            window.close()
            return true
        } catch {
            return false
        }
    }
}

/// Sample data for the snapshots (documentation addresses and fake fingerprints only).
@MainActor
enum Samples {
    static let keyPath = NSHomeDirectory() + "/.ssh/id_ed25519"

    static let key = LocalKeyInfo(
        privateKeyPath: keyPath,
        publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample deployer",
        fingerprint: "SHA256:q3Vb8mJ0x1T2nYw9sKcR4uLhZp6dFgE7aQ0iO5yXtNs")

    static let hostKey = HostKeyPrompt(
        host: "203.0.113.10", port: 22, algorithm: "ED25519", keyLength: 256,
        sha256Fingerprint: "SHA256:Zk1m8Qe3VbT0yHn4sJ7cR2uLxP9dFgA6wE5iO0qYtMs",
        md5Fingerprint: "MD5:3a:7f:19:c2:5e:88:0b:d4:61:af:92:3c:e7:14:5b:d0")

    static let server = ServerInfo(
        osID: "rocky", osName: "Rocky Linux 9.4 (Blue Onyx)", osVersion: "9.4", family: .rhel,
        packageManager: .dnf, initSystem: .systemd, privilege: .su, sudoInstalled: false,
        sshdIncludesDropIns: true, selinuxEnforcing: true, firewall: .firewalld,
        socketActivated: false, currentPorts: [22])

    static let plan = DeploymentPlan(server: server, actions: [
        .installPackages(manager: .dnf, packages: ["sudo", "policycoreutils-python-utils"]),
        .temporarySudoViaSu(account: "deploy"),
        .installPublicKey(account: "root"),
        .writeSshdPolicy(rootLogin: .keyOnly, passwordLogin: false),
        .changePort(from: [22], to: 2222),
        .openFirewallPort(.firewalld, port: 2222),
        .labelSelinuxPort(port: 2222),
    ])

    private static func base() -> DeployerViewModel {
        let model = DeployerViewModel(persistent: false)
        model.keyPath = keyPath
        model.touched = []
        return model
    }

    private static func filled(_ model: DeployerViewModel) {
        model.host = "203.0.113.10"
        model.port = "22"
        model.username = "deploy"
        model.password = "correct-horse-battery"
        model.rootPassword = "root-secret"
        model.showRootPassword = true
        model.rootLogin = .keyOnly
        model.changePort = true
        model.newPort = "2222"
        model.keyInfo = key
        model.touched = []
        model.setRecentServers([
            RecentServer(host: "203.0.113.10", port: 22, username: "deploy", keyPath: keyPath, lastUsed: Date()),
        ])
    }

    static func emptyModel() -> DeployerViewModel {
        base()
    }

    static func invalidModel() -> DeployerViewModel {
        let model = base()
        model.host = "https://203.0.113.10"
        model.port = "22a"
        model.username = "Admin"
        model.password = ""
        model.rootLogin = .disabled
        model.changePort = true
        model.newPort = "70000"
        model.touched = Set(FormField.allCases)
        return model
    }

    private static func log(_ model: DeployerViewModel, _ lines: [(String, String, Bool)]) {
        let start = Date(timeIntervalSince1970: 1_764_072_000)
        for (index, line) in lines.enumerated() {
            model.append(.init(line.0, line.1), isError: line.2, time: start.addingTimeInterval(Double(index * 3)))
        }
    }

    private static let earlyLog: [(String, String, Bool)] = [
        ("开始部署到 deploy@203.0.113.10:22", "Deploying to deploy@203.0.113.10:22", false),
        ("使用密钥 \(key.fingerprint)", "Using key \(key.fingerprint)", false),
        ("已批准主机指纹。", "Host key approved.", false),
        ("检测到 Rocky Linux 9.4 (Blue Onyx)，等待确认变更计划。", "Detected Rocky Linux 9.4 (Blue Onyx); waiting for plan approval.", false),
        ("已批准变更计划。", "Plan approved.", false),
        ("已通过 dnf 安装 sudo、policycoreutils-python-utils。", "Installed sudo, policycoreutils-python-utils with dnf.", false),
    ]

    static func deployingModel() -> DeployerViewModel {
        let model = base()
        filled(model)
        model.isBusy = true
        model.phase = .deploying
        model.runIncludesPortChange = true
        log(model, earlyLog + [("正在写入 SSH 策略…", "Writing the SSH policy...", false)])
        model.apply(stage: .writingSshdConfiguration,
                    message: "Writing /etc/ssh/sshd_config.d/10-ssh-key-deployer.conf...", percent: 52)
        return model
    }

    static func successModel() -> DeployerViewModel {
        let model = base()
        filled(model)
        model.password = ""
        model.rootPassword = ""
        model.changePort = false
        model.port = "2222"
        model.touched = []
        model.runIncludesPortChange = true
        model.phase = .succeeded
        for step in model.visibleSteps { model.stepStates[step] = .done }
        model.setStatus(.init("部署成功，密钥登录已验证。", "Deployment succeeded and key login was verified."), progress: 1)
        log(model, earlyLog + [
            ("SSH 已改用端口 2222，旧端口 22 已关闭。", "SSH moved to port 2222; port 22 is closed.", false),
            ("已验证 root 的密钥登录（端口 2222）。", "Key login verified for root on port 2222.", false),
        ])
        model.result = ResultSummary(
            host: "203.0.113.10", username: "root", keyPath: keyPath, sshPort: 2222, previousPort: 22,
            osName: server.osName, rootLogin: .keyOnly, passwordLogin: false)
        return model
    }

    static func failureModel() -> DeployerViewModel {
        let model = base()
        filled(model)
        model.password = ""
        model.rootPassword = ""
        model.touched = []
        model.runIncludesPortChange = true
        model.stepStates = [.localKey: .done, .hostKey: .done, .inspect: .done, .privileges: .failed]
        let error = DeploymentError(
            .rootPasswordRejected,
            "Deployment failed: su: Authentication failure. Server changes were rolled back.",
            rollback: .succeeded)
        let failure = FailureSummary(error)
        model.failure = failure
        model.phase = .failed
        model.setStatus(failure.title, progress: 0)
        log(model, Array(earlyLog.prefix(5)) + [(error.localized.chinese, error.localized.english, true)])
        return model
    }
}
