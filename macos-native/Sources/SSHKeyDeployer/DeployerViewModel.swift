import AppKit
import Combine
import DeployerCore
import Foundation

struct LogEntry: Identifiable {
    let id = UUID()
    let time = Date()
    let text: LocalizedText
    let isError: Bool
}

@MainActor
final class DeployerViewModel: ObservableObject {
    // Form
    @Published var host = ""
    @Published var port = "22"
    @Published var username = "root"
    @Published var password = ""
    @Published var keyPath = KeyStore.defaultKeyPath
    @Published var enableRootLogin = true
    @Published var allowPasswordLogin = true

    // State
    @Published private(set) var isBusy = false
    @Published private(set) var isDeploying = false
    @Published private(set) var progress = 0.0
    @Published private(set) var status = LocalizedText("等待开始。", "Waiting to start.")
    @Published private(set) var stepStates: [DeploymentStep: StepState] = [:]
    @Published private(set) var log: [LogEntry] = []
    @Published private(set) var keyInfo: KeyPairInfo?
    @Published var pendingHostKey: HostKeyInfo?

    private let keyStore = KeyStore()
    private let deploymentService = DeploymentService()
    private var deployTask: Task<Void, Never>?
    private var hostKeyContinuation: CheckedContinuation<Bool, Never>?
    private var terminationRequested = false

    init() {
        Task { await refreshKeyInfo() }
    }

    var canDeploy: Bool {
        !isBusy && !host.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    // MARK: - Key actions

    func generateOrLoadKey() {
        guard !isBusy else { return }
        isBusy = true
        setStatus(.init("正在准备 Ed25519 密钥…", "Preparing the Ed25519 key..."), progress: 0.1)
        Task {
            defer { isBusy = false }
            do {
                let info = try await keyStore.ensureKeyPair(at: keyPath)
                keyInfo = info
                setStatus(.init("密钥已就绪。", "Key is ready."), progress: 1)
                append(.init("密钥：\(info.privateKeyPath)（\(info.sha256Fingerprint)）",
                             "Key: \(info.privateKeyPath) (\(info.sha256Fingerprint))"))
            } catch {
                setStatus(.init("密钥准备失败。", "Key preparation failed."), progress: 0)
                append(describe(error), isError: true)
            }
        }
    }

    /// Shows the existing pair at the current path, if there is one.
    func refreshKeyInfo() async {
        let path = DeploymentRequest.expandPath(keyPath)
        guard FileManager.default.fileExists(atPath: path),
              FileManager.default.fileExists(atPath: path + ".pub") else {
            keyInfo = nil
            return
        }
        keyInfo = try? await keyStore.readExisting(at: path)
    }

    func useDefaultKeyPath() {
        guard !isBusy else { return }
        keyPath = KeyStore.defaultKeyPath
        Task { await refreshKeyInfo() }
    }

    func chooseExistingKey() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.directoryURL = URL(fileURLWithPath: (DeploymentRequest.expandPath(keyPath) as NSString).deletingLastPathComponent)
        if panel.runModal() == .OK, let url = panel.url {
            keyPath = url.path.hasSuffix(".pub") ? String(url.path.dropLast(4)) : url.path
            Task { await refreshKeyInfo() }
        }
    }

    func chooseNewKeyLocation() {
        let panel = NSSavePanel()
        panel.showsHiddenFiles = true
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "server_ed25519"
        panel.directoryURL = URL(fileURLWithPath: (DeploymentRequest.expandPath(keyPath) as NSString).deletingLastPathComponent)
        if panel.runModal() == .OK, let url = panel.url {
            keyPath = url.path
            Task { await refreshKeyInfo() }
        }
    }

    func revealKeyInFinder() {
        let path = DeploymentRequest.expandPath(keyPath)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            return
        }
        let directory = (path as NSString).deletingLastPathComponent
        if FileManager.default.fileExists(atPath: directory) {
            NSWorkspace.shared.open(URL(fileURLWithPath: directory))
        } else {
            append(.init("密钥文件夹尚不存在。", "The key folder does not exist yet."), isError: true)
        }
    }

    func copyPublicKey() {
        guard let keyInfo else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(keyInfo.publicKey, forType: .string)
        append(.init("公钥已复制到剪贴板。", "Public key copied to the clipboard."))
    }

    // MARK: - Deployment

    func deploy() {
        guard !isBusy else { return }
        guard let portNumber = Int(port.trimmingCharacters(in: .whitespaces)) else {
            append(.init("端口必须是 1–65535 之间的数字。", "Port must be a number between 1 and 65535."), isError: true)
            return
        }
        let draft = DeploymentRequest(
            host: host, port: portNumber, username: username, password: password,
            keyPath: keyPath, enableRootLogin: enableRootLogin, allowPasswordLogin: allowPasswordLogin)
        // Check the form before creating a key, so a typo never leaves an unused key behind.
        let issues = RequestValidator.validate(draft, requireExistingKey: false)
        guard issues.isEmpty else {
            setStatus(.init("输入有误。", "Invalid input."), progress: 0)
            append(describe(DeploymentError(.validation, issues.map(\.message).joined(separator: "\n"))), isError: true)
            return
        }

        isBusy = true
        isDeploying = true
        stepStates = [:]
        setStatus(.init("正在准备部署…", "Preparing deployment..."), progress: 0.02)
        append(.init("开始部署到 \(draft.username)@\(draft.host):\(draft.port)",
                     "Deploying to \(draft.username)@\(draft.host):\(draft.port)"))

        let (progressStream, progressSink) = AsyncStream<DeploymentProgress>.pipe()
        let progressTask = Task { [weak self] in
            for await update in progressStream { self?.apply(update) }
        }

        deployTask = Task { [weak self] in
            guard let self else { return }
            do {
                let key = try await keyStore.ensureKeyPair(at: draft.keyPath)
                keyInfo = key
                append(.init("使用密钥 \(key.sha256Fingerprint)", "Using key \(key.sha256Fingerprint)"))

                let result = try await deploymentService.deploy(
                    draft,
                    approveHostKey: { [weak self] info in await self?.requestApproval(for: info) ?? false },
                    progress: { progressSink.yield($0) })
                progressSink.finish()
                await progressTask.value

                setStatus(.init("部署成功，密钥登录已验证。", "Deployment succeeded and key login was verified."), progress: 1)
                append(.init("已验证 \(result.verifiedUsername) 的密钥登录。现在可以用此私钥登录服务器。",
                             "Key login verified for \(result.verifiedUsername). You can now sign in with this private key."))
                for warning in result.warnings {
                    append(.init(warning, warning), isError: true)
                }
            } catch {
                progressSink.finish()
                await progressTask.value
                markActiveStepFailed()
                if error is CancellationError {
                    setStatus(.init("部署已取消。", "Deployment cancelled."), progress: 0)
                    append(.init("部署已取消；已开始的远端修改已回滚。",
                                 "Deployment cancelled; any remote changes that had started were rolled back."), isError: true)
                } else {
                    setStatus(.init("部署失败。", "Deployment failed."), progress: 0)
                    append(describe(error), isError: true)
                }
            }

            password = ""
            isBusy = false
            isDeploying = false
            deployTask = nil
            if terminationRequested {
                NSApp.reply(toApplicationShouldTerminate: true)
            }
        }
    }

    func cancelDeployment() {
        guard let deployTask else { return }
        setStatus(.init("正在取消并回滚…", "Cancelling and rolling back..."), progress: progress)
        deployTask.cancel()
        resolveHostKey(approved: false)
    }

    func resolveHostKey(approved: Bool) {
        pendingHostKey = nil
        hostKeyContinuation?.resume(returning: approved)
        hostKeyContinuation = nil
        if approved {
            append(.init("已批准主机指纹。", "Host key approved."))
        }
    }

    /// Called when the app is asked to quit. A running deployment is cancelled and
    /// allowed to finish its rollback before the app exits.
    func shouldTerminateNow() -> Bool {
        guard isDeploying else { return true }
        terminationRequested = true
        cancelDeployment()
        append(.init("正在回滚未完成的部署，完成后将自动退出。",
                     "Rolling back the unfinished deployment; the app will quit when it is done."), isError: true)
        return false
    }

    private func requestApproval(for hostKey: HostKeyInfo) async -> Bool {
        if Task.isCancelled { return false }
        return await withCheckedContinuation { continuation in
            hostKeyContinuation = continuation
            pendingHostKey = hostKey
        }
    }

    // MARK: - Progress and log

    private func apply(_ update: DeploymentProgress) {
        progress = Double(update.percent) / 100
        let chinese: String
        switch update.stage {
        case .awaitingHostKeyApproval: chinese = "请核对并确认服务器主机指纹。"
        case .rollingBack: chinese = "正在回滚远端修改…"
        case .completed: chinese = "部署完成。"
        default: chinese = (DeploymentStep(stage: update.stage)?.title.chinese ?? "") + "…"
        }
        status = .init(chinese, update.message)

        if let step = DeploymentStep(stage: update.stage) {
            for earlier in DeploymentStep.allCases where earlier.rawValue < step.rawValue {
                stepStates[earlier] = .done
            }
            stepStates[step] = .active
        } else if update.stage == .completed {
            for step in DeploymentStep.allCases { stepStates[step] = .done }
        }
    }

    private func markActiveStepFailed() {
        if let active = stepStates.first(where: { $0.value == .active })?.key {
            stepStates[active] = .failed
        }
    }

    private func setStatus(_ text: LocalizedText, progress value: Double) {
        status = text
        progress = value
    }

    private func append(_ text: LocalizedText, isError: Bool = false) {
        log.append(LogEntry(text: text, isError: isError))
    }

    private func describe(_ error: Error) -> LocalizedText {
        if let error = error as? DeploymentError { return error.localized }
        let message = error.localizedDescription
        return .init(message, message)
    }
}

extension AsyncStream {
    /// An ordered single-consumer channel (equivalent to `AsyncStream.makeStream`).
    static func pipe() -> (stream: AsyncStream<Element>, continuation: Continuation) {
        var continuation: Continuation!
        let stream = AsyncStream { continuation = $0 }
        return (stream, continuation)
    }
}
