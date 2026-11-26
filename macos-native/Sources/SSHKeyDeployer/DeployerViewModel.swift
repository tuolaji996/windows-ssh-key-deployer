import AppKit
import Combine
import DeployerCore
import Foundation

struct LogEntry: Identifiable {
    let id = UUID()
    let time: Date
    let text: LocalizedText
    let isError: Bool

    init(text: LocalizedText, isError: Bool = false, time: Date = Date()) {
        self.text = text
        self.isError = isError
        self.time = time
    }
}

/// The local key pair shown in the form.
struct LocalKeyInfo: Equatable {
    let privateKeyPath: String
    let publicKey: String
    let fingerprint: String

    init(privateKeyPath: String, publicKey: String, fingerprint: String) {
        self.privateKeyPath = privateKeyPath
        self.publicKey = publicKey
        self.fingerprint = fingerprint
    }

    init(_ info: KeyPairInfo) {
        self.init(privateKeyPath: info.privateKeyPath, publicKey: info.publicKey, fingerprint: info.sha256Fingerprint)
    }
}

/// A host key waiting for the user's decision.
struct HostKeyPrompt: Identifiable, Equatable {
    let host: String
    let port: Int
    let algorithm: String
    let keyLength: Int
    let sha256Fingerprint: String
    let md5Fingerprint: String

    var id: String { sha256Fingerprint }

    init(host: String, port: Int, algorithm: String, keyLength: Int, sha256Fingerprint: String, md5Fingerprint: String) {
        self.host = host
        self.port = port
        self.algorithm = algorithm
        self.keyLength = keyLength
        self.sha256Fingerprint = sha256Fingerprint
        self.md5Fingerprint = md5Fingerprint
    }

    init(_ info: HostKeyInfo) {
        self.init(host: info.host, port: info.port, algorithm: info.algorithm, keyLength: info.keyLength,
                  sha256Fingerprint: info.sha256Fingerprint, md5Fingerprint: info.md5Fingerprint)
    }
}

/// A plan waiting for the user's decision (stable identity for `.sheet(item:)`).
struct PlanPrompt: Identifiable {
    let id = UUID()
    let plan: DeploymentPlan
}

enum FormField: Hashable, CaseIterable {
    case host, port, username, password, keyPath, rootLogin, rootPassword, newSSHPort

    init?(_ field: ValidationIssue.Field) {
        switch field {
        case .host: self = .host
        case .port: self = .port
        case .username: self = .username
        case .password: self = .password
        case .keyPath: self = .keyPath
        case .rootLogin: self = .rootLogin
        case .rootPassword: self = .rootPassword
        case .newSSHPort: self = .newSSHPort
        @unknown default: return nil
        }
    }
}

enum DeployPhase: Equatable {
    case idle, deploying, succeeded, failed
}

@MainActor
final class DeployerViewModel: ObservableObject {
    // Form. Editing a field marks it "touched" so its error shows while typing.
    @Published var host = "" { didSet { touch(.host) } }
    @Published var port = "22" { didSet { touch(.port) } }
    @Published var username = "root" { didSet { touch(.username) } }
    @Published var password = "" { didSet { touch(.password) } }
    @Published var keyPath = KeyStore.defaultKeyPath { didSet { touch(.keyPath) } }
    @Published var rootLogin = RootLoginChoice.keyAndPassword { didSet { touch(.rootLogin) } }
    /// Only used when root login is disabled; otherwise the root choice decides it.
    @Published var passwordLoginForOthers = true
    @Published var rootPassword = "" { didSet { touch(.rootPassword) } }
    @Published var showRootPassword = false
    @Published var changePort = false { didSet { touch(.newSSHPort) } }
    @Published var newPort = "" { didSet { touch(.newSSHPort) } }
    @Published var touched: Set<FormField> = []

    // State
    @Published var isBusy = false
    @Published var phase = DeployPhase.idle
    @Published var progress = 0.0
    @Published var status = LocalizedText("填写服务器信息后开始部署。", "Fill in the server details to start.")
    @Published var stepStates: [DeploymentStep: StepState] = [:]
    @Published var activeStepDetail: String?
    @Published var log: [LogEntry] = []
    @Published var keyInfo: LocalKeyInfo?
    @Published var result: ResultSummary?
    @Published var failure: FailureSummary?
    @Published var pendingHostKey: HostKeyPrompt?
    @Published var pendingPlan: PlanPrompt?
    @Published private(set) var recentServers: [RecentServer] = []
    /// Whether the timeline of the last (or running) deployment includes the port change.
    @Published var runIncludesPortChange: Bool?

    private let keyStore = KeyStore()
    private let deploymentService = DeploymentService()
    private let recentStore: RecentServersStore
    private var deployTask: Task<Void, Never>?
    private var hostKeyContinuation: CheckedContinuation<Bool, Never>?
    private var planContinuation: CheckedContinuation<Bool, Never>?
    private var terminationRequested = false

    /// - Parameter persistent: false for the snapshot renderer (no disk access at all).
    init(persistent: Bool = true) {
        recentStore = RecentServersStore(defaults: persistent ? .standard : nil)
        recentServers = recentStore.load()
        touched = []
        if persistent {
            Task { await refreshKeyInfo() }
        }
    }

    var isDeploying: Bool { phase == .deploying }

    // MARK: - Policy

    var effectivePasswordLogin: Bool {
        switch rootLogin {
        case .disabled: return passwordLoginForOthers
        case .keyOnly: return false
        case .keyAndPassword: return true
        }
    }

    var policySummary: LocalizedText {
        PolicyText.summary(root: rootLogin, passwordLogin: effectivePasswordLogin, account: username)
    }

    var needsRootPasswordOption: Bool {
        username.trimmingCharacters(in: .whitespaces) != "root"
    }

    // MARK: - Validation

    private func touch(_ field: FormField) {
        if !touched.contains(field) { touched.insert(field) }
    }

    /// The request the form describes; the port is 0 when it is not a number.
    private func draftRequest() -> DeploymentRequest {
        DeploymentRequest(
            host: host,
            port: Int(port.trimmingCharacters(in: .whitespaces)) ?? 0,
            username: username,
            password: password,
            keyPath: keyPath,
            enableRootLogin: rootLogin != .disabled,
            allowPasswordLogin: effectivePasswordLogin,
            rootPassword: needsRootPasswordOption ? rootPassword : nil,
            newSSHPort: changePort ? Int(newPort.trimmingCharacters(in: .whitespaces)) : nil)
    }

    /// Every problem with the form, by field (first problem per field).
    var allIssues: [FormField: LocalizedText] {
        var issues: [FormField: LocalizedText] = [:]
        for issue in RequestValidator.validate(draftRequest(), requireExistingKey: false) {
            let field = FormField(issue.field) ?? .host
            if issues[field] == nil { issues[field] = ValidationText.localize(issue.message) }
        }
        let portNumber = Int(port.trimmingCharacters(in: .whitespaces))
        if portNumber == nil { issues[.port] = ValidationText.portNotNumeric }
        if changePort {
            if let value = Int(newPort.trimmingCharacters(in: .whitespaces)), (1...65_535).contains(value) {
                if value == portNumber, issues[.newSSHPort] == nil { issues[.newSSHPort] = ValidationText.newPortSame }
            } else {
                issues[.newSSHPort] = ValidationText.newPortInvalid
            }
        }
        if needsRootPasswordOption,
           rootPassword.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" }) {
            issues[.rootPassword] = ValidationText.rootPasswordInvalid
        }
        return issues
    }

    /// Problems for fields the user has already edited.
    var visibleIssues: [FormField: LocalizedText] {
        allIssues.filter { touched.contains($0.key) }
    }

    var canDeploy: Bool { !isBusy && allIssues.isEmpty }

    // MARK: - Recent servers

    func fill(from server: RecentServer) {
        guard !isBusy else { return }
        host = server.host
        port = String(server.port)
        username = server.username
        keyPath = server.keyPath
        password = ""
        rootPassword = ""
        changePort = false
        newPort = ""
        touched = [.host, .port, .username, .keyPath]
        Task { await refreshKeyInfo() }
    }

    func removeRecent(_ server: RecentServer) {
        recentServers.removeAll { $0.id == server.id }
        recentStore.save(recentServers)
    }

    func clearRecent() {
        recentServers = []
        recentStore.save([])
    }

    /// For the snapshot renderer.
    func setRecentServers(_ servers: [RecentServer]) {
        recentServers = servers
    }

    private func remember(host: String, port: Int, username: String, keyPath: String) {
        let server = RecentServer(host: host, port: port, username: username, keyPath: keyPath, lastUsed: Date())
        recentServers = RecentServersStore.remembering(server, in: recentServers)
        recentStore.save(recentServers)
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
                keyInfo = LocalKeyInfo(info)
                setStatus(.init("密钥已就绪。", "Key is ready."), progress: 0)
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
        keyInfo = (try? await keyStore.readExisting(at: path)).map(LocalKeyInfo.init)
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
        copyToPasteboard(keyInfo.publicKey)
        append(.init("公钥已复制到剪贴板。", "Public key copied to the clipboard."))
    }

    func copyLog(language: AppLanguage) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let text = log.map { "[\(formatter.string(from: $0.time))] \($0.text(language))" }.joined(separator: "\n")
        copyToPasteboard(text)
    }

    func copyToPasteboard(_ text: String) {
        Clipboard.copy(text)
    }

    // MARK: - Deployment

    func deploy() {
        guard !isBusy else { return }
        touched = Set(FormField.allCases)
        guard allIssues.isEmpty else {
            setStatus(.init("请先修正标红的字段。", "Fix the highlighted fields first."), progress: 0)
            return
        }
        let request = draftRequest()

        isBusy = true
        phase = .deploying
        result = nil
        failure = nil
        stepStates = [:]
        activeStepDetail = nil
        runIncludesPortChange = request.newSSHPort != nil
        setStatus(.init("正在准备部署…", "Preparing deployment..."), progress: 0.02)
        append(.init("开始部署到 \(request.username)@\(request.host):\(request.port)",
                     "Deploying to \(request.username)@\(request.host):\(request.port)"))
        remember(host: request.host, port: request.port, username: request.username, keyPath: keyPath)

        let (progressStream, progressSink) = AsyncStream<DeploymentProgress>.pipe()
        let progressTask = Task { [weak self] in
            for await update in progressStream { self?.apply(update) }
        }

        deployTask = Task { [weak self] in
            guard let self else { return }
            do {
                let key = try await keyStore.ensureKeyPair(at: request.keyPath)
                keyInfo = LocalKeyInfo(key)
                append(.init("使用密钥 \(key.sha256Fingerprint)", "Using key \(key.sha256Fingerprint)"))

                let outcome = try await deploymentService.deploy(
                    request,
                    approveHostKey: { [weak self] info in await self?.requestApproval(for: info) ?? false },
                    approvePlan: { [weak self] plan in await self?.requestPlanApproval(plan) ?? false },
                    progress: { progressSink.yield($0) })
                progressSink.finish()
                await progressTask.value

                let summary = ResultSummary(result: outcome, request: request)
                result = summary
                phase = .succeeded
                for step in visibleSteps { stepStates[step] = .done }
                activeStepDetail = nil
                setStatus(.init("部署成功，密钥登录已验证。", "Deployment succeeded and key login was verified."), progress: 1)
                append(.init("已验证 \(outcome.verifiedUsername) 的密钥登录（端口 \(outcome.sshPort)）。",
                             "Key login verified for \(outcome.verifiedUsername) on port \(outcome.sshPort)."))
                for warning in outcome.warnings {
                    append(.init(verbatim: warning), isError: true)
                }
                remember(host: request.host, port: outcome.sshPort, username: request.username, keyPath: keyPath)
                if outcome.sshPort != request.port {
                    port = String(outcome.sshPort)
                    changePort = false
                    newPort = ""
                }
            } catch {
                progressSink.finish()
                await progressTask.value
                markActiveStepFailed()
                let summary = FailureSummary(error)
                failure = summary
                phase = .failed
                setStatus(summary.title, progress: 0)
                if error is CancellationError {
                    append(.init("部署已取消；已开始的远端修改已回滚。",
                                 "Deployment cancelled; any remote changes that had started were rolled back."), isError: true)
                } else {
                    append(describe(error), isError: true)
                }
            }

            // Secrets never outlive the deployment.
            password = ""
            rootPassword = ""
            touched.remove(.password)
            isBusy = false
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
        resolvePlan(approved: false)
    }

    func resolveHostKey(approved: Bool) {
        pendingHostKey = nil
        guard let continuation = hostKeyContinuation else { return }
        hostKeyContinuation = nil
        continuation.resume(returning: approved)
        append(approved ? .init("已批准主机指纹。", "Host key approved.")
                        : .init("未批准主机指纹。", "Host key not approved."), isError: !approved)
    }

    func resolvePlan(approved: Bool) {
        pendingPlan = nil
        guard let continuation = planContinuation else { return }
        planContinuation = nil
        continuation.resume(returning: approved)
        append(approved ? .init("已批准变更计划。", "Plan approved.")
                        : .init("未批准变更计划，不会修改服务器。", "Plan not approved; the server will not be changed."),
               isError: !approved)
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
            pendingHostKey = HostKeyPrompt(hostKey)
        }
    }

    private func requestPlanApproval(_ plan: DeploymentPlan) async -> Bool {
        if Task.isCancelled { return false }
        append(.init("检测到 \(plan.server.displayName)，等待确认变更计划。",
                     "Detected \(plan.server.displayName); waiting for plan approval."))
        return await withCheckedContinuation { continuation in
            planContinuation = continuation
            pendingPlan = PlanPrompt(plan: plan)
        }
    }

    // MARK: - Progress and log

    /// Steps shown in the timeline; the port step only when a port change is requested.
    var visibleSteps: [DeploymentStep] {
        let includePort = runIncludesPortChange ?? changePort
        return DeploymentStep.allCases.filter { $0 != .changePort || includePort }
    }

    func apply(_ update: DeploymentProgress) {
        apply(stage: update.stage, message: update.message, percent: update.percent)
    }

    func apply(stage: DeploymentStage, message: String, percent: Int) {
        progress = Double(percent) / 100
        let chinese: String
        switch stage {
        case .awaitingHostKeyApproval: chinese = "请核对并确认服务器主机指纹。"
        case .awaitingPlanApproval: chinese = "请查看并确认变更计划。"
        case .rollingBack: chinese = "正在回滚远端修改…"
        case .completed: chinese = "部署完成。"
        default: chinese = (DeploymentStep(stage: stage)?.title.chinese ?? "") + "…"
        }
        status = .init(chinese, message)
        activeStepDetail = message

        if let step = DeploymentStep(stage: stage) {
            for earlier in DeploymentStep.allCases where earlier.rawValue < step.rawValue {
                stepStates[earlier] = .done
            }
            stepStates[step] = .active
        } else if stage == .completed {
            for step in DeploymentStep.allCases { stepStates[step] = .done }
        }
    }

    private func markActiveStepFailed() {
        if let active = stepStates.first(where: { $0.value == .active })?.key {
            stepStates[active] = .failed
        }
    }

    func setStatus(_ text: LocalizedText, progress value: Double) {
        status = text
        progress = value
    }

    func append(_ text: LocalizedText, isError: Bool = false, time: Date = Date()) {
        log.append(LogEntry(text: text, isError: isError, time: time))
    }

    private func describe(_ error: Error) -> LocalizedText {
        if let error = error as? DeploymentError { return error.localized }
        return .init(verbatim: error.localizedDescription)
    }
}

enum Clipboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
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
