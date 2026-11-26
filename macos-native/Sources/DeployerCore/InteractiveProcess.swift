import Foundation

struct InteractiveProcessOutput: Sendable {
    let status: Int32
    /// The start marker appeared, so the remote script itself ran.
    let started: Bool
    let promptAnswered: Bool
    /// Terminal output before the start marker (carriage returns removed).
    let beforeStart: String
    /// Terminal output after the start marker (carriage returns removed).
    let afterStart: String
    let stderr: String
    let timedOut: Bool
}

/// Decides when to type a secret into a terminal stream. Holds no process state, so
/// it can be tested on its own.
///
/// The secret is typed at most once: only after a prompt containing `promptWord`
/// (case-insensitive) has appeared, and never after `startMarker`, which the remote
/// side prints once authentication is over. A second prompt (wrong password with a
/// retry, or an expired password asking for a new one) aborts instead of waiting.
struct TerminalPrompter {
    enum Action: Equatable {
        case none
        case answer
        case abort
    }

    static let maximumOutput = 128 * 1024

    let startMarker: String
    let promptWord: String
    private(set) var started = false
    private(set) var promptAnswered = false
    private var before = Data()
    private var after = Data()
    private var answeredAtCharacter = 0

    init(startMarker: String, promptWord: String = "password") {
        self.startMarker = startMarker
        self.promptWord = promptWord.lowercased()
    }

    var beforeStart: String { Self.clean(before) }
    var afterStart: String { Self.clean(after) }

    mutating func feed(_ chunk: Data) -> Action {
        if started {
            after.append(chunk)
            if after.count > Self.maximumOutput {
                after = after.suffix(Self.maximumOutput)
            }
            return .none
        }

        before.append(chunk)
        let text = Self.clean(before)
        if let range = text.range(of: startMarker + "\n") {
            started = true
            after = Data(text[range.upperBound...].utf8)
            before = Data(text[..<range.lowerBound].utf8)
            return .none
        }
        // Without a marker the remote side is still authenticating; it never needs
        // this much output, so stop rather than buffer without limit.
        if before.count > Self.maximumOutput {
            return .abort
        }

        let lower = text.lowercased()
        if !promptAnswered {
            guard lower.contains(promptWord) else { return .none }
            promptAnswered = true
            answeredAtCharacter = lower.count
            return .answer
        }
        return lower.dropFirst(answeredAtCharacter).contains(promptWord) ? .abort : .none
    }

    static func clean(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self).replacingOccurrences(of: "\r", with: "")
    }
}

/// Runs a trusted executable whose remote side reads a secret from a terminal (`su`
/// over `ssh -tt`). Same timeout and cancellation behaviour as `ProcessRunner`; the
/// secret goes to standard input only, and only once a prompt asks for it.
enum InteractiveProcess {
    private static let brokenPipeIgnored: Void = { _ = signal(SIGPIPE, SIG_IGN) }()

    static func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String]? = nil,
        secret: String,
        startMarker: String,
        timeout: TimeInterval
    ) async throws -> InteractiveProcessOutput {
        try Task.checkCancellation()
        _ = brokenPipeIgnored
        let job = Job()

        let output: InteractiveProcessOutput = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        continuation.resume(returning: try job.execute(
                            executable: executable,
                            arguments: arguments,
                            environment: environment,
                            secret: secret,
                            startMarker: startMarker,
                            timeout: timeout))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            job.cancel()
        }

        try Task.checkCancellation()
        return output
    }

    private final class Job: @unchecked Sendable {
        private let lock = NSLock()
        private var process: Process?
        private var cancelled = false
        private var timedOut = false

        func cancel() {
            lock.lock()
            cancelled = true
            let running = process
            lock.unlock()
            if let running, running.isRunning { running.terminate() }
        }

        private func expire() {
            lock.lock()
            timedOut = true
            let running = process
            lock.unlock()
            if let running, running.isRunning { running.terminate() }
        }

        func execute(
            executable: String,
            arguments: [String],
            environment: [String: String]?,
            secret: String,
            startMarker: String,
            timeout: TimeInterval
        ) throws -> InteractiveProcessOutput {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            if let environment { process.environment = environment }

            let stdinPipe = Pipe()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.standardInput = stdinPipe
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            lock.lock()
            let alreadyCancelled = cancelled
            if !alreadyCancelled { self.process = process }
            lock.unlock()
            if alreadyCancelled { throw CancellationError() }

            do {
                try process.run()
            } catch {
                throw ProcessRunnerError.launchFailed(executable: executable, reason: error.localizedDescription)
            }

            lock.lock()
            let cancelledDuringLaunch = cancelled
            lock.unlock()
            if cancelledDuringLaunch { process.terminate() }

            let deadline = DispatchWorkItem { [weak self] in self?.expire() }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)

            // Standard input stays open until the process exits: closing it early
            // would reach the remote terminal as end-of-file.
            let writer = stdinPipe.fileHandleForWriting
            // Each box is only touched by its reader until `readers.wait()` returns.
            let state = PrompterBox(TerminalPrompter(startMarker: startMarker))
            let stderrBox = DataBox()
            let readers = DispatchGroup()

            readers.enter()
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let reader = stdoutPipe.fileHandleForReading
                while true {
                    let chunk = reader.availableData
                    if chunk.isEmpty { break }
                    switch state.prompter.feed(chunk) {
                    case .none:
                        break
                    case .answer:
                        try? writer.write(contentsOf: Data((secret + "\n").utf8))
                    case .abort:
                        self?.terminateRunning()
                    }
                }
                readers.leave()
            }
            readers.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                stderrBox.data = stderrPipe.fileHandleForReading.readDataToEndOfFile()
                readers.leave()
            }

            process.waitUntilExit()
            deadline.cancel()
            readers.wait()
            try? writer.close()

            lock.lock()
            let didTimeOut = timedOut
            self.process = nil
            lock.unlock()

            let prompter = state.prompter
            return InteractiveProcessOutput(
                status: process.terminationStatus,
                started: prompter.started,
                promptAnswered: prompter.promptAnswered,
                beforeStart: prompter.beforeStart,
                afterStart: prompter.afterStart,
                stderr: String(decoding: stderrBox.data, as: UTF8.self),
                timedOut: didTimeOut)
        }

        private func terminateRunning() {
            lock.lock()
            let running = process
            lock.unlock()
            if let running, running.isRunning { running.terminate() }
        }
    }

    private final class PrompterBox: @unchecked Sendable {
        var prompter: TerminalPrompter
        init(_ prompter: TerminalPrompter) { self.prompter = prompter }
    }

    private final class DataBox: @unchecked Sendable {
        var data = Data()
    }
}
