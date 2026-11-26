import Foundation

public struct ProcessOutput: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
    public let timedOut: Bool
}

enum ProcessRunnerError: Error, LocalizedError {
    case launchFailed(executable: String, reason: String)

    var errorDescription: String? {
        switch self {
        case let .launchFailed(executable, reason):
            return "\(executable) could not be started: \(reason)"
        }
    }
}

/// Runs a trusted system executable without a shell, with a timeout and
/// cooperative cancellation. Arguments are passed as an array, so no value is
/// ever interpreted by a local shell.
enum ProcessRunner {
    /// Writing to a child that already exited must surface as a write error instead of
    /// terminating the whole process with SIGPIPE. Evaluated once, before the first run.
    private static let brokenPipeIgnored: Void = { _ = signal(SIGPIPE, SIG_IGN) }()

    /// - Parameters:
    ///   - input: Bytes written to standard input before it is closed. `nil` connects `/dev/null`.
    ///   - stderrFile: When set, standard error goes to this file and standard output is
    ///     discarded. Required for commands that leave a background child holding the
    ///     descriptors open (`ssh -f`), which would otherwise never deliver end-of-file.
    static func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String]? = nil,
        input: Data? = nil,
        timeout: TimeInterval,
        stderrFile: URL? = nil
    ) async throws -> ProcessOutput {
        try Task.checkCancellation()
        _ = brokenPipeIgnored
        let job = Job()

        let output: ProcessOutput = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        continuation.resume(returning: try job.execute(
                            executable: executable,
                            arguments: arguments,
                            environment: environment,
                            input: input,
                            timeout: timeout,
                            stderrFile: stderrFile))
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

    /// Owns one child process so that cancellation and timeouts can stop it from any thread.
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
            input: Data?,
            timeout: TimeInterval,
            stderrFile: URL?
        ) throws -> ProcessOutput {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            if let environment { process.environment = environment }

            let stdinPipe = Pipe()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            var stderrHandle: FileHandle?

            if input == nil {
                process.standardInput = FileHandle.nullDevice
            } else {
                process.standardInput = stdinPipe
            }
            if let stderrFile {
                FileManager.default.createFile(
                    atPath: stderrFile.path,
                    contents: nil,
                    attributes: [.posixPermissions: 0o600])
                stderrHandle = try FileHandle(forWritingTo: stderrFile)
                process.standardOutput = FileHandle.nullDevice
                process.standardError = stderrHandle
            } else {
                process.standardOutput = stdoutPipe
                process.standardError = stderrPipe
            }
            defer { try? stderrHandle?.close() }

            lock.lock()
            let alreadyCancelled = cancelled
            if !alreadyCancelled { self.process = process }
            lock.unlock()
            if alreadyCancelled { throw CancellationError() }

            do {
                try process.run()
            } catch {
                throw ProcessRunnerError.launchFailed(
                    executable: executable,
                    reason: error.localizedDescription)
            }

            // cancel() may have run between registering the process and launching it.
            lock.lock()
            let cancelledDuringLaunch = cancelled
            lock.unlock()
            if cancelledDuringLaunch { process.terminate() }

            // Arm the timeout before writing stdin, so a child that never reads cannot block us forever.
            let deadline = DispatchWorkItem { [weak self] in self?.expire() }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)

            // Drain both pipes concurrently so a chatty child can never block on a full pipe.
            let stdoutBox = DataBox()
            let stderrBox = DataBox()
            let readers = DispatchGroup()
            if stderrFile == nil {
                for (pipe, box) in [(stdoutPipe, stdoutBox), (stderrPipe, stderrBox)] {
                    readers.enter()
                    DispatchQueue.global(qos: .userInitiated).async {
                        box.data = pipe.fileHandleForReading.readDataToEndOfFile()
                        readers.leave()
                    }
                }
            }

            if let input {
                let writer = stdinPipe.fileHandleForWriting
                // The child may exit before reading everything; that is not an error here.
                try? writer.write(contentsOf: input)
                try? writer.close()
            }

            process.waitUntilExit()
            deadline.cancel()
            readers.wait()

            lock.lock()
            let didTimeOut = timedOut
            self.process = nil
            lock.unlock()

            var stderrText = String(decoding: stderrBox.data, as: UTF8.self)
            if let stderrFile, let data = try? Data(contentsOf: stderrFile) {
                stderrText = String(decoding: data, as: UTF8.self)
            }

            return ProcessOutput(
                status: process.terminationStatus,
                stdout: String(decoding: stdoutBox.data, as: UTF8.self),
                stderr: stderrText,
                timedOut: didTimeOut)
        }
    }

    private final class DataBox: @unchecked Sendable {
        var data = Data()
    }
}
