import Foundation

public enum RequestValidator {
    public static func validate(
        _ request: DeploymentRequest,
        requireExistingKey: Bool = true
    ) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if request.host.isEmpty {
            issues.append(.init(field: .host, message: "Host is required."))
        } else if !HostName.isValid(request.host) {
            issues.append(.init(
                field: .host,
                message: "Host must be a valid DNS name or IP address without a URL scheme or port."))
        }

        if !(1...65_535).contains(request.port) {
            issues.append(.init(field: .port, message: "Port must be between 1 and 65535."))
        }

        if !isValidUsername(request.username) {
            issues.append(.init(
                field: .username,
                message: "Username must be a valid Linux account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters)."))
        }

        if request.username == "root" && !request.enableRootLogin {
            issues.append(.init(
                field: .rootLogin,
                message: "Root login cannot be disabled when the deployment account is root."))
        }

        if request.password.isEmpty {
            issues.append(.init(
                field: .password,
                message: "A password is required for the initial SSH connection and sudo authentication."))
        } else if request.password.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" }) {
            issues.append(.init(
                field: .password,
                message: "Password cannot contain line breaks or null characters."))
        } else if request.password.count > 1_024 {
            issues.append(.init(field: .password, message: "Password cannot exceed 1024 characters."))
        }

        if let rootPassword = request.rootPassword {
            if rootPassword.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" }) {
                issues.append(.init(
                    field: .rootPassword,
                    message: "Root password cannot contain line breaks or null characters."))
            } else if rootPassword.count > 1_024 {
                issues.append(.init(field: .rootPassword, message: "Root password cannot exceed 1024 characters."))
            }
        }

        if let newPort = request.newSSHPort {
            if !(1...65_535).contains(newPort) {
                issues.append(.init(field: .newSSHPort, message: "New SSH port must be between 1 and 65535."))
            } else if newPort == request.port {
                issues.append(.init(
                    field: .newSSHPort,
                    message: "New SSH port must differ from the port used for this connection; leave it empty to keep the current port."))
            }
        }

        issues.append(contentsOf: validateKeyPath(request.keyPath, requireExistingKey: requireExistingKey))
        return issues
    }

    public static func ensureValid(
        _ request: DeploymentRequest,
        requireExistingKey: Bool = true
    ) throws {
        let issues = validate(request, requireExistingKey: requireExistingKey)
        guard issues.isEmpty else {
            throw DeploymentError(
                .validation,
                issues.map(\.message).joined(separator: "\n"),
                issues: issues)
        }
    }

    /// Returns the reason a private-key path is unusable, or `nil` when it is acceptable.
    static func keyPathProblem(_ keyPath: String) -> String? {
        if keyPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Private-key path is required."
        }
        if !keyPath.hasPrefix("/") {
            return "Private-key path must be absolute."
        }
        if keyPath.lowercased().hasSuffix(".pub") {
            return "Select the private key, not the .pub file."
        }
        if keyPath.hasSuffix("/") || keyPath.unicodeScalars.contains(where: { $0 == "\0" || $0 == "\n" || $0 == "\r" }) {
            return "Private-key path is invalid."
        }
        return nil
    }

    private static func validateKeyPath(_ keyPath: String, requireExistingKey: Bool) -> [ValidationIssue] {
        if let problem = keyPathProblem(keyPath) {
            return [.init(field: .keyPath, message: problem)]
        }
        guard requireExistingKey else { return [] }

        var issues: [ValidationIssue] = []
        if !FileManager.default.fileExists(atPath: keyPath) {
            issues.append(.init(field: .keyPath, message: "Private-key file does not exist."))
        }
        if !FileManager.default.fileExists(atPath: keyPath + ".pub") {
            issues.append(.init(field: .keyPath, message: "Matching .pub file does not exist."))
        }
        return issues
    }

    /// Matches `^[a-z_][a-z0-9_-]{0,31}$`. The leading character rule also guarantees
    /// the name can never be mistaken for an `ssh` command-line option.
    static func isValidUsername(_ name: String) -> Bool {
        let scalars = Array(name.unicodeScalars)
        guard let first = scalars.first, scalars.count <= 32 else { return false }
        guard first.isASCIILowercase || first == "_" else { return false }
        return scalars.dropFirst().allSatisfy { scalar in
            scalar.isASCIILowercase || scalar.isASCIIDigit || scalar == "_" || scalar == "-"
        }
    }
}

extension Unicode.Scalar {
    var isASCIILowercase: Bool { value >= 97 && value <= 122 }
    var isASCIIUppercase: Bool { value >= 65 && value <= 90 }
    var isASCIIDigit: Bool { value >= 48 && value <= 57 }
    var isASCIIAlphanumeric: Bool { isASCIILowercase || isASCIIUppercase || isASCIIDigit }
}

/// Host-name and IP-address helpers shared by validation and deployment.
enum HostName {
    static func isValid(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 253 else { return false }
        return ipAddressBytes(host) != nil || isDNSName(host)
    }

    /// Parses a numeric IPv4 or IPv6 address into its raw bytes.
    static func ipAddressBytes(_ text: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }

    private static func isDNSName(_ host: String) -> Bool {
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        return labels.allSatisfy { label in
            let scalars = Array(label.unicodeScalars)
            guard (1...63).contains(scalars.count),
                  let first = scalars.first, let last = scalars.last,
                  first != "-", last != "-" else { return false }
            return scalars.allSatisfy { $0.isASCIIAlphanumeric || $0 == "-" || $0 == "_" }
        }
    }
}
