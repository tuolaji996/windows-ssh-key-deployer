import CryptoKit
import Foundation

/// Reads the length-prefixed fields of an SSH wire-format blob.
struct SSHBlobReader {
    private let bytes: [UInt8]
    private(set) var offset = 0

    init(_ data: Data) { bytes = Array(data) }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func readField() -> [UInt8]? {
        guard bytes.count - offset >= 4 else { return nil }
        let length = bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
        offset += 4
        guard length <= bytes.count - offset else { return nil }
        defer { offset += length }
        return Array(bytes[offset..<offset + length])
    }
}

enum Fingerprint {
    /// OpenSSH style: `SHA256:` followed by unpadded base64.
    static func sha256(_ blob: Data) -> String {
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        return "SHA256:" + digest.replacingOccurrences(of: "=", with: "")
    }

    /// Legacy colon-separated hex, shown only so it can be compared with older consoles.
    static func md5(_ blob: Data) -> String {
        "MD5:" + Insecure.MD5.hash(data: blob)
            .map { String(format: "%02x", $0) }
            .joined(separator: ":")
    }
}

/// A validated OpenSSH Ed25519 public key.
struct Ed25519PublicKey: Equatable {
    static let comment = "ssh-key-deployer"
    private static let maximumFileLength = 16 * 1024

    /// `ssh-ed25519 <base64> ssh-key-deployer`
    let normalizedText: String
    /// Canonical base64 of the key blob; used to compare keys.
    let keyData: String
    let sha256Fingerprint: String

    static func read(path: String) throws -> Ed25519PublicKey {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard size <= maximumFileLength else {
            throw DeploymentError(.key, "Public-key file is unexpectedly large.")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try parse(String(decoding: data, as: UTF8.self))
    }

    static func parse(_ text: String) throws -> Ed25519PublicKey {
        let invalid = DeploymentError(
            .key,
            "Public key must contain exactly one OpenSSH Ed25519 public key.")

        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.unicodeScalars.contains(where: { $0 == "\n" || $0 == "\r" }) else {
            throw invalid
        }
        let fields = trimmed.split(
            maxSplits: 2,
            omittingEmptySubsequences: true,
            whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 2, fields[0] == "ssh-ed25519" else { throw invalid }

        guard let blob = Data(base64Encoded: String(fields[1])) else {
            throw DeploymentError(.key, "Public-key data is not valid base64.")
        }

        var reader = SSHBlobReader(blob)
        guard let algorithm = reader.readField(),
              let key = reader.readField(),
              algorithm == Array("ssh-ed25519".utf8),
              key.count == 32,
              reader.isAtEnd else {
            throw DeploymentError(.key, "Public-key blob is not a valid Ed25519 key.")
        }

        let keyData = blob.base64EncodedString()
        return Ed25519PublicKey(
            normalizedText: "ssh-ed25519 \(keyData) \(comment)",
            keyData: keyData,
            sha256Fingerprint: Fingerprint.sha256(blob))
    }
}

/// A server host key as reported by `ssh-keyscan`.
struct ScannedHostKey: Equatable {
    /// Preference order when a server offers several key types.
    static let supportedAlgorithms = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    ]

    let algorithm: String
    let base64: String
    let blob: Data

    /// Picks the most preferred supported key from `ssh-keyscan` output.
    static func parseBest(keyscanOutput: String) -> ScannedHostKey? {
        var found: [String: ScannedHostKey] = [:]
        for line in keyscanOutput.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 3, !fields[0].hasPrefix("#") else { continue }
            let algorithm = String(fields[1])
            guard supportedAlgorithms.contains(algorithm),
                  found[algorithm] == nil,
                  let blob = Data(base64Encoded: String(fields[2])) else { continue }

            // The blob must declare the same algorithm as the text column.
            var reader = SSHBlobReader(blob)
            guard reader.readField() == Array(algorithm.utf8) else { continue }
            found[algorithm] = ScannedHostKey(
                algorithm: algorithm,
                base64: blob.base64EncodedString(),
                blob: blob)
        }
        return supportedAlgorithms.lazy.compactMap { found[$0] }.first
    }

    /// The `HostKeyAlgorithms` value that makes `ssh` negotiate exactly this key type.
    var negotiationAlgorithms: String {
        algorithm == "ssh-rsa" ? "rsa-sha2-512,rsa-sha2-256" : algorithm
    }

    var keyLength: Int {
        switch algorithm {
        case "ssh-ed25519", "ecdsa-sha2-nistp256": return 256
        case "ecdsa-sha2-nistp384": return 384
        case "ecdsa-sha2-nistp521": return 521
        default: return rsaModulusBits
        }
    }

    private var rsaModulusBits: Int {
        var reader = SSHBlobReader(blob)
        guard reader.readField() != nil,
              reader.readField() != nil,
              let modulus = reader.readField() else { return 0 }
        let significant = modulus.drop(while: { $0 == 0 })
        guard let first = significant.first else { return 0 }
        return (significant.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }

    /// One `known_hosts` line that pins this key under a `HostKeyAlias`, which avoids
    /// any host-name, IPv6 bracket or port-pattern ambiguity.
    func knownHostsLine(alias: String) -> String {
        "\(alias) \(algorithm) \(base64)\n"
    }

    func info(host: String, port: Int) -> HostKeyInfo {
        HostKeyInfo(
            host: host,
            port: port,
            algorithm: algorithm,
            keyLength: keyLength,
            sha256Fingerprint: Fingerprint.sha256(blob),
            md5Fingerprint: Fingerprint.md5(blob))
    }
}
