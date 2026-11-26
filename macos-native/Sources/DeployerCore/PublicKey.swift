#if canImport(CryptoKit)
import CryptoKit
#endif
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
        let digest = Data(Digests.sha256(blob)).base64EncodedString()
        return "SHA256:" + digest.replacingOccurrences(of: "=", with: "")
    }

    /// Legacy colon-separated hex, shown only so it can be compared with older consoles.
    static func md5(_ blob: Data) -> String {
        "MD5:" + Digests.md5(blob)
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

/// Digests used only for fingerprints. CryptoKit where available (macOS); a small
/// portable implementation elsewhere (Linux, used by the end-to-end test harness).
enum Digests {
    #if canImport(CryptoKit)
    static func sha256(_ data: Data) -> [UInt8] { Array(SHA256.hash(data: data)) }
    static func md5(_ data: Data) -> [UInt8] { Array(Insecure.MD5.hash(data: data)) }
    #else
    static func sha256(_ data: Data) -> [UInt8] { PortableDigests.sha256(Array(data)) }
    static func md5(_ data: Data) -> [UInt8] { PortableDigests.md5(Array(data)) }
    #endif
}

/// Pure-Swift SHA-256 (FIPS 180-4) and MD5 (RFC 1321). Not constant time; only ever
/// applied to public data (key blobs) to display fingerprints.
enum PortableDigests {
    private static let sha256Constants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    private static let md5Shifts: [UInt32] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]

    /// K[i] = floor(|sin(i + 1)| * 2^32), exact in double precision for all 64 entries.
    private static let md5Constants: [UInt32] = (0..<64).map { index in
        UInt32(truncatingIfNeeded: Int64(abs(sin(Double(index + 1))) * 4_294_967_296.0))
    }

    private static func rotateRight(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value >> count) | (value << (32 - count))
    }

    private static func rotateLeft(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    /// Appends 0x80, zero padding and the 64-bit message bit length.
    private static func pad(_ message: [UInt8], bigEndianLength: Bool) -> [UInt8] {
        var padded = message
        let bitLength = UInt64(message.count) &* 8
        padded.append(0x80)
        while padded.count % 64 != 56 { padded.append(0) }
        for index in 0..<8 {
            let shift = UInt64(bigEndianLength ? (7 - index) * 8 : index * 8)
            padded.append(UInt8(truncatingIfNeeded: bitLength >> shift))
        }
        return padded
    }

    static func sha256(_ message: [UInt8]) -> [UInt8] {
        var hash: [UInt32] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]
        let padded = pad(message, bigEndianLength: true)
        var schedule = [UInt32](repeating: 0, count: 64)

        for chunk in stride(from: 0, to: padded.count, by: 64) {
            for index in 0..<16 {
                var word: UInt32 = 0
                for byte in 0..<4 {
                    word = (word << 8) | UInt32(padded[chunk + index * 4 + byte])
                }
                schedule[index] = word
            }
            for index in 16..<64 {
                let w15 = schedule[index - 15]
                let w2 = schedule[index - 2]
                let s0 = rotateRight(w15, 7) ^ rotateRight(w15, 18) ^ (w15 >> 3)
                let s1 = rotateRight(w2, 17) ^ rotateRight(w2, 19) ^ (w2 >> 10)
                schedule[index] = schedule[index - 16] &+ s0 &+ schedule[index - 7] &+ s1
            }

            var a = hash[0], b = hash[1], c = hash[2], d = hash[3]
            var e = hash[4], f = hash[5], g = hash[6], h = hash[7]
            for index in 0..<64 {
                let sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
                let choice = (e & f) ^ (~e & g)
                let temp1 = h &+ sigma1 &+ choice &+ sha256Constants[index] &+ schedule[index]
                let sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
                let majority = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = sigma0 &+ majority
                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }
            hash[0] = hash[0] &+ a
            hash[1] = hash[1] &+ b
            hash[2] = hash[2] &+ c
            hash[3] = hash[3] &+ d
            hash[4] = hash[4] &+ e
            hash[5] = hash[5] &+ f
            hash[6] = hash[6] &+ g
            hash[7] = hash[7] &+ h
        }

        var digest: [UInt8] = []
        for word in hash {
            for shift in stride(from: 24, through: 0, by: -8) {
                digest.append(UInt8(truncatingIfNeeded: word >> UInt32(shift)))
            }
        }
        return digest
    }

    static func md5(_ message: [UInt8]) -> [UInt8] {
        var state: [UInt32] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        let padded = pad(message, bigEndianLength: false)
        var words = [UInt32](repeating: 0, count: 16)

        for chunk in stride(from: 0, to: padded.count, by: 64) {
            for index in 0..<16 {
                var word: UInt32 = 0
                for byte in (0..<4).reversed() {
                    word = (word << 8) | UInt32(padded[chunk + index * 4 + byte])
                }
                words[index] = word
            }

            var a = state[0], b = state[1], c = state[2], d = state[3]
            for index in 0..<64 {
                var mixed: UInt32
                let wordIndex: Int
                switch index {
                case 0..<16:
                    mixed = (b & c) | (~b & d)
                    wordIndex = index
                case 16..<32:
                    mixed = (d & b) | (~d & c)
                    wordIndex = (5 * index + 1) % 16
                case 32..<48:
                    mixed = b ^ c ^ d
                    wordIndex = (3 * index + 5) % 16
                default:
                    mixed = c ^ (b | ~d)
                    wordIndex = (7 * index) % 16
                }
                mixed = mixed &+ a &+ md5Constants[index] &+ words[wordIndex]
                a = d
                d = c
                c = b
                b = b &+ rotateLeft(mixed, md5Shifts[index])
            }
            state[0] = state[0] &+ a
            state[1] = state[1] &+ b
            state[2] = state[2] &+ c
            state[3] = state[3] &+ d
        }

        var digest: [UInt8] = []
        for word in state {
            for shift in stride(from: 0, through: 24, by: 8) {
                digest.append(UInt8(truncatingIfNeeded: word >> UInt32(shift)))
            }
        }
        return digest
    }
}
