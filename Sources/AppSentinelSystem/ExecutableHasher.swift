import Foundation
import CryptoKit
import AppSentinelCore

/// Hashes an executable's bytes with SHA-256 via Apple's built-in
/// CryptoKit system framework (not a third-party dependency) for evidence.
/// The digest is all that is ever persisted; the bytes themselves are read
/// only transiently, in memory, and discarded.
public struct RealExecutableHasher: ExecutableHashing {
    /// Executables larger than this are not hashed, to bound memory use
    /// and avoid stalling the session on a pathologically large binary.
    public let maximumFileSize: Int

    public init(maximumFileSize: Int = 256 * 1024 * 1024) {
        self.maximumFileSize = maximumFileSize
    }

    public func sha256(ofFileAt path: String) -> String? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attributes[.size] as? Int,
              size <= maximumFileSize,
              let data = FileManager.default.contents(atPath: path) else {
            return nil
        }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
