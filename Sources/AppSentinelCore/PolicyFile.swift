import Foundation

/// Decodes a JSON policy file into a `SecurityPolicy`. The on-disk schema
/// is exactly `SecurityPolicy`'s `Codable` representation, so the example
/// policy shipped in `policies/` doubles as living documentation of the
/// format.
public enum PolicyFile {
    public static func decode(_ data: Data) throws -> SecurityPolicy {
        let decoder = JSONDecoder()
        return try decoder.decode(SecurityPolicy.self, from: data)
    }
}
