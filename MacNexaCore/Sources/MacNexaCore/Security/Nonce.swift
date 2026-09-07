import Foundation
import CryptoKit

/// Generates cryptographically secure nonces for protocol messages (spec §16).
public enum Nonce {
    /// A fresh base64-encoded nonce with at least the required entropy.
    public static func generate(byteCount: Int = Constants.Security.minNonceLength) -> String {
        precondition(byteCount >= Constants.Security.minNonceLength)
        var bytes = [UInt8](repeating: 0, count: byteCount)
        // SecRandomCopyBytes-backed secure RNG via SystemRandomNumberGenerator.
        var rng = SystemRandomNumberGenerator()
        for i in 0..<byteCount { bytes[i] = UInt8.random(in: 0...255, using: &rng) }
        return Data(bytes).base64EncodedString()
    }
}
