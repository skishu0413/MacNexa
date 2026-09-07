import Foundation
import CryptoKit

/// A short human-verifiable pairing code shown on one Mac and entered on the
/// other (spec §14). Six digits, generated from a secure RNG.
public struct PairingCode: Equatable, Sendable {
    public let digits: String   // e.g. "823491"

    public init(digits: String) { self.digits = digits }

    /// Generates a fresh 6-digit code.
    public static func generate() -> PairingCode {
        var rng = SystemRandomNumberGenerator()
        let value = Int.random(in: 0...999_999, using: &rng)
        return PairingCode(digits: String(format: "%06d", value))
    }

    /// Formatted for display, e.g. "823 491".
    public var displayValue: String {
        guard digits.count == 6 else { return digits }
        let mid = digits.index(digits.startIndex, offsetBy: 3)
        return "\(digits[digits.startIndex..<mid]) \(digits[mid...])"
    }

    /// Constant-time comparison of an entered code against this one.
    public func matches(_ entered: String) -> Bool {
        let normalized = entered.filter { $0.isNumber }
        guard normalized.count == digits.count else { return false }
        let a = Array(digits.utf8), b = Array(normalized.utf8)
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}

/// The public information two Macs exchange during pairing (spec §14). No
/// secrets are exchanged in the clear; only public keys and identities.
public struct PairingExchange: Codable, Equatable, Sendable {
    public let peerId: UUID
    public let publicKey: Data
    public let displayName: String

    public init(peerId: UUID, publicKey: Data, displayName: String) {
        self.peerId = peerId
        self.publicKey = publicKey
        self.displayName = displayName
    }
}

/// Drives the pairing state on one side of the exchange.
public enum PairingError: Error, Equatable, Sendable {
    case codeMismatch
    case invalidPublicKey
}

/// Validates a peer's pairing exchange and produces a `TrustedPeer` once the
/// code has been verified out-of-band by the user.
public struct PairingValidator: Sendable {
    public init() {}

    public func makeTrustedPeer(from exchange: PairingExchange) throws -> TrustedPeer {
        guard exchange.publicKey.count == Constants.Security.publicKeyLength else {
            throw PairingError.invalidPublicKey
        }
        return TrustedPeer(id: exchange.peerId, publicKey: exchange.publicKey, displayName: exchange.displayName)
    }
}
