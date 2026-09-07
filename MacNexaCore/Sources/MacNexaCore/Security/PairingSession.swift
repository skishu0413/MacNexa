import Foundation
import CryptoKit

/// Messages exchanged during pairing, carried in the `payload` of HELLO/
/// AUTHENTICATE protocol messages (spec §14, §38).
public enum PairingMessage: Codable, Equatable, Sendable {
    /// Initiator → responder: my identity, public key, and a fresh nonce.
    case hello(PairingExchange, nonce: Data)
    /// Responder → initiator: my identity, public key, and my nonce.
    case ack(PairingExchange, nonce: Data)
}

/// A MITM-resistant pairing handshake (spec §13 "message spoofing", §14).
///
/// Both Macs exchange public keys and nonces, then INDEPENDENTLY derive a
/// 6-digit short authentication string (SAS) from a hash binding BOTH public
/// keys and BOTH nonces. The user compares the codes shown on each Mac; if an
/// attacker substituted a key in transit, the derived codes differ and the user
/// declines. Only after the user confirms the codes match is trust established.
public struct PairingSession: Sendable {
    public let localExchange: PairingExchange
    public let localNonce: Data

    public init(localExchange: PairingExchange, localNonce: Data = PairingSession.freshNonce()) {
        self.localExchange = localExchange
        self.localNonce = localNonce
    }

    public static func freshNonce(byteCount: Int = 16) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        var rng = SystemRandomNumberGenerator()
        for i in 0..<byteCount { bytes[i] = UInt8.random(in: 0...255, using: &rng) }
        return Data(bytes)
    }

    /// Derives the shared verification code from both sides' key material.
    /// Deterministic and order-independent: both Macs compute the same value.
    public static func verificationCode(
        localKey: Data, localNonce: Data,
        remoteKey: Data, remoteNonce: Data
    ) -> PairingCode {
        // Canonical ordering so both sides hash the same concatenation.
        let (k1, n1, k2, n2): (Data, Data, Data, Data)
        if localKey.lexicographicallyPrecedes(remoteKey) {
            (k1, n1, k2, n2) = (localKey, localNonce, remoteKey, remoteNonce)
        } else {
            (k1, n1, k2, n2) = (remoteKey, remoteNonce, localKey, localNonce)
        }
        var hasher = SHA256()
        hasher.update(data: Data("macnexa-sas-v1".utf8))
        hasher.update(data: k1); hasher.update(data: n1)
        hasher.update(data: k2); hasher.update(data: n2)
        let digest = hasher.finalize()
        // Take the first 4 bytes as a big-endian integer, reduce to 6 digits.
        let value = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return PairingCode(digits: String(format: "%06d", value % 1_000_000))
    }

    /// Computes the verification code for this session given the peer's exchange.
    public func verificationCode(withRemote remote: PairingExchange, remoteNonce: Data) -> PairingCode {
        Self.verificationCode(
            localKey: localExchange.publicKey, localNonce: localNonce,
            remoteKey: remote.publicKey, remoteNonce: remoteNonce
        )
    }

    /// After the user confirms codes match, produces the peer to trust.
    public func confirm(remote: PairingExchange) throws -> TrustedPeer {
        try PairingValidator().makeTrustedPeer(from: remote)
    }
}
