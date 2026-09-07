import Foundation
import CryptoKit

/// A long-term cryptographic identity for this Mac (spec §15).
///
/// The private key belongs in the Keychain; this type only models the key
/// material and the key-agreement/derivation logic, which is unit-testable.
public struct PeerIdentity: Sendable {
    public let privateKey: Curve25519.KeyAgreement.PrivateKey

    public init(privateKey: Curve25519.KeyAgreement.PrivateKey = .init()) {
        self.privateKey = privateKey
    }

    public var publicKeyData: Data {
        privateKey.publicKey.rawRepresentation
    }

    /// Derives a symmetric authentication key shared with a peer via Curve25519
    /// key agreement followed by HKDF-SHA256 (spec §15).
    public func deriveAuthenticationKey(
        withPeerPublicKey peerPublicKeyData: Data,
        salt: Data = Data(),
        info: Data = Data("macnexa-auth-v1".utf8)
    ) throws -> SymmetricKey {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKeyData)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: 32
        )
    }
}
