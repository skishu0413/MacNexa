import Foundation
import CryptoKit

/// Loads or creates this Mac's long-term Curve25519 identity, persisting the
/// private key in a `SecretStoring` (Keychain in production). The private key is
/// never exposed outside this type except as an in-memory `PeerIdentity`.
public final class IdentityStore {
    private let secrets: SecretStoring
    private let privateKeyKey = "macnexa.identity.privateKey"
    private let peerIdKey = "macnexa.identity.peerId"

    public init(secrets: SecretStoring) {
        self.secrets = secrets
    }

    /// Returns the stable peer id for this Mac, creating one if needed.
    public func loadOrCreatePeerId() throws -> UUID {
        if let data = try secrets.secret(for: peerIdKey),
           let string = String(data: data, encoding: .utf8),
           let id = UUID(uuidString: string) {
            return id
        }
        let id = UUID()
        try secrets.setSecret(Data(id.uuidString.utf8), for: peerIdKey)
        return id
    }

    /// Returns this Mac's identity, generating and persisting a new key on first use.
    public func loadOrCreateIdentity() throws -> PeerIdentity {
        if let data = try secrets.secret(for: privateKeyKey) {
            let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
            return PeerIdentity(privateKey: key)
        }
        let identity = PeerIdentity()
        try secrets.setSecret(identity.privateKey.rawRepresentation, for: privateKeyKey)
        return identity
    }
}
