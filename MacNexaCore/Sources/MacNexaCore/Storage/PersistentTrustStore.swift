import Foundation

/// A Codable record of a trusted peer for persistence.
private struct TrustedPeerRecord: Codable {
    let id: UUID
    let publicKey: Data
    let displayName: String
}

/// A `TrustStore` whose contents are persisted through a `SecretStoring` so that
/// trusted peers survive app restarts (spec §29). Trusted-peer credentials are
/// sensitive and therefore stored in the secure store, not UserDefaults.
public final class PersistentTrustStore {
    private let secrets: SecretStoring
    private let prefix = "macnexa.trust."
    private let inner: TrustStore

    public init(secrets: SecretStoring) throws {
        self.secrets = secrets
        // Rehydrate any previously trusted peers.
        var loaded: [TrustedPeer] = []
        for key in try secrets.allKeys(withPrefix: prefix) {
            if let data = try secrets.secret(for: key),
               let record = try? JSONDecoder().decode(TrustedPeerRecord.self, from: data) {
                loaded.append(TrustedPeer(id: record.id, publicKey: record.publicKey, displayName: record.displayName))
            }
        }
        self.inner = TrustStore(peers: loaded)
    }

    /// The live, in-memory store used by the validator.
    public var store: TrustStore { inner }

    public func trust(_ peer: TrustedPeer) throws {
        inner.trust(peer)
        let record = TrustedPeerRecord(id: peer.id, publicKey: peer.publicKey, displayName: peer.displayName)
        try secrets.setSecret(try JSONEncoder().encode(record), for: prefix + peer.id.uuidString)
    }

    public func revoke(id: UUID) throws {
        inner.revoke(id: id)
        try secrets.removeSecret(for: prefix + id.uuidString)
    }
}
