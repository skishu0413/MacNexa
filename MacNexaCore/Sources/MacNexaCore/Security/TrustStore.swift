import Foundation
import CryptoKit

/// A peer that has completed explicit pairing and is authorized to issue
/// commands (spec §14). Binds a stable peer id to its long-term public key.
public struct TrustedPeer: Equatable, Sendable {
    public let id: UUID
    public let publicKey: Data
    public let displayName: String

    public init(id: UUID, publicKey: Data, displayName: String) {
        self.id = id
        self.publicKey = publicKey
        self.displayName = displayName
    }
}

/// The authority on which peers are trusted. A message is only acted upon if its
/// `senderId` resolves to a `TrustedPeer` here (spec §13 "unauthorized peer",
/// §14 trust establishment). Fails closed: unknown senders are rejected.
///
/// Not thread-safe on its own; confine to an actor at the app layer.
public final class TrustStore {
    private var peers: [UUID: TrustedPeer] = [:]

    public init(peers: [TrustedPeer] = []) {
        for peer in peers { self.peers[peer.id] = peer }
    }

    public var trustedPeers: [TrustedPeer] { Array(peers.values) }

    /// Adds/updates a peer only after explicit user-authorized pairing.
    public func trust(_ peer: TrustedPeer) {
        peers[peer.id] = peer
    }

    /// Revokes trust so the peer can no longer issue commands.
    public func revoke(id: UUID) {
        peers[id] = nil
    }

    public func isTrusted(id: UUID) -> Bool {
        peers[id] != nil
    }

    public func peer(for id: UUID) -> TrustedPeer? {
        peers[id]
    }
}
