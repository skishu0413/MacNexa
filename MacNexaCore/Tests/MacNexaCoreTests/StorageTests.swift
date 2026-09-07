import XCTest
import CryptoKit
@testable import MacNexaCore

final class StorageTests: XCTestCase {
    func testIdentityIsStableAcrossLoads() throws {
        let secrets = InMemorySecretStore()
        let store = IdentityStore(secrets: secrets)
        let a = try store.loadOrCreateIdentity()
        let b = try store.loadOrCreateIdentity()
        XCTAssertEqual(a.publicKeyData, b.publicKeyData)
    }

    func testPeerIdIsStableAcrossLoads() throws {
        let secrets = InMemorySecretStore()
        let store = IdentityStore(secrets: secrets)
        XCTAssertEqual(try store.loadOrCreatePeerId(), try store.loadOrCreatePeerId())
    }

    func testTrustPersistsAcrossInstances() throws {
        let secrets = InMemorySecretStore()
        let peer = TrustedPeer(id: UUID(), publicKey: PeerIdentity().publicKeyData, displayName: "Mac mini")
        let store1 = try PersistentTrustStore(secrets: secrets)
        try store1.trust(peer)
        // New instance rehydrates from the same secret store.
        let store2 = try PersistentTrustStore(secrets: secrets)
        XCTAssertTrue(store2.store.isTrusted(id: peer.id))
    }

    func testRevokeRemovesPersistedTrust() throws {
        let secrets = InMemorySecretStore()
        let peer = TrustedPeer(id: UUID(), publicKey: PeerIdentity().publicKeyData, displayName: "X")
        let store = try PersistentTrustStore(secrets: secrets)
        try store.trust(peer)
        try store.revoke(id: peer.id)
        let reloaded = try PersistentTrustStore(secrets: secrets)
        XCTAssertFalse(reloaded.store.isTrusted(id: peer.id))
    }
}
