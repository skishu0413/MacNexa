import XCTest
import CryptoKit
@testable import MacNexaCore

final class TrustStoreTests: XCTestCase {
    private func peer() -> TrustedPeer {
        TrustedPeer(id: UUID(), publicKey: PeerIdentity().publicKeyData, displayName: "Mac mini")
    }

    func testUnknownSenderIsNotTrusted() {
        let store = TrustStore()
        XCTAssertFalse(store.isTrusted(id: UUID()))
        XCTAssertNil(store.peer(for: UUID()))
    }

    func testTrustThenLookup() {
        let store = TrustStore()
        let p = peer()
        store.trust(p)
        XCTAssertTrue(store.isTrusted(id: p.id))
        XCTAssertEqual(store.peer(for: p.id), p)
    }

    func testRevokeRemovesTrust() {
        let p = peer()
        let store = TrustStore(peers: [p])
        store.revoke(id: p.id)
        XCTAssertFalse(store.isTrusted(id: p.id))
    }
}
