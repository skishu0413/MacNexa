import XCTest
import CryptoKit
@testable import MacNexaCore

final class PeerIdentityTests: XCTestCase {
    func testBothPeersDeriveSameAuthenticationKey() throws {
        let a = PeerIdentity()
        let b = PeerIdentity()
        let keyA = try a.deriveAuthenticationKey(withPeerPublicKey: b.publicKeyData)
        let keyB = try b.deriveAuthenticationKey(withPeerPublicKey: a.publicKeyData)
        XCTAssertEqual(
            keyA.withUnsafeBytes { Data($0) },
            keyB.withUnsafeBytes { Data($0) },
            "Key agreement + HKDF must yield an identical shared key on both sides"
        )
    }

    func testDerivedKeyRoundTripsThroughSigner() throws {
        let a = PeerIdentity()
        let b = PeerIdentity()
        let keyA = try a.deriveAuthenticationKey(withPeerPublicKey: b.publicKeyData)
        let keyB = try b.deriveAuthenticationKey(withPeerPublicKey: a.publicKeyData)
        let msg = NetworkMessage(senderId: UUID(), timestamp: 1, nonce: Nonce.generate(), type: .ping)
        let signed = try MessageSigner(authenticationKey: keyA).sign(msg)
        XCTAssertNoThrow(try MessageSigner(authenticationKey: keyB).verify(signed))
    }

    func testInvalidPeerKeyThrows() {
        let a = PeerIdentity()
        XCTAssertThrowsError(try a.deriveAuthenticationKey(withPeerPublicKey: Data([0x01, 0x02])))
    }
}
