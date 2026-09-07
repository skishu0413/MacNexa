import XCTest
import CryptoKit
@testable import MacNexaCore

final class PairingSessionTests: XCTestCase {
    private func exchange(_ id: PeerIdentity, name: String) -> PairingExchange {
        PairingExchange(peerId: UUID(), publicKey: id.publicKeyData, displayName: name)
    }

    func testBothSidesDeriveSameCode() {
        let idA = PeerIdentity(), idB = PeerIdentity()
        let a = PairingSession(localExchange: exchange(idA, name: "A"))
        let b = PairingSession(localExchange: exchange(idB, name: "B"))

        let codeA = a.verificationCode(withRemote: b.localExchange, remoteNonce: b.localNonce)
        let codeB = b.verificationCode(withRemote: a.localExchange, remoteNonce: a.localNonce)
        XCTAssertEqual(codeA, codeB, "SAS must match on both Macs")
        XCTAssertEqual(codeA.digits.count, 6)
    }

    func testTamperedKeyProducesDifferentCode() {
        let idA = PeerIdentity(), idB = PeerIdentity(), attacker = PeerIdentity()
        let a = PairingSession(localExchange: exchange(idA, name: "A"))
        let b = PairingSession(localExchange: exchange(idB, name: "B"))

        // A computes against B's real key.
        let honest = a.verificationCode(withRemote: b.localExchange, remoteNonce: b.localNonce)
        // A computes against an attacker-substituted key (MITM).
        let tampered = a.verificationCode(
            withRemote: PairingExchange(peerId: b.localExchange.peerId, publicKey: attacker.publicKeyData, displayName: "B"),
            remoteNonce: b.localNonce
        )
        XCTAssertNotEqual(honest, tampered, "a substituted key must change the code so the user can reject")
    }

    func testConfirmProducesTrustedPeerWithCorrectKey() throws {
        let idA = PeerIdentity(), idB = PeerIdentity()
        let a = PairingSession(localExchange: exchange(idA, name: "A"))
        let peer = try a.confirm(remote: exchange(idB, name: "B"))
        XCTAssertEqual(peer.publicKey, idB.publicKeyData)
    }

    func testPairingMessageCodableRoundTrip() throws {
        let idA = PeerIdentity()
        let msg = PairingMessage.hello(exchange(idA, name: "A"), nonce: PairingSession.freshNonce())
        let data = try JSONEncoder().encode(msg)
        let decoded = try JSONDecoder().decode(PairingMessage.self, from: data)
        XCTAssertEqual(msg, decoded)
    }
}
