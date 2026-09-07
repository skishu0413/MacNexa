import XCTest
@testable import MacNexaCore

private final class PairingDelegate: PeerSessionDelegate, @unchecked Sendable {
    var pairingMessages: [PairingMessage] = []
    var commandMessages: [NetworkMessage] = []
    let expectation: XCTestExpectation
    init(_ e: XCTestExpectation) { self.expectation = e }

    func session(_ session: PeerSession, didReceive message: NetworkMessage, from peer: TrustedPeer) async {
        commandMessages.append(message)
    }
    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async {
        pairingMessages.append(message)
        expectation.fulfill()
    }
    func sessionDidClose(_ session: PeerSession) async {}
}

final class PeerSessionPairingTests: XCTestCase {
    func testPairingMessageDeliveredWithoutTrust() async throws {
        let idA = PeerIdentity(), idB = PeerIdentity()
        let clock = MutableClock(now: 1000)

        // B trusts no one; a pairing message must STILL be delivered (bypasses gate).
        let validatorB = CommandValidator(trustStore: TrustStore(), replay: ReplayProtection(clock: clock),
                                          rateLimiter: RateLimiter(clock: clock), localIdentity: idB)
        let (tA, tB) = InMemoryTransport.makePair()

        let sessionA = PeerSession(transport: tA, localIdentity: idA, localPeerId: UUID(),
                                   remotePeer: nil, validator: validatorB, clock: clock)
        let sessionB = PeerSession(transport: tB, localIdentity: idB, localPeerId: UUID(),
                                   remotePeer: nil, validator: validatorB, clock: clock)

        let expect = expectation(description: "pairing delivered")
        let delegateB = PairingDelegate(expect)
        await sessionB.setDelegate(delegateB)
        await sessionA.start(); await sessionB.start()

        let exchange = PairingExchange(peerId: UUID(), publicKey: idA.publicKeyData, displayName: "A")
        try await sessionA.sendPairing(.hello(exchange, nonce: PairingSession.freshNonce()))
        await fulfillment(of: [expect], timeout: 2)

        XCTAssertEqual(delegateB.pairingMessages.count, 1)
        XCTAssertTrue(delegateB.commandMessages.isEmpty)
    }
}
