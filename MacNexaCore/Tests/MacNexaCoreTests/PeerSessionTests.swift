import XCTest
import CryptoKit
@testable import MacNexaCore

private final class CollectingDelegate: PeerSessionDelegate, @unchecked Sendable {
    var received: [(NetworkMessage, TrustedPeer)] = []
    var closed = false
    let expectation: XCTestExpectation?
    init(expectation: XCTestExpectation? = nil) { self.expectation = expectation }

    func session(_ session: PeerSession, didReceive message: NetworkMessage, from peer: TrustedPeer) async {
        received.append((message, peer))
        expectation?.fulfill()
    }
    func sessionDidClose(_ session: PeerSession) async { closed = true }
}

final class PeerSessionTests: XCTestCase {

    func testMutuallyTrustedSessionsExchangeValidatedMessage() async throws {
        // Two Macs: A and B, each with an identity and peer id.
        let idA = PeerIdentity(), idB = PeerIdentity()
        let peerIdA = UUID(), peerIdB = UUID()
        let clock = MutableClock(now: 1000)

        // A trusts B; B trusts A.
        let trustA = TrustStore(peers: [TrustedPeer(id: peerIdB, publicKey: idB.publicKeyData, displayName: "B")])
        let trustB = TrustStore(peers: [TrustedPeer(id: peerIdA, publicKey: idA.publicKeyData, displayName: "A")])

        let validatorA = CommandValidator(trustStore: trustA, replay: ReplayProtection(clock: clock),
                                          rateLimiter: RateLimiter(clock: clock), localIdentity: idA)
        let validatorB = CommandValidator(trustStore: trustB, replay: ReplayProtection(clock: clock),
                                          rateLimiter: RateLimiter(clock: clock), localIdentity: idB)

        let (transportA, transportB) = InMemoryTransport.makePair()

        let sessionA = PeerSession(transport: transportA, localIdentity: idA, localPeerId: peerIdA,
                                   remotePeer: TrustedPeer(id: peerIdB, publicKey: idB.publicKeyData, displayName: "B"),
                                   validator: validatorA, clock: clock)
        let sessionB = PeerSession(transport: transportB, localIdentity: idB, localPeerId: peerIdB,
                                   remotePeer: TrustedPeer(id: peerIdA, publicKey: idA.publicKeyData, displayName: "A"),
                                   validator: validatorB, clock: clock)

        let expect = expectation(description: "B receives PING")
        let delegateB = CollectingDelegate(expectation: expect)
        await sessionB.setDelegate(delegateB)
        await sessionA.start()
        await sessionB.start()

        // A sends a PING to B.
        try await sessionA.send(type: .ping)
        await fulfillment(of: [expect], timeout: 2)

        XCTAssertEqual(delegateB.received.count, 1)
        XCTAssertEqual(delegateB.received.first?.0.type, .ping)
        XCTAssertEqual(delegateB.received.first?.1.id, peerIdA)
    }

    func testUntrustedSenderMessageIsDropped() async throws {
        let idA = PeerIdentity(), idB = PeerIdentity()
        let peerIdA = UUID(), peerIdB = UUID()
        let clock = MutableClock(now: 1000)

        // B does NOT trust A.
        let trustB = TrustStore()
        let validatorB = CommandValidator(trustStore: trustB, replay: ReplayProtection(clock: clock),
                                          rateLimiter: RateLimiter(clock: clock), localIdentity: idB)
        let (transportA, transportB) = InMemoryTransport.makePair()

        let sessionA = PeerSession(transport: transportA, localIdentity: idA, localPeerId: peerIdA,
                                   remotePeer: TrustedPeer(id: peerIdB, publicKey: idB.publicKeyData, displayName: "B"),
                                   validator: validatorB, clock: clock)
        let sessionB = PeerSession(transport: transportB, localIdentity: idB, localPeerId: peerIdB,
                                   remotePeer: nil, validator: validatorB, clock: clock)

        let delegateB = CollectingDelegate()
        await sessionB.setDelegate(delegateB)
        await sessionA.start()
        await sessionB.start()

        try await sessionA.send(type: .releaseDevices)
        // Give the async pipeline a moment.
        try await Task.sleep(nanoseconds: 200_000_000)

        XCTAssertTrue(delegateB.received.isEmpty, "untrusted command must be dropped")
        let err = await sessionB.lastValidationError
        XCTAssertEqual(err, .untrustedSender)
    }
}
