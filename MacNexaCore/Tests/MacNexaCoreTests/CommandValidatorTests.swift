import XCTest
import CryptoKit
@testable import MacNexaCore

/// End-to-end tests for the fail-closed command validation pipeline (spec §16).
/// Models an attacker on the local network attempting to trigger RELEASE_DEVICES.
final class CommandValidatorTests: XCTestCase {

    // Local Mac (receiver) and a legitimate trusted peer (sender).
    private var local: PeerIdentity!
    private var peer: PeerIdentity!
    private var senderId: UUID!
    private var clock: MutableClock!
    private var trust: TrustStore!
    private var validator: CommandValidator!

    override func setUp() {
        super.setUp()
        local = PeerIdentity()
        peer = PeerIdentity()
        senderId = UUID()
        clock = MutableClock(now: 1000)
        trust = TrustStore(peers: [
            TrustedPeer(id: senderId, publicKey: peer.publicKeyData, displayName: "Mac mini")
        ])
        validator = CommandValidator(
            trustStore: trust,
            replay: ReplayProtection(clock: clock, window: 30),
            rateLimiter: RateLimiter(clock: clock, limit: 5, window: 10),
            localIdentity: local
        )
    }

    /// Builds a message signed by `signerIdentity`'s shared key with `local`.
    private func signedMessage(
        from sender: UUID,
        signerIdentity: PeerIdentity,
        type: MessageType = .releaseDevices,
        timestamp: TimeInterval? = nil
    ) throws -> NetworkMessage {
        let key = try signerIdentity.deriveAuthenticationKey(withPeerPublicKey: local.publicKeyData)
        let msg = NetworkMessage(
            senderId: sender,
            timestamp: timestamp ?? clock.now(),
            nonce: Nonce.generate(),
            type: type
        )
        return try MessageSigner(authenticationKey: key).sign(msg)
    }

    func testLegitimateCommandIsAccepted() throws {
        let msg = try signedMessage(from: senderId, signerIdentity: peer)
        let resolved = try validator.validate(msg)
        XCTAssertEqual(resolved.id, senderId)
    }

    func testUntrustedSenderIsRejected() throws {
        // Attacker uses an unknown senderId, even with a well-formed signature.
        let attacker = PeerIdentity()
        let msg = try signedMessage(from: UUID(), signerIdentity: attacker)
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .untrustedSender)
        }
    }

    func testSpoofedSenderWithWrongKeyIsRejected() throws {
        // Attacker claims the trusted senderId but signs with a different key.
        let attacker = PeerIdentity()
        let msg = try signedMessage(from: senderId, signerIdentity: attacker)
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }

    func testTamperedMessageIsRejected() throws {
        var msg = try signedMessage(from: senderId, signerIdentity: peer)
        // Flip the type after signing.
        msg = NetworkMessage(
            version: msg.version, messageId: msg.messageId, senderId: msg.senderId,
            transactionId: msg.transactionId, timestamp: msg.timestamp, nonce: msg.nonce,
            type: .connectDevices, payload: msg.payload, authentication: msg.authentication
        )
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }

    func testUnsignedMessageIsRejected() throws {
        let msg = NetworkMessage(senderId: senderId, timestamp: clock.now(),
                                 nonce: Nonce.generate(), type: .releaseDevices)
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }

    func testReplayedMessageIsRejected() throws {
        let msg = try signedMessage(from: senderId, signerIdentity: peer)
        XCTAssertNoThrow(try validator.validate(msg))
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .replayDetected)
        }
    }

    func testStaleMessageIsRejected() throws {
        let msg = try signedMessage(from: senderId, signerIdentity: peer, timestamp: clock.now() - 100)
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .timestampOutOfWindow)
        }
    }

    func testRevokedPeerIsRejected() throws {
        trust.revoke(id: senderId)
        let msg = try signedMessage(from: senderId, signerIdentity: peer)
        XCTAssertThrowsError(try validator.validate(msg)) { error in
            XCTAssertEqual(error as? ProtocolError, .untrustedSender)
        }
    }

    func testRateLimitBlocksFlood() throws {
        // 5 allowed, 6th blocked (distinct nonces/ids each time).
        for _ in 0..<5 {
            let msg = try signedMessage(from: senderId, signerIdentity: peer)
            XCTAssertNoThrow(try validator.validate(msg))
        }
        let flood = try signedMessage(from: senderId, signerIdentity: peer)
        XCTAssertThrowsError(try validator.validate(flood)) { error in
            XCTAssertEqual(error as? ProtocolError, .rateLimited)
        }
    }
}
