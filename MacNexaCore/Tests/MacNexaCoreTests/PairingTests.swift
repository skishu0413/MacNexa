import XCTest
@testable import MacNexaCore

final class PairingTests: XCTestCase {
    func testGeneratedCodeIsSixDigits() {
        for _ in 0..<50 {
            let code = PairingCode.generate()
            XCTAssertEqual(code.digits.count, 6)
            XCTAssertTrue(code.digits.allSatisfy { $0.isNumber })
        }
    }

    func testDisplayValueIsGrouped() {
        XCTAssertEqual(PairingCode(digits: "823491").displayValue, "823 491")
    }

    func testMatchesAcceptsSameCodeIgnoringSpaces() {
        let code = PairingCode(digits: "823491")
        XCTAssertTrue(code.matches("823491"))
        XCTAssertTrue(code.matches("823 491"))
    }

    func testMatchesRejectsWrongCode() {
        XCTAssertFalse(PairingCode(digits: "823491").matches("000000"))
        XCTAssertFalse(PairingCode(digits: "823491").matches("82349"))
    }

    func testExchangeProducesTrustedPeer() throws {
        let identity = PeerIdentity()
        let exchange = PairingExchange(peerId: UUID(), publicKey: identity.publicKeyData, displayName: "Mac mini")
        let peer = try PairingValidator().makeTrustedPeer(from: exchange)
        XCTAssertEqual(peer.publicKey, identity.publicKeyData)
    }

    func testExchangeRejectsBadPublicKey() {
        let exchange = PairingExchange(peerId: UUID(), publicKey: Data([1, 2, 3]), displayName: "X")
        XCTAssertThrowsError(try PairingValidator().makeTrustedPeer(from: exchange)) { error in
            XCTAssertEqual(error as? PairingError, .invalidPublicKey)
        }
    }
}
