import XCTest
@testable import MacNexaCore

final class NetworkMessageHardeningTests: XCTestCase {
    private func message(nonce: String = Nonce.generate(), version: Int = Constants.protocolVersion) -> NetworkMessage {
        NetworkMessage(version: version, senderId: UUID(), timestamp: 1000, nonce: nonce, type: .ping)
    }

    func testOversizedFrameIsRejected() {
        let big = Data(repeating: 0x41, count: Constants.Security.maxMessageBytes + 1)
        XCTAssertThrowsError(try NetworkMessage.deserialize(big)) { error in
            guard case ProtocolError.messageTooLarge = error else {
                return XCTFail("expected messageTooLarge, got \(error)")
            }
        }
    }

    func testMalformedFrameIsRejected() {
        XCTAssertThrowsError(try NetworkMessage.deserialize(Data("{not json".utf8))) { error in
            XCTAssertEqual(error as? ProtocolError, .malformedMessage)
        }
    }

    func testWeakNonceIsRejected() {
        XCTAssertThrowsError(try message(nonce: "AAAA").validateStructure()) { error in
            XCTAssertEqual(error as? ProtocolError, .weakNonce)
        }
    }

    func testUnsupportedVersionIsRejected() {
        XCTAssertThrowsError(try message(version: 99).validateStructure()) { error in
            XCTAssertEqual(error as? ProtocolError, .unsupportedVersion(99))
        }
    }

    func testValidMessagePassesStructure() {
        XCTAssertNoThrow(try message().validateStructure())
    }
}
