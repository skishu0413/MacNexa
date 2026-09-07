import XCTest
import CryptoKit
@testable import MacNexaCore

final class MessageSignerTests: XCTestCase {
    private func message() -> NetworkMessage {
        NetworkMessage(senderId: UUID(), timestamp: 1000, nonce: Nonce.generate(), type: .releaseDevices)
    }

    func testSignThenVerifySucceeds() throws {
        let signer = MessageSigner(authenticationKey: SymmetricKey(size: .bits256))
        let signed = try signer.sign(message())
        XCTAssertNotNil(signed.authentication)
        XCTAssertNoThrow(try signer.verify(signed))
    }

    func testVerifyFailsForTamperedMessage() throws {
        let signer = MessageSigner(authenticationKey: SymmetricKey(size: .bits256))
        var signed = try signer.sign(message())
        signed = NetworkMessage(
            version: signed.version,
            messageId: signed.messageId,
            senderId: signed.senderId,
            timestamp: signed.timestamp + 1, // tamper
            nonce: signed.nonce,
            type: signed.type,
            payload: signed.payload,
            authentication: signed.authentication
        )
        XCTAssertThrowsError(try signer.verify(signed)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }

    func testVerifyFailsWithWrongKey() throws {
        let signed = try MessageSigner(authenticationKey: SymmetricKey(size: .bits256)).sign(message())
        let other = MessageSigner(authenticationKey: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try other.verify(signed)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }

    func testVerifyFailsWhenUnsigned() {
        let signer = MessageSigner(authenticationKey: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try signer.verify(message())) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidAuthentication)
        }
    }
}
