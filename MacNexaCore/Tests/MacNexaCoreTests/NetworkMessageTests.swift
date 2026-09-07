import XCTest
@testable import MacNexaCore

final class NetworkMessageTests: XCTestCase {
    private func sampleMessage() -> NetworkMessage {
        NetworkMessage(
            senderId: UUID(),
            timestamp: 1_000_000,
            nonce: Nonce.generate(),
            type: .ping
        )
    }

    func testSerializeDeserializeRoundTrip() throws {
        let message = sampleMessage()
        let data = try message.serialize()
        let decoded = try NetworkMessage.deserialize(data)
        XCTAssertEqual(message, decoded)
    }

    func testSignedDataExcludesAuthentication() throws {
        var message = sampleMessage()
        let before = try message.signedData()
        message.authentication = "some-tag"
        let after = try message.signedData()
        XCTAssertEqual(before, after, "signedData must not depend on the authentication field")
    }

    func testDefaultsToCurrentProtocolVersion() {
        XCTAssertEqual(sampleMessage().version, Constants.protocolVersion)
    }
}
