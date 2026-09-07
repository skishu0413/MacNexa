import XCTest
@testable import MacNexaCore

final class NonceTests: XCTestCase {
    func testGeneratesSufficientEntropy() {
        let nonce = Nonce.generate()
        let decoded = Data(base64Encoded: nonce)
        XCTAssertNotNil(decoded)
        XCTAssertGreaterThanOrEqual(decoded!.count, Constants.Security.minNonceLength)
    }

    func testNoncesAreUnique() {
        let a = Nonce.generate()
        let b = Nonce.generate()
        XCTAssertNotEqual(a, b)
    }
}
