import XCTest
@testable import MacNexaCore

final class RetryPolicyTests: XCTestCase {
    func testNoDelayBeforeFirstAttempt() {
        let policy = RetryPolicy(maxAttempts: 3, backoff: 2)
        XCTAssertEqual(policy.delay(beforeAttempt: 1), 0)
        XCTAssertEqual(policy.delay(beforeAttempt: 2), 2)
    }

    func testSucceedsOnFirstAttempt() async throws {
        let policy = RetryPolicy(maxAttempts: 3, backoff: 0)
        var attempts = 0
        let result = try await policy.run(operation: { _ in
            attempts += 1
            return "ok"
        }, sleep: { _ in })
        XCTAssertEqual(result, "ok")
        XCTAssertEqual(attempts, 1)
    }

    func testRetriesThenSucceeds() async throws {
        let policy = RetryPolicy(maxAttempts: 3, backoff: 0)
        var attempts = 0
        let result = try await policy.run(operation: { attempt in
            attempts += 1
            if attempt < 3 { throw SwitchError.keyboardConnectionFailed }
            return attempt
        }, sleep: { _ in })
        XCTAssertEqual(result, 3)
        XCTAssertEqual(attempts, 3)
    }

    func testExhaustsAttemptsAndThrowsLastError() async {
        let policy = RetryPolicy(maxAttempts: 2, backoff: 0)
        var attempts = 0
        do {
            _ = try await policy.run(operation: { _ -> Int in
                attempts += 1
                throw SwitchError.trackpadConnectionFailed
            }, sleep: { _ in })
            XCTFail("Expected failure")
        } catch {
            XCTAssertEqual(error as? SwitchError, .trackpadConnectionFailed)
            XCTAssertEqual(attempts, 2)
        }
    }
}
