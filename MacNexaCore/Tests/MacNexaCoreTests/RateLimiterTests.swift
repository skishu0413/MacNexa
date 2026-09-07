import XCTest
@testable import MacNexaCore

final class RateLimiterTests: XCTestCase {
    func testAllowsUpToLimitThenBlocks() {
        let clock = MutableClock(now: 0)
        let sut = RateLimiter(clock: clock, limit: 3, window: 10)
        let sender = UUID()
        XCTAssertTrue(sut.allow(sender: sender))
        XCTAssertTrue(sut.allow(sender: sender))
        XCTAssertTrue(sut.allow(sender: sender))
        XCTAssertFalse(sut.allow(sender: sender), "4th within window must be blocked")
    }

    func testWindowSlides() {
        let clock = MutableClock(now: 0)
        let sut = RateLimiter(clock: clock, limit: 1, window: 10)
        let sender = UUID()
        XCTAssertTrue(sut.allow(sender: sender))
        XCTAssertFalse(sut.allow(sender: sender))
        clock.advance(by: 11)
        XCTAssertTrue(sut.allow(sender: sender), "after window expires, allowed again")
    }

    func testSendersAreIndependent() {
        let sut = RateLimiter(clock: MutableClock(now: 0), limit: 1, window: 10)
        XCTAssertTrue(sut.allow(sender: UUID()))
        XCTAssertTrue(sut.allow(sender: UUID()))
    }
}
