import XCTest
@testable import MacNexaCore

final class ReplayProtectionTests: XCTestCase {
    func testAcceptsFreshMessage() throws {
        let clock = MutableClock(now: 1000)
        let sut = ReplayProtection(clock: clock)
        XCTAssertNoThrow(try sut.validate(messageId: UUID(), timestamp: 1000))
    }

    func testRejectsReplayedMessageId() throws {
        let clock = MutableClock(now: 1000)
        let sut = ReplayProtection(clock: clock)
        let id = UUID()
        try sut.validate(messageId: id, timestamp: 1000)
        XCTAssertThrowsError(try sut.validate(messageId: id, timestamp: 1000)) { error in
            XCTAssertEqual(error as? ProtocolError, .replayDetected)
        }
    }

    func testRejectsStaleTimestamp() {
        let clock = MutableClock(now: 1000)
        let sut = ReplayProtection(clock: clock, window: 30)
        XCTAssertThrowsError(try sut.validate(messageId: UUID(), timestamp: 900)) { error in
            XCTAssertEqual(error as? ProtocolError, .timestampOutOfWindow)
        }
    }

    func testRejectsFutureTimestampBeyondWindow() {
        let clock = MutableClock(now: 1000)
        let sut = ReplayProtection(clock: clock, window: 30)
        XCTAssertThrowsError(try sut.validate(messageId: UUID(), timestamp: 1100)) { error in
            XCTAssertEqual(error as? ProtocolError, .timestampOutOfWindow)
        }
    }

    func testEvictsOldestBeyondCapacity() throws {
        let clock = MutableClock(now: 1000)
        let sut = ReplayProtection(clock: clock, window: 100, capacity: 2)
        let first = UUID()
        try sut.validate(messageId: first, timestamp: 1000)
        try sut.validate(messageId: UUID(), timestamp: 1000)
        try sut.validate(messageId: UUID(), timestamp: 1000) // evicts `first`
        // `first` is no longer remembered, so it is accepted again.
        XCTAssertNoThrow(try sut.validate(messageId: first, timestamp: 1000))
    }
}
