import XCTest
@testable import MacNexaCore

final class SwitchStateMachineTests: XCTestCase {
    func testHappyPathReachesCompleted() throws {
        var sm = SwitchStateMachine()
        try sm.apply(.begin)
        XCTAssertEqual(sm.state, .preparing)
        try sm.apply(.releaseRequested)
        XCTAssertEqual(sm.state, .requestingRelease)
        try sm.apply(.releaseRequested)
        XCTAssertEqual(sm.state, .waitingForRelease)
        try sm.apply(.releaseConfirmed)
        XCTAssertEqual(sm.state, .connectingKeyboard)
        try sm.apply(.keyboardConnected)
        XCTAssertEqual(sm.state, .connectingTrackpad)
        try sm.apply(.trackpadConnected)
        XCTAssertEqual(sm.state, .verifying)
        try sm.apply(.verified)
        XCTAssertEqual(sm.state, .completed)
        XCTAssertTrue(sm.isTerminal)
    }

    func testIllegalTransitionThrowsConflict() {
        var sm = SwitchStateMachine()
        XCTAssertThrowsError(try sm.apply(.verified)) { error in
            XCTAssertEqual(error as? SwitchError, .transactionConflict)
        }
        XCTAssertEqual(sm.state, .idle)
    }

    func testFailureFromActiveStateRollsBackToIdle() throws {
        var sm = SwitchStateMachine()
        try sm.apply(.begin)
        try sm.apply(.releaseRequested)
        try sm.apply(.fail)
        XCTAssertEqual(sm.state, .failed)
        try sm.apply(.rolledBack)
        XCTAssertEqual(sm.state, .rollback)
        try sm.apply(.reset)
        XCTAssertEqual(sm.state, .idle)
    }

    func testCannotFailFromIdle() {
        var sm = SwitchStateMachine()
        XCTAssertFalse(sm.canHandle(.fail))
        XCTAssertThrowsError(try sm.apply(.fail))
    }

    func testCannotFailFromCompleted() throws {
        var sm = SwitchStateMachine(state: .completed)
        XCTAssertFalse(sm.canHandle(.fail))
    }

    func testIsActiveReflectsInFlightTransaction() throws {
        var sm = SwitchStateMachine()
        XCTAssertFalse(sm.isActive)
        try sm.apply(.begin)
        XCTAssertTrue(sm.isActive)
    }
}
