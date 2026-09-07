import Foundation

/// States of a single handoff transaction (spec §18).
public enum SwitchState: String, Codable, Sendable, Equatable {
    case idle
    case preparing
    case requestingRelease
    case waitingForRelease
    case connectingKeyboard
    case connectingTrackpad
    case verifying
    case completed
    case failed
    case rollback
}

/// Events that drive the state machine forward.
public enum SwitchEvent: Sendable, Equatable {
    case begin
    case releaseRequested
    case releaseConfirmed
    case keyboardConnected
    case trackpadConnected
    case verified
    case fail
    case rolledBack
    case reset
}
