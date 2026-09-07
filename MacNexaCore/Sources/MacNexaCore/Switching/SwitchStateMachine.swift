import Foundation

/// A deterministic state machine for a handoff transaction (spec §18).
///
/// Any state can transition to `.failed` via `.fail`; failure then rolls back
/// and returns to `.idle`. Invalid transitions are rejected so the system can
/// never reach an undefined switching state.
public struct SwitchStateMachine: Sendable, Equatable {
    public private(set) var state: SwitchState

    public init(state: SwitchState = .idle) {
        self.state = state
    }

    /// The valid "forward" transition for an event from the current state,
    /// ignoring the universal failure/reset transitions.
    private func forwardTarget(for event: SwitchEvent) -> SwitchState? {
        switch (state, event) {
        case (.idle, .begin): return .preparing
        case (.preparing, .releaseRequested): return .requestingRelease
        case (.requestingRelease, .releaseRequested): return .waitingForRelease
        case (.waitingForRelease, .releaseConfirmed): return .connectingKeyboard
        case (.connectingKeyboard, .keyboardConnected): return .connectingTrackpad
        case (.connectingTrackpad, .trackpadConnected): return .verifying
        case (.verifying, .verified): return .completed
        default: return nil
        }
    }

    /// Whether the given event is a legal transition from the current state.
    public func canHandle(_ event: SwitchEvent) -> Bool {
        switch event {
        case .fail:
            // Failure is legal from any active state, but not from terminal ones.
            return state != .idle && state != .completed && state != .failed && state != .rollback
        case .rolledBack:
            return state == .failed
        case .reset:
            return state == .completed || state == .rollback
        default:
            return forwardTarget(for: event) != nil
        }
    }

    /// Applies an event. Throws `SwitchError.transactionConflict` for illegal
    /// transitions so callers cannot silently corrupt the state.
    public mutating func apply(_ event: SwitchEvent) throws {
        guard canHandle(event) else {
            throw SwitchError.transactionConflict
        }
        switch event {
        case .fail:
            state = .failed
        case .rolledBack:
            state = .rollback
        case .reset:
            state = .idle
        default:
            state = forwardTarget(for: event)!
        }
    }

    public var isTerminal: Bool {
        state == .idle || state == .completed
    }

    public var isActive: Bool {
        !(state == .idle || state == .completed || state == .failed || state == .rollback)
    }
}
