import Foundation
@testable import MacNexaCore

/// A controllable clock for deterministic time-based tests.
final class MutableClock: ClockProviding, @unchecked Sendable {
    private var current: TimeInterval
    init(now: TimeInterval) { self.current = now }
    func now() -> TimeInterval { current }
    func advance(by seconds: TimeInterval) { current += seconds }
    func set(_ t: TimeInterval) { current = t }
}
