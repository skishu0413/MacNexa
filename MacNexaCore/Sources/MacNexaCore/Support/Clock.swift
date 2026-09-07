import Foundation

/// Abstraction over the current time so logic that depends on time can be
/// tested deterministically (spec: testability / coding standards).
public protocol ClockProviding: Sendable {
    /// Current time as a Unix timestamp (seconds since 1970).
    func now() -> TimeInterval
}

/// Production clock backed by the system wall clock.
public struct SystemClock: ClockProviding {
    public init() {}
    public func now() -> TimeInterval { Date().timeIntervalSince1970 }
}
