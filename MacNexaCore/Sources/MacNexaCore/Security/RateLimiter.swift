import Foundation

/// Per-sender sliding-window rate limiter for control commands, mitigating a
/// malicious peer repeatedly requesting device release (spec §13 "denial of
/// service"). Not thread-safe; confine to an actor.
public final class RateLimiter {
    private let clock: ClockProviding
    private let limit: Int
    private let window: TimeInterval
    private var events: [UUID: [TimeInterval]] = [:]

    public init(
        clock: ClockProviding = SystemClock(),
        limit: Int = Constants.RateLimit.commandsPerWindow,
        window: TimeInterval = Constants.RateLimit.window
    ) {
        self.clock = clock
        self.limit = limit
        self.window = window
    }

    /// Records an attempt from `sender`. Returns true if allowed, false if the
    /// sender has exceeded the limit within the current window.
    public func allow(sender: UUID) -> Bool {
        let now = clock.now()
        var times = events[sender] ?? []
        times = times.filter { now - $0 < window }
        guard times.count < limit else {
            events[sender] = times
            return false
        }
        times.append(now)
        events[sender] = times
        return true
    }
}
