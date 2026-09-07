import Foundation

/// Guards against replayed and stale authenticated messages (spec §16).
///
/// A message is accepted only if:
///   1. Its timestamp is within the acceptable skew window, and
///   2. Its messageId has not been seen before.
///
/// Not thread-safe on its own; callers should confine it to an actor.
public final class ReplayProtection {
    private let clock: ClockProviding
    private let window: TimeInterval
    private let capacity: Int
    private var seen: Set<UUID> = []
    private var order: [UUID] = []

    public init(
        clock: ClockProviding = SystemClock(),
        window: TimeInterval = Constants.Security.timestampWindow,
        capacity: Int = Constants.Security.replayCacheSize
    ) {
        self.clock = clock
        self.window = window
        self.capacity = capacity
    }

    /// Validates and records a message. Throws if stale or replayed.
    public func validate(messageId: UUID, timestamp: TimeInterval) throws {
        let now = clock.now()
        if abs(now - timestamp) > window {
            throw ProtocolError.timestampOutOfWindow
        }
        if seen.contains(messageId) {
            throw ProtocolError.replayDetected
        }
        record(messageId)
    }

    private func record(_ id: UUID) {
        seen.insert(id)
        order.append(id)
        if order.count > capacity {
            let evicted = order.removeFirst()
            seen.remove(evicted)
        }
    }
}
