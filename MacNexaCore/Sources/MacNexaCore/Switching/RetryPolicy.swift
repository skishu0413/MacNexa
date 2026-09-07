import Foundation

/// Bounded retry with backoff (spec §23). Pure and testable: it computes the
/// schedule and outcome without performing the work itself.
public struct RetryPolicy: Sendable, Equatable {
    public let maxAttempts: Int
    public let backoff: TimeInterval

    public init(
        maxAttempts: Int = Constants.Retry.maxAttempts,
        backoff: TimeInterval = Constants.Retry.backoff
    ) {
        self.maxAttempts = max(1, maxAttempts)
        self.backoff = backoff
    }

    /// Wait interval before the given 1-based attempt. No wait before attempt 1.
    public func delay(beforeAttempt attempt: Int) -> TimeInterval {
        guard attempt > 1 else { return 0 }
        return backoff
    }

    /// Runs `operation` up to `maxAttempts` times, awaiting `sleep` between
    /// attempts. Returns the successful result or rethrows the last error.
    public func run<T: Sendable>(
        operation: @Sendable (Int) async throws -> T,
        sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }
    ) async throws -> T {
        var lastError: Error?
        for attempt in 1...maxAttempts {
            if attempt > 1 {
                try await sleep(delay(beforeAttempt: attempt))
            }
            do {
                return try await operation(attempt)
            } catch {
                lastError = error
            }
        }
        throw lastError ?? SwitchError.rollbackFailed
    }
}
