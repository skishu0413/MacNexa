import Foundation

/// What the SwitchCoordinator needs from the network layer to run a handoff,
/// abstracted so the coordinator is testable without real networking.
public protocol PeerControlling: Sendable {
    /// Ask the peer that currently holds the devices to release them, waiting
    /// for its confirmation. Throws `SwitchError.releaseTimedOut`/`.releaseRejected`.
    func requestRelease(transaction: SwitchTransaction) async throws
    /// Notify the peer that the switch completed successfully.
    func notifySwitchComplete(transaction: SwitchTransaction) async throws
    /// Notify the peer that the switch failed (so it can restore devices).
    func notifySwitchFailed(transaction: SwitchTransaction) async throws
    /// Ask the peer to reconnect the devices (used during rollback when THIS Mac
    /// was the source that already released them). No-op for pure destination.
    func requestReconnect(transaction: SwitchTransaction) async throws
}
