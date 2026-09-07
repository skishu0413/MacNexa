import Foundation

/// Encapsulates rollback logic so a failed switch does not strand the
/// peripherals (spec §21, §41). Given what was done during a transaction, it
/// reverses those actions in the correct order.
public struct RecoveryManager: Sendable {
    private let bluetooth: BluetoothManaging
    private let peerControl: PeerControlling
    private let retry: RetryPolicy

    public init(bluetooth: BluetoothManaging, peerControl: PeerControlling, retry: RetryPolicy = RetryPolicy()) {
        self.bluetooth = bluetooth
        self.peerControl = peerControl
        self.retry = retry
    }

    /// Rolls back a destination-side failure: disconnect anything this Mac
    /// connected, then ask the source to reconnect so the user is not stranded.
    public func rollback(
        transaction: SwitchTransaction,
        connectedByDestination: [ManagedDevice]
    ) async throws {
        // 1. Release anything this (destination) Mac managed to grab.
        for device in connectedByDestination {
            try? await bluetooth.disconnect(device)
        }
        // 2. Ask the source to take the devices back (bounded retry).
        try await retry.run(operation: { _ in
            try await peerControl.requestReconnect(transaction: transaction)
        })
        // 3. Tell the source the switch failed so it restores its own state.
        try? await peerControl.notifySwitchFailed(transaction: transaction)
    }
}
