import Foundation

/// Owns the handoff transaction end-to-end (spec §17, §18, §24, §25).
///
/// An actor, so exactly one transaction runs at a time; a concurrent request is
/// rejected with `SwitchError.transactionConflict` (spec §25). It drives the
/// `SwitchStateMachine`, coordinates Bluetooth + peer control, and rolls back on
/// any failure so the peripherals are never left stranded (spec §21).
public actor SwitchCoordinator {
    private let bluetooth: BluetoothManaging
    private let peerControl: PeerControlling
    private let recovery: RecoveryManager
    private let retry: RetryPolicy
    private let clock: ClockProviding

    private var machine = SwitchStateMachine()
    private var activeTransaction: SwitchTransaction?

    public init(
        bluetooth: BluetoothManaging,
        peerControl: PeerControlling,
        retry: RetryPolicy = RetryPolicy(),
        clock: ClockProviding = SystemClock()
    ) {
        self.bluetooth = bluetooth
        self.peerControl = peerControl
        self.recovery = RecoveryManager(bluetooth: bluetooth, peerControl: peerControl, retry: retry)
        self.retry = retry
        self.clock = clock
    }

    public var state: SwitchState { machine.state }
    public var isBusy: Bool { machine.isActive }

    /// Acquires the given devices from the destination peer to THIS Mac.
    ///
    /// Flow (spec §18/§19): begin → request release → wait → connect keyboard →
    /// connect trackpad → verify → complete. Any failure triggers rollback.
    public func acquireDevices(
        _ devices: [ManagedDevice],
        fromPeer peerId: UUID
    ) async throws {
        // Reject concurrent transactions (spec §25).
        guard !machine.isActive else { throw SwitchError.transactionConflict }

        let transaction = SwitchTransaction(
            destinationPeerId: peerId,
            deviceIds: devices.map(\.id),
            startedAt: clock.now()
        )
        activeTransaction = transaction
        machine = SwitchStateMachine()
        var connected: [ManagedDevice] = []

        do {
            try machine.apply(.begin)                    // -> preparing

            try machine.apply(.releaseRequested)         // -> requestingRelease
            try await peerControl.requestRelease(transaction: transaction)
            try machine.apply(.releaseRequested)         // -> waitingForRelease
            try machine.apply(.releaseConfirmed)         // -> connectingKeyboard

            // Connect keyboard(s) first, then trackpad(s), each with bounded retry.
            for keyboard in devices.filter({ $0.type == .keyboard }) {
                try await connect(keyboard)
                connected.append(keyboard)
            }
            try machine.apply(.keyboardConnected)        // -> connectingTrackpad

            for trackpad in devices.filter({ $0.type != .keyboard }) {
                try await connect(trackpad)
                connected.append(trackpad)
            }
            try machine.apply(.trackpadConnected)        // -> verifying

            try await verify(connected)
            try machine.apply(.verified)                 // -> completed

            try await peerControl.notifySwitchComplete(transaction: transaction)
            try machine.apply(.reset)                    // -> idle
            activeTransaction = nil
        } catch {
            await handleFailure(transaction: transaction, connected: connected)
            throw error
        }
    }

    private func connect(_ device: ManagedDevice) async throws {
        try await retry.run(operation: { [bluetooth] _ in
            try await bluetooth.connect(device)
        })
        let state = await bluetooth.connectionState(for: device)
        guard state == .connected else {
            throw device.type == .keyboard
                ? SwitchError.keyboardConnectionFailed
                : SwitchError.trackpadConnectionFailed
        }
    }

    private func verify(_ devices: [ManagedDevice]) async throws {
        for device in devices {
            let state = await bluetooth.connectionState(for: device)
            guard state == .connected else { throw SwitchError.verificationFailed }
        }
    }

    private func handleFailure(transaction: SwitchTransaction, connected: [ManagedDevice]) async {
        // Move machine into failed -> rollback, then attempt recovery.
        try? machine.apply(.fail)
        do {
            try await recovery.rollback(transaction: transaction, connectedByDestination: connected)
            try? machine.apply(.rolledBack)
        } catch {
            // Rollback itself failed: leave in failed state for the app to surface.
            try? machine.apply(.rolledBack)
        }
        try? machine.apply(.reset)
        activeTransaction = nil
    }
}
