import Foundation
import MacNexaCore

/// Bridges the `SwitchCoordinator` to a live `PeerSession`, translating the
/// coordinator's control calls into signed protocol messages and awaiting the
/// peer's confirmations (spec §11, §17, §19).
///
/// Confirmations are matched by transaction id with a timeout so a stalled peer
/// surfaces as a controlled failure rather than hanging (spec §22).
public actor NetworkPeerControl: PeerControlling {
    private let session: PeerSession

    private enum WaitKind { case release, reconnect }
    private var releaseWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var reconnectWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]

    public init(session: PeerSession) {
        self.session = session
    }

    public func requestRelease(transaction: SwitchTransaction) async throws {
        let payload = try JSONEncoder().encode(DeviceListPayload(deviceIds: transaction.deviceIds))
        try await session.send(type: .releaseDevices, payload: payload, transactionId: transaction.id)
        try await waitRelease(transaction.id,
                                    timeout: Constants.Timeouts.deviceRelease,
                                    timeoutError: SwitchError.releaseTimedOut)
    }

    public func notifySwitchComplete(transaction: SwitchTransaction) async throws {
        try await session.send(type: .switchComplete, transactionId: transaction.id)
    }

    public func notifySwitchFailed(transaction: SwitchTransaction) async throws {
        try await session.send(type: .switchFailed, transactionId: transaction.id)
    }

    public func requestReconnect(transaction: SwitchTransaction) async throws {
        try await session.send(type: .connectDevices, transactionId: transaction.id)
        try await waitReconnect(transaction.id,
                                timeout: Constants.Timeouts.deviceConnection,
                                timeoutError: SwitchError.rollbackFailed)
    }

    /// Called by the session delegate when a confirmation message arrives.
    public func handleConfirmation(_ type: MessageType, transactionId: UUID?) {
        guard let id = transactionId else { return }
        switch type {
        case .devicesReleased:
            releaseWaiters.removeValue(forKey: id)?.resume()
        case .devicesConnected:
            reconnectWaiters.removeValue(forKey: id)?.resume()
        default:
            break
        }
    }

    private func waitRelease(_ id: UUID, timeout: TimeInterval, timeoutError: Error) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [self] in
                try await withCheckedThrowingContinuation { cont in
                    Task { await self.registerRelease(id, cont) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw timeoutError
            }
            defer { group.cancelAll() }
            try await group.next()
        }
    }

    private func waitReconnect(_ id: UUID, timeout: TimeInterval, timeoutError: Error) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { [self] in
                try await withCheckedThrowingContinuation { cont in
                    Task { await self.registerReconnect(id, cont) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw timeoutError
            }
            defer { group.cancelAll() }
            try await group.next()
        }
    }

    private func registerRelease(_ id: UUID, _ cont: CheckedContinuation<Void, Error>) {
        releaseWaiters[id] = cont
    }
    private func registerReconnect(_ id: UUID, _ cont: CheckedContinuation<Void, Error>) {
        reconnectWaiters[id] = cont
    }
}
