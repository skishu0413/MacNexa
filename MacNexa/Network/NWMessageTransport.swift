import Foundation
import Network
import MacNexaCore

/// Errors surfaced by the network transport layer.
public enum TransportError: Error, Sendable {
    /// The connection was closed/cancelled before or during use.
    case connectionClosed
}

/// A `MessageTransport` backed by an `NWConnection` (spec §11). Handles the raw
/// byte stream; framing and validation are done by `PeerSession` in core.
public actor NWMessageTransport: MessageTransport {
    private let connection: NWConnection
    private var receiveHandler: (@Sendable (Data) -> Void)?
    private var started = false

    /// Readiness gate: continuations awaiting the connection reaching `.ready`.
    /// Resolved once the connection is ready, or failed if it errors/cancels so
    /// that `send` fails fast instead of blocking on an unreachable peer.
    private enum Readiness {
        case pending
        case ready
        case failed(Error)
    }
    private var readiness: Readiness = .pending
    private var readyWaiters: [CheckedContinuation<Void, Error>] = []

    public init(connection: NWConnection) {
        self.connection = connection
    }

    /// Creates an outbound transport to a resolved endpoint.
    public init(endpoint: NWEndpoint) {
        let params = NWParameters.tcp
        self.connection = NWConnection(to: endpoint, using: params)
    }

    public func start() {
        guard !started else { return }
        started = true
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            Task { await self.handleState(state) }
        }
        connection.start(queue: .global(qos: .userInitiated))
        receiveLoop()
    }

    /// Reacts to NWConnection lifecycle changes, resolving the readiness gate.
    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            readiness = .ready
            let waiters = readyWaiters
            readyWaiters.removeAll()
            for w in waiters { w.resume() }
        case .failed(let error):
            fail(with: error)
        case .cancelled:
            fail(with: TransportError.connectionClosed)
        case .waiting(let error):
            // .waiting means the path is currently unusable (e.g. peer not
            // listening, no route). Treat as a fast failure rather than hanging.
            fail(with: error)
        case .setup, .preparing:
            break
        @unknown default:
            break
        }
    }

    private func fail(with error: Error) {
        guard case .failed = readiness else {
            readiness = .failed(error)
            let waiters = readyWaiters
            readyWaiters.removeAll()
            for w in waiters { w.resume(throwing: error) }
            return
        }
    }

    /// Suspends until the connection is ready, or throws if it has failed.
    private func awaitReady() async throws {
        switch readiness {
        case .ready:
            return
        case .failed(let error):
            throw error
        case .pending:
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                readyWaiters.append(cont)
            }
        }
    }

    public func send(_ data: Data) async throws {
        if !started { start() }
        // Fail fast on an unreachable peer instead of letting `send` block
        // indefinitely waiting for a connection that never becomes ready.
        try await awaitReady()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func setReceiveHandler(_ handler: @escaping @Sendable (Data) -> Void) async {
        receiveHandler = handler
        if !started { start() }
    }

    private func receiveLoop() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                Task { await self.deliver(data) }
            }
            if error == nil && !isComplete {
                Task { await self.receiveLoop() }
            }
        }
    }

    private func deliver(_ data: Data) {
        receiveHandler?(data)
    }

    public func close() async {
        connection.cancel()
        receiveHandler = nil
        // Release anyone still awaiting readiness so they don't hang.
        fail(with: TransportError.connectionClosed)
    }
}
