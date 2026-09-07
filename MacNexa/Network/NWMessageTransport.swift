import Foundation
import Network
import MacNexaCore

/// A `MessageTransport` backed by an `NWConnection` (spec §11). Handles the raw
/// byte stream; framing and validation are done by `PeerSession` in core.
public actor NWMessageTransport: MessageTransport {
    private let connection: NWConnection
    private var receiveHandler: (@Sendable (Data) -> Void)?
    private var started = false

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
        connection.stateUpdateHandler = { _ in }
        connection.start(queue: .global(qos: .userInitiated))
        receiveLoop()
    }

    public func send(_ data: Data) async throws {
        if !started { start() }
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
    }
}
