import Foundation

/// Abstraction over a bidirectional byte transport (a single peer connection).
/// The real implementation wraps `NWConnection`; tests use `InMemoryTransport`.
public protocol MessageTransport: Actor {
    /// Sends raw bytes to the remote endpoint.
    func send(_ data: Data) async throws
    /// Delivers received bytes to the given handler until the transport closes.
    func setReceiveHandler(_ handler: @escaping @Sendable (Data) -> Void) async
    /// Closes the transport.
    func close() async
}

/// An in-memory transport whose sends are delivered to a paired transport's
/// receive handler. Used to test session/handshake logic without networking.
public actor InMemoryTransport: MessageTransport {
    private var receiveHandler: (@Sendable (Data) -> Void)?
    private weak var peer: InMemoryTransport?
    private var closed = false

    public init() {}

    /// Wires two transports together as a connected pair.
    public static func makePair() -> (InMemoryTransport, InMemoryTransport) {
        let a = InMemoryTransport()
        let b = InMemoryTransport()
        Task { await a.setPeer(b); await b.setPeer(a) }
        return (a, b)
    }

    func setPeer(_ peer: InMemoryTransport) { self.peer = peer }

    public func send(_ data: Data) async throws {
        guard !closed else { throw ProtocolError.malformedMessage }
        await peer?.deliver(data)
    }

    func deliver(_ data: Data) {
        receiveHandler?(data)
    }

    public func setReceiveHandler(_ handler: @escaping @Sendable (Data) -> Void) async {
        receiveHandler = handler
    }

    public func close() async {
        closed = true
        receiveHandler = nil
    }
}
