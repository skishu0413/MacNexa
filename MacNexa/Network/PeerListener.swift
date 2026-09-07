import Foundation
import Network
import MacNexaCore

/// Advertises this Mac's MacNexa service and accepts inbound peer connections
/// (spec §10, §11, §36).
public final class PeerListener: @unchecked Sendable {
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.macnexa.listener")
    private let serviceName: String

    /// Called with a transport for each accepted inbound connection.
    public var onConnection: (@Sendable (NWMessageTransport) -> Void)?

    public init(serviceName: String) {
        self.serviceName = serviceName
    }

    public func start() throws {
        let listener = try NWListener(using: .tcp)
        listener.service = NWListener.Service(
            name: serviceName, type: Constants.bonjourServiceType
        )
        listener.newConnectionHandler = { [weak self] connection in
            let transport = NWMessageTransport(connection: connection)
            Task { await transport.start() }
            self?.onConnection?(transport)
        }
        listener.start(queue: queue)
        self.listener = listener
        Log.network.info("Listener advertising as \(self.serviceName, privacy: .public)")
    }

    public func stop() {
        listener?.cancel()
        listener = nil
    }
}
