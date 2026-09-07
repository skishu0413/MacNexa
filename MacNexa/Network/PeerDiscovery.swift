import Foundation
import Network
import MacNexaCore

/// A discovered peer endpoint on the local network (spec §10).
public struct DiscoveredPeer: Identifiable, Sendable, Hashable {
    public let id: String          // Bonjour name
    public let endpoint: NWEndpoint
    public let displayName: String
    public var idString: String { id }
}

/// Advertises this Mac and discovers other MacNexa peers via Bonjour
/// (spec §10, §36). Discovery metadata is non-sensitive only.
public final class PeerDiscovery: @unchecked Sendable {
    private var browser: NWBrowser?
    private let queue = DispatchQueue(label: "com.macnexa.discovery")

    public var onPeersChanged: (@Sendable ([DiscoveredPeer]) -> Void)?

    public init() {}

    public func start() {
        let descriptor = NWBrowser.Descriptor.bonjour(
            type: Constants.bonjourServiceType, domain: nil
        )
        let browser = NWBrowser(for: descriptor, using: .tcp)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let peers = results.compactMap { result -> DiscoveredPeer? in
                guard case let .service(name, _, _, _) = result.endpoint else { return nil }
                return DiscoveredPeer(id: name, endpoint: result.endpoint, displayName: name)
            }
            self?.onPeersChanged?(peers)
        }
        browser.start(queue: queue)
        self.browser = browser
        Log.discovery.info("Bonjour browsing started for \(Constants.bonjourServiceType, privacy: .public)")
    }

    public func stop() {
        browser?.cancel()
        browser = nil
    }
}
