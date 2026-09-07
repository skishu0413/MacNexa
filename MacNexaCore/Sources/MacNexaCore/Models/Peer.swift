import Foundation

/// Availability of a discovered peer Mac.
public enum PeerStatus: String, Codable, Sendable {
    case available
    case offline
    case connecting
    case untrusted
    case busy
}

/// Another MacNexa instance discovered on the local network.
public struct Peer: Identifiable, Codable, Hashable, Sendable {
    /// Stable identity of the peer (its public identity fingerprint).
    public let id: UUID
    public let displayName: String
    public let protocolVersion: Int
    public var status: PeerStatus

    public init(id: UUID, displayName: String, protocolVersion: Int, status: PeerStatus = .offline) {
        self.id = id
        self.displayName = displayName
        self.protocolVersion = protocolVersion
        self.status = status
    }
}
