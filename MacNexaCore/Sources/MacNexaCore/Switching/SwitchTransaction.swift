import Foundation

/// An immutable record of a single handoff transaction (spec §20). Every network
/// command belonging to a switch carries this `id`.
public struct SwitchTransaction: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let destinationPeerId: UUID
    public let deviceIds: [UUID]
    public let startedAt: TimeInterval

    public init(id: UUID = UUID(), destinationPeerId: UUID, deviceIds: [UUID], startedAt: TimeInterval) {
        self.id = id
        self.destinationPeerId = destinationPeerId
        self.deviceIds = deviceIds
        self.startedAt = startedAt
    }
}

/// The role a Mac plays in a given switch.
public enum SwitchRole: Sendable, Equatable {
    /// This Mac currently holds the devices and is giving them up.
    case source
    /// This Mac is acquiring the devices.
    case destination
}
