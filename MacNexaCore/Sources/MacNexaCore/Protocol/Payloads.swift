import Foundation

/// Payload for STATUS responses (spec §12).
public struct StatusPayload: Codable, Equatable, Sendable {
    public let devices: [DeviceStatus]
    public init(devices: [DeviceStatus]) { self.devices = devices }
}

/// Payload listing devices involved in a release/connect request.
public struct DeviceListPayload: Codable, Equatable, Sendable {
    public let deviceIds: [UUID]
    public init(deviceIds: [UUID]) { self.deviceIds = deviceIds }
}

/// Payload for ERROR messages.
public struct ErrorPayload: Codable, Equatable, Sendable {
    public let code: String
    public let message: String
    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}
