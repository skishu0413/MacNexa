import Foundation

/// The set of application protocol message types (spec §12).
public enum MessageType: String, Codable, Sendable {
    case hello = "HELLO"
    case authenticate = "AUTHENTICATE"
    case ping = "PING"
    case pong = "PONG"
    case getStatus = "GET_STATUS"
    case status = "STATUS"
    case releaseDevices = "RELEASE_DEVICES"
    case devicesReleased = "DEVICES_RELEASED"
    case connectDevices = "CONNECT_DEVICES"
    case devicesConnected = "DEVICES_CONNECTED"
    case switchComplete = "SWITCH_COMPLETE"
    case switchFailed = "SWITCH_FAILED"
    case busy = "BUSY"
    case error = "ERROR"
}
