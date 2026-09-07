import Foundation

/// The category of a managed Bluetooth peripheral.
public enum DeviceType: String, Codable, Sendable, CaseIterable {
    case keyboard
    case trackpad
    case mouse
    case unknown
}
