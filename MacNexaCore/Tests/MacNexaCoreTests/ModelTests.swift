import XCTest
@testable import MacNexaCore

final class ModelTests: XCTestCase {
    func testManagedDeviceRoundTripsThroughCodable() throws {
        let device = ManagedDevice(bluetoothAddress: "AA-BB-CC-DD-EE-FF", name: "Magic Keyboard", type: .keyboard)
        let data = try JSONEncoder().encode(device)
        let decoded = try JSONDecoder().decode(ManagedDevice.self, from: data)
        XCTAssertEqual(device, decoded)
    }

    func testDeviceStatusIdMatchesDevice() {
        let device = ManagedDevice(bluetoothAddress: "AA", name: "Trackpad", type: .trackpad)
        let status = DeviceStatus(device: device, state: .connected)
        XCTAssertEqual(status.id, device.id)
    }

    func testPeerDefaultsToOffline() {
        let peer = Peer(id: UUID(), displayName: "Mac mini", protocolVersion: 1)
        XCTAssertEqual(peer.status, .offline)
    }
}
