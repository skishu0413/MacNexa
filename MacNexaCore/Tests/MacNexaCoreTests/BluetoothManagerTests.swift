import XCTest
@testable import MacNexaCore

/// Integration tests for the Bluetooth abstraction using the mock manager
/// (spec §45 integration layer).
final class BluetoothManagerTests: XCTestCase {
    func testMockReportsSampleDevices() async throws {
        let sut = MockBluetoothManager()
        let devices = try await sut.devices()
        XCTAssertEqual(devices.count, 2)
        XCTAssertTrue(devices.contains { $0.type == .keyboard })
        XCTAssertTrue(devices.contains { $0.type == .trackpad })
    }

    func testDisconnectThenConnectUpdatesState() async throws {
        let sut = MockBluetoothManager()
        let device = try await sut.devices().first!
        try await sut.disconnect(device)
        var state = await sut.connectionState(for: device)
        XCTAssertEqual(state, .disconnected)
        try await sut.connect(device)
        state = await sut.connectionState(for: device)
        XCTAssertEqual(state, .connected)
    }
}
