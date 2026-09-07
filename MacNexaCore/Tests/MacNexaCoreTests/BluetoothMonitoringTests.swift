import XCTest
@testable import MacNexaCore

final class BluetoothMonitoringTests: XCTestCase {
    func testConnectDisconnectEmitEvents() async throws {
        let manager = MockBluetoothManager()
        let device = try await manager.devices().first!

        let received = Received()
        await manager.startMonitoring { event in Task { await received.append(event) } }

        try await manager.disconnect(device)
        try await manager.connect(device)
        try await Task.sleep(nanoseconds: 100_000_000)

        let events = await received.events
        XCTAssertTrue(events.contains(.deviceDisconnected(device.id)))
        XCTAssertTrue(events.contains(.deviceConnected(device.id)))
    }

    func testSimulatedUnavailableEvent() async {
        let manager = MockBluetoothManager()
        let received = Received()
        await manager.startMonitoring { event in Task { await received.append(event) } }
        await manager.simulate(.bluetoothUnavailable)
        try? await Task.sleep(nanoseconds: 100_000_000)
        let events = await received.events
        XCTAssertTrue(events.contains(.bluetoothUnavailable))
    }
}

private actor Received {
    var events: [BluetoothEvent] = []
    func append(_ e: BluetoothEvent) { events.append(e) }
}
