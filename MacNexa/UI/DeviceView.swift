import SwiftUI
import MacNexaCore

/// A single device row with a status indicator (spec §27).
struct DeviceRow: View {
    let status: DeviceStatus

    var body: some View {
        HStack {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(status.device.name)
            Spacer()
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }

    private var color: Color {
        switch status.state {
        case .connected: return .green
        case .connecting: return .yellow
        case .disconnected: return .gray
        case .error: return .red
        }
    }

    private var label: String {
        switch status.state {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .disconnected: return "Disconnected"
        case .error: return "Error"
        }
    }
}
