import SwiftUI
import MacNexaCore

/// A discovered peer Mac with a switch or pair action (spec §26, §27).
struct PeerRow: View {
    let peer: Peer
    let onSwitch: () -> Void
    let onPair: () -> Void

    var body: some View {
        HStack {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(peer.displayName)
            Spacer()
            switch peer.status {
            case .available:
                Button("Switch") { onSwitch() }
            case .untrusted:
                Button("Pair") { onPair() }
            default:
                Text(peer.status.rawValue.capitalized)
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var color: Color {
        switch peer.status {
        case .available: return .green
        case .connecting: return .yellow
        case .offline: return .gray
        case .untrusted: return .orange
        case .busy: return .red
        }
    }
}
