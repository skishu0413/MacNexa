import SwiftUI
import MacNexaCore

/// Primary menu-bar panel (spec §26, §27).
struct MenuBarView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("MacNexa").font(.headline)

            if !appState.bluetoothAvailable {
                Label("Bluetooth unavailable", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }

            section("THIS MAC") {
                Label(appState.thisMacName, systemImage: "desktopcomputer")
            }

            section("DEVICES") {
                if appState.deviceStatuses.isEmpty {
                    Text("No Magic devices found").foregroundStyle(.secondary)
                } else {
                    ForEach(appState.deviceStatuses) { DeviceRow(status: $0) }
                }
            }

            section("OTHER MACS") {
                if appState.peers.isEmpty {
                    Text("Searching…").foregroundStyle(.secondary)
                } else {
                    ForEach(appState.peers) { peer in
                        PeerRow(peer: peer,
                                onSwitch: { Task { await appState.switchTo(peer: peer) } },
                                onPair: { appState.beginPairing(with: peer) })
                    }
                }
            }

            if appState.isSwitching {
                HStack(spacing: 6) {
                    ProgressView().scaleEffect(0.6)
                    Text("Switching…").font(.caption).foregroundStyle(.secondary)
                }
            }

            if let error = appState.lastError {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            Divider()
            HStack {
                Button("Refresh") { Task { await appState.refreshDevices() } }
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding()
        .frame(width: 280)
        .sheet(item: $appState.pendingPairing) { pending in
            PairingView(peerName: pending.peerName, code: pending.code,
                        onConfirm: { appState.confirmPairing() },
                        onCancel: { appState.cancelPairing() })
        }
    }

    @ViewBuilder
    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }
}
