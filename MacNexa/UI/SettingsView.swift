import SwiftUI
import MacNexaCore

/// Settings window (spec §28).
struct SettingsView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        TabView {
            generalTab.tabItem { Label("General", systemImage: "gear") }
            trustedTab.tabItem { Label("Trusted Macs", systemImage: "lock.shield") }
        }
        .frame(width: 420, height: 300)
        .padding()
    }

    private var generalTab: some View {
        Form {
            Toggle("Launch MacNexa at login", isOn: $appState.launchAtLogin)
            Text("MacNexa operates entirely over your local network. It does not use iCloud or any cloud service.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding()
    }

    private var trustedTab: some View {
        VStack(alignment: .leading) {
            Text("Trusted Macs").font(.headline)
            let peers = appState.trustedPeers()
            if peers.isEmpty {
                Text("No trusted Macs yet. Pair a Mac from the menu bar.")
                    .foregroundStyle(.secondary)
            } else {
                List(peers, id: \.id) { peer in
                    HStack {
                        Text(peer.displayName)
                        Spacer()
                        Button("Remove") { appState.revokeTrust(peer.id) }
                    }
                }
            }
            Spacer()
        }
        .padding()
    }
}
