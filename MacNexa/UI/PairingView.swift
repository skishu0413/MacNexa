import SwiftUI
import MacNexaCore

/// Pairing UI: shows a code to verify and confirms trust (spec §14).
struct PairingView: View {
    let peerName: String
    let code: PairingCode
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Text("Pair with \(peerName)").font(.headline)
            Text("Confirm this code matches the one shown on the other Mac:")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Text(code.displayValue)
                .font(.system(size: 32, weight: .bold, design: .monospaced))
            HStack {
                Button("Cancel", role: .cancel) { onCancel() }
                Button("Codes Match — Pair") { onConfirm() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 320)
    }
}
