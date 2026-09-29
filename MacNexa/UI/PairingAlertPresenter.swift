import AppKit
import Foundation
import MacNexaCore

/// Presents a system alert dialog for SAS pairing confirmation (spec §14).
///
/// Because MacNexa is an LSUIElement menu-bar application, standard SwiftUI sheets
/// attached to MenuBarExtra are invisible when the menu is not actively open.
/// This presenter guarantees the user sees the 6-digit verification code prominently
/// on screen even when running headlessly or in the background.
@MainActor
final class PairingAlertPresenter {
    static let shared = PairingAlertPresenter()

    private var isPresenting = false

    func show(
        pending: PendingPairing,
        onConfirm: @escaping () -> Void,
        onCancel: @escaping () -> Void
    ) {
        guard !isPresenting else { return }
        isPresenting = true
        defer { isPresenting = false }

        NSApp.activate(ignoringOtherApps: true)

        let alert = NSAlert()
        alert.messageText = "MacNexa: Pair with \(pending.peerName)?"
        alert.informativeText = """
        Confirm this 6-digit verification code matches the one shown on \(pending.peerName):

        \(pending.code.displayValue)

        Both Macs independently derive this code from their cryptographic keys and nonces. If the codes differ or you did not initiate this request, click Cancel.
        """
        alert.addButton(withTitle: "Codes Match — Pair")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .informational

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            onConfirm()
        } else {
            onCancel()
        }
    }
}
