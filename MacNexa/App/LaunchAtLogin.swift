import Foundation
import ServiceManagement
import MacNexaCore

/// Registers/unregisters MacNexa as a login item using SMAppService
/// (spec §42, macOS 13+).
enum LaunchAtLogin {
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func setEnabled(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            Log.ui.info("Launch at login set to \(enabled, privacy: .public)")
        } catch {
            Log.ui.error("Launch at login change failed: \(String(describing: error), privacy: .public)")
        }
    }
}
