import SwiftUI
import AppKit

/// MacNexa menu-bar application entry point (spec §26).
@main
struct MacNexaApp: App {
    @StateObject private var appState: AppState

    init() {
        let container = DependencyContainer()
        let state = AppState(bluetooth: container.bluetooth, services: container.services)
        _appState = StateObject(wrappedValue: state)
        // Start network discovery, listener, and Bluetooth monitoring immediately upon launch,
        // without waiting for the user to click the menu-bar icon.
        Task { @MainActor in
            await state.start()
        }
    }

    var body: some Scene {
        MenuBarExtra("MacNexa", systemImage: "keyboard") {
            MenuBarView()
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }
}
