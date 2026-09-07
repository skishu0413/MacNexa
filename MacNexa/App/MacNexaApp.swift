import SwiftUI

/// MacNexa menu-bar application entry point (spec §26).
@main
struct MacNexaApp: App {
    @StateObject private var appState: AppState

    init() {
        let container = DependencyContainer()
        _appState = StateObject(wrappedValue: AppState(bluetooth: container.bluetooth,
                                                       services: container.services))
    }

    var body: some Scene {
        MenuBarExtra("MacNexa", systemImage: "keyboard") {
            MenuBarView()
                .environmentObject(appState)
                .task { await appState.start() }
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }
}
