import Foundation
import MacNexaCore

/// Central place to build and inject dependencies. Swaps mock vs. real
/// implementations based on environment (spec §7, coding-standards).
@MainActor
final class DependencyContainer {
    let bluetooth: BluetoothManaging
    let services: AppServices

    init() {
        let env = ProcessInfo.processInfo.environment
        let useReal = env["MACNEXA_USE_IOBLUETOOTH"] == "1"

        let bt: BluetoothManaging = useReal ? IOBluetoothManager() : MockBluetoothManager()
        self.bluetooth = bt

        do {
            let secrets = try Self.makeSecretStore(env: env)
            self.services = try AppServices(bluetooth: bt, secrets: secrets)
        } catch {
            fatalError("Failed to initialize services: \(error)")
        }
    }

    /// Chooses where long-term secrets (identity key, trusted peers) are stored.
    ///
    /// - `MACNEXA_NO_KEYCHAIN=1` forces the encrypted file store — use this on
    ///   MDM-managed / locked-down Macs where Keychain access is blocked by
    ///   policy, so the app can still persist its identity and paired peers.
    /// - Otherwise the Keychain is used, but if it is unavailable at runtime
    ///   (e.g. policy denies access) the app falls back to the file store
    ///   automatically instead of failing to launch.
    private static func makeSecretStore(env: [String: String]) throws -> SecretStoring {
        #if MACNEXA_FILE_SECRETS
        // Compile-time default (set for Debug in project.yml): never touch the
        // Keychain. This makes development and MDM-locked Macs behave the same
        // without depending on an env var being present.
        return try FileSecretStore()
        #else
        // Explicit opt-out for MDM-managed / locked-down Macs.
        if env["MACNEXA_NO_KEYCHAIN"] == "1" {
            return try FileSecretStore()
        }
        let keychain = KeychainSecretStore()
        if isKeychainUsable(keychain) {
            return keychain
        }
        // Keychain is present but not writable/readable here (typical under
        // restrictive MDM). Persist without it rather than losing all state.
        return try FileSecretStore()
        #endif
    }

    #if !MACNEXA_FILE_SECRETS
    /// Probes whether the Keychain can actually be written to and read from.
    /// A denied policy surfaces as a thrown error or a mismatch here.
    private static func isKeychainUsable(_ store: KeychainSecretStore) -> Bool {
        let probeKey = "macnexa.keychain.probe"
        let probe = Data("ok".utf8)
        do {
            try store.setSecret(probe, for: probeKey)
            let read = try store.secret(for: probeKey)
            try? store.removeSecret(for: probeKey)
            return read == probe
        } catch {
            return false
        }
    }
    #endif
}
