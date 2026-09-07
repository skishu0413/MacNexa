import Foundation
import CryptoKit
import MacNexaCore

/// A `SecretStoring` that persists secrets to an encrypted file in the app's
/// Application Support directory, with NO Keychain involvement.
///
/// Why this exists: on MDM-managed / locked-down Macs the Keychain is often
/// unavailable or blocked by policy, so a Keychain-only app cannot store its
/// identity or trusted peers at all. This store is the fallback: it keeps
/// secrets across launches without touching the Keychain.
///
/// Security tradeoff (documented deliberately): the Keychain provides
/// OS-managed, hardware-backed encryption at rest. This store instead encrypts
/// its contents with AES-GCM using a key derived from a per-install random seed
/// that is stored in the same directory. That protects against casual disk
/// inspection and accidental exposure, but the key material lives on disk, so
/// it is weaker than the Keychain. It is only used when explicitly selected
/// (or when the Keychain is unavailable), never as the default on machines
/// where the Keychain works. See Documentation/SECURITY.md.
public final class FileSecretStore: SecretStoring, @unchecked Sendable {
    private let fileURL: URL
    private let seedURL: URL
    private let lock = NSLock()
    private let key: SymmetricKey

    /// Creates a file-backed store rooted in Application Support/MacNexa.
    /// - Throws: if the storage directory cannot be created.
    public init(directory: URL? = nil) throws {
        let base: URL
        if let directory {
            base = directory
        } else {
            let appSupport = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true)
            base = appSupport.appendingPathComponent("MacNexa", isDirectory: true)
        }
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)

        self.fileURL = base.appendingPathComponent("secrets.enc", isDirectory: false)
        self.seedURL = base.appendingPathComponent("secrets.seed", isDirectory: false)
        self.key = try Self.loadOrCreateKey(at: base.appendingPathComponent("secrets.seed"))
    }

    // MARK: SecretStoring

    public func setSecret(_ data: Data, for key: String) throws {
        lock.lock(); defer { lock.unlock() }
        var all = try readAll()
        all[key] = data
        try writeAll(all)
    }

    public func secret(for key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return try readAll()[key]
    }

    public func removeSecret(for key: String) throws {
        lock.lock(); defer { lock.unlock() }
        var all = try readAll()
        all[key] = nil
        try writeAll(all)
    }

    public func allKeys(withPrefix prefix: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        return try readAll().keys.filter { $0.hasPrefix(prefix) }
    }

    // MARK: Encrypted persistence

    /// The on-disk model: keys mapped to base64-encoded secret bytes.
    private func readAll() throws -> [String: Data] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [:] }
        let sealedData = try Data(contentsOf: fileURL)
        guard !sealedData.isEmpty else { return [:] }
        let box = try AES.GCM.SealedBox(combined: sealedData)
        let plaintext = try AES.GCM.open(box, using: key)
        let raw = try JSONDecoder().decode([String: Data].self, from: plaintext)
        return raw
    }

    private func writeAll(_ all: [String: Data]) throws {
        let plaintext = try JSONEncoder().encode(all)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw FileSecretStoreError.encryptionFailed
        }
        // Write atomically and restrict permissions to the current user.
        try combined.write(to: fileURL, options: [.atomic, .completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    /// Loads the per-install encryption seed, creating it on first run.
    private static func loadOrCreateKey(at url: URL) throws -> SymmetricKey {
        if FileManager.default.fileExists(atPath: url.path),
           let seed = try? Data(contentsOf: url), seed.count == 32 {
            return SymmetricKey(data: seed)
        }
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        guard status == errSecSuccess else { throw FileSecretStoreError.seedGenerationFailed }
        try bytes.write(to: url, options: [.atomic, .completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return SymmetricKey(data: bytes)
    }
}

enum FileSecretStoreError: Error {
    case encryptionFailed
    case seedGenerationFailed
}
