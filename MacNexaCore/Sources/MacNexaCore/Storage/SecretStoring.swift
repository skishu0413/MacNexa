import Foundation

/// Abstraction over secure secret storage (spec §29). The real implementation is
/// Keychain-backed (in the app); tests use an in-memory fake. Values are opaque
/// bytes so callers control encoding.
public protocol SecretStoring: Sendable {
    func setSecret(_ data: Data, for key: String) throws
    func secret(for key: String) throws -> Data?
    func removeSecret(for key: String) throws
    func allKeys(withPrefix prefix: String) throws -> [String]
}

/// In-memory secret store for tests and mock runs. NOT secure; never used to
/// persist real secrets in production.
public final class InMemorySecretStore: SecretStoring, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func setSecret(_ data: Data, for key: String) throws {
        lock.lock(); defer { lock.unlock() }
        storage[key] = data
    }
    public func secret(for key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return storage[key]
    }
    public func removeSecret(for key: String) throws {
        lock.lock(); defer { lock.unlock() }
        storage[key] = nil
    }
    public func allKeys(withPrefix prefix: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        return storage.keys.filter { $0.hasPrefix(prefix) }
    }
}
