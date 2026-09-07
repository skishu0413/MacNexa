import Foundation
import CryptoKit

/// Derives a stable, deterministic `UUID` from a Bluetooth address so a device
/// has the same id every time it is enumerated and across event notifications
/// (spec §9, §35). Uses a namespaced SHA-256 of the normalized address.
public enum DeviceIdentity {
    public static func uuid(forAddress address: String) -> UUID {
        let normalized = address.uppercased().replacingOccurrences(of: ":", with: "-")
        var hasher = SHA256()
        hasher.update(data: Data("macnexa-device".utf8))
        hasher.update(data: Data(normalized.utf8))
        let digest = Array(hasher.finalize())
        var bytes = Array(digest.prefix(16))
        // Set RFC 4122 version (5-like) and variant bits for a well-formed UUID.
        bytes[6] = (bytes[6] & 0x0F) | 0x50
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        let uuid = uuid_t(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                          bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                          bytes[12], bytes[13], bytes[14], bytes[15])
        return UUID(uuid: uuid)
    }
}
