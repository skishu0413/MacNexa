import Foundation

/// Central tuning constants. Values are initial estimates from the spec and
/// should be refined against real hardware behavior (spec §22, §23).
public enum Constants {
    /// Current wire protocol version.
    public static let protocolVersion: Int = 1

    /// Bonjour service type for peer discovery (spec §10).
    public static let bonjourServiceType = "_macnexa._tcp"

    public enum Timeouts {
        public static let peerResponse: TimeInterval = 3
        public static let deviceRelease: TimeInterval = 5
        public static let deviceConnection: TimeInterval = 10
        public static let verification: TimeInterval = 5
        public static let entireSwitch: TimeInterval = 20
    }

    public enum Retry {
        /// Maximum attempts for a bounded retry (spec §23).
        public static let maxAttempts = 3
        /// Base wait between attempts.
        public static let backoff: TimeInterval = 1
    }

    public enum Security {
        /// Acceptable clock skew for message timestamps, in seconds.
        public static let timestampWindow: TimeInterval = 30
        /// Number of recently seen message IDs/nonces to retain for replay protection.
        public static let replayCacheSize = 4096
        /// Maximum allowed size of a single decoded frame, in bytes (DoS guard).
        public static let maxMessageBytes = 64 * 1024
        /// Minimum nonce length in bytes (before base64/encoding) required.
        public static let minNonceLength = 16
        /// HMAC-SHA256 tag length in bytes.
        public static let authTagLength = 32
        /// Curve25519 raw public key length in bytes.
        public static let publicKeyLength = 32
    }

    public enum RateLimit {
        /// Sustained control commands allowed per sender per window.
        public static let commandsPerWindow = 5
        /// Rate-limit window, in seconds.
        public static let window: TimeInterval = 10
    }
}
