import Foundation

/// Errors that can occur during a device switch transaction (spec §31).
public enum SwitchError: Error, Equatable, Sendable {
    case peerUnavailable
    case peerAuthenticationFailed
    case releaseRejected
    case releaseTimedOut
    case keyboardConnectionFailed
    case trackpadConnectionFailed
    case verificationFailed
    case transactionConflict
    case rollbackFailed
}

/// Errors raised while validating or authenticating protocol messages (spec §13, §16).
///
/// Every reject path is explicit so command handling can fail closed: a message
/// is executed only when NONE of these are thrown.
public enum ProtocolError: Error, Equatable, Sendable {
    /// Wire version not supported by this build.
    case unsupportedVersion(Int)
    /// Message could not be decoded, or exceeds size/field bounds.
    case malformedMessage
    /// Encoded frame is larger than the allowed maximum (DoS guard).
    case messageTooLarge(Int)
    /// Sender is not in the trust store, or its key does not match.
    case untrustedSender
    /// Authentication tag missing, malformed, or does not verify.
    case invalidAuthentication
    /// Timestamp is outside the acceptable skew window.
    case timestampOutOfWindow
    /// messageId or nonce has already been processed.
    case replayDetected
    /// Nonce is missing or does not meet minimum entropy requirements.
    case weakNonce
    /// Sender exceeded the allowed command rate (DoS guard).
    case rateLimited
    /// Payload does not match the declared message type.
    case payloadMismatch
}
