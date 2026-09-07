import Foundation
import CryptoKit

/// Signs and verifies protocol messages using an HMAC-SHA256 authentication key
/// derived from the peer key agreement (spec §13-15).
///
/// Verification is constant-time (via CryptoKit) and validates the tag length
/// before comparison so malformed tags are rejected cleanly rather than
/// triggering undefined behavior.
public struct MessageSigner: Sendable {
    private let authenticationKey: SymmetricKey

    public init(authenticationKey: SymmetricKey) {
        self.authenticationKey = authenticationKey
    }

    /// Returns a signed copy of the message with the `authentication` tag set.
    public func sign(_ message: NetworkMessage) throws -> NetworkMessage {
        let data = try message.signedData()
        let tag = HMAC<SHA256>.authenticationCode(for: data, using: authenticationKey)
        var signed = message
        signed.authentication = Data(tag).base64EncodedString()
        return signed
    }

    /// Verifies a message's authentication tag. Throws on any failure. Does NOT
    /// check trust, freshness, or replay — that is the CommandValidator's job.
    public func verify(_ message: NetworkMessage) throws {
        guard let auth = message.authentication,
              let tag = Data(base64Encoded: auth),
              tag.count == Constants.Security.authTagLength else {
            throw ProtocolError.invalidAuthentication
        }
        let data = try message.signedData()
        let valid = HMAC<SHA256>.isValidAuthenticationCode(
            tag,
            authenticating: data,
            using: authenticationKey
        )
        if !valid { throw ProtocolError.invalidAuthentication }
    }
}
