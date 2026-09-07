import Foundation

/// A strongly-typed, versioned protocol envelope (spec §12).
///
/// The `authentication` field carries a detached signature/MAC computed over the
/// canonical signed representation of the message (see `signedData`). It is kept
/// separate so the same struct can represent both signed and unsigned messages.
public struct NetworkMessage: Codable, Equatable, Sendable {
    public let version: Int
    public let messageId: UUID
    public let senderId: UUID
    /// Transaction this message belongs to, if any (spec §20).
    public let transactionId: UUID?
    public let timestamp: TimeInterval
    public let nonce: String
    public let type: MessageType
    /// Opaque, type-specific payload encoded as JSON bytes.
    public let payload: Data
    /// Detached authentication tag (base64). Nil for unauthenticated messages.
    public var authentication: String?

    public init(
        version: Int = Constants.protocolVersion,
        messageId: UUID = UUID(),
        senderId: UUID,
        transactionId: UUID? = nil,
        timestamp: TimeInterval,
        nonce: String,
        type: MessageType,
        payload: Data = Data(),
        authentication: String? = nil
    ) {
        self.version = version
        self.messageId = messageId
        self.senderId = senderId
        self.transactionId = transactionId
        self.timestamp = timestamp
        self.nonce = nonce
        self.type = type
        self.payload = payload
        self.authentication = authentication
    }

    /// The canonical byte representation that authentication is computed over.
    /// Excludes the `authentication` field itself so signing is well-defined.
    public func signedData() throws -> Data {
        var copy = self
        copy.authentication = nil
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(copy)
    }

    /// Encode the full message (including authentication) for transport.
    public func serialize() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    /// Decode a message from transport bytes, enforcing a maximum frame size to
    /// prevent memory-exhaustion denial of service (spec §13 "denial of service").
    public static func deserialize(
        _ data: Data,
        maxBytes: Int = Constants.Security.maxMessageBytes
    ) throws -> NetworkMessage {
        guard data.count <= maxBytes else {
            throw ProtocolError.messageTooLarge(data.count)
        }
        do {
            return try JSONDecoder().decode(NetworkMessage.self, from: data)
        } catch {
            throw ProtocolError.malformedMessage
        }
    }

    /// Structural validation independent of cryptography: version support and
    /// nonce entropy. Throws a typed `ProtocolError` on failure.
    public func validateStructure() throws {
        guard version == Constants.protocolVersion else {
            throw ProtocolError.unsupportedVersion(version)
        }
        // Nonce is transported as a base64 string; require minimum decoded entropy.
        guard let nonceData = Data(base64Encoded: nonce),
              nonceData.count >= Constants.Security.minNonceLength else {
            throw ProtocolError.weakNonce
        }
        guard payload.count <= Constants.Security.maxMessageBytes else {
            throw ProtocolError.messageTooLarge(payload.count)
        }
    }
}
