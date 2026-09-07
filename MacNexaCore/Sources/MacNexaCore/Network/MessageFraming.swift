import Foundation

/// Length-prefixed framing so multiple messages can share a byte stream.
///
/// Wire format: 4-byte big-endian unsigned length, followed by that many bytes
/// of payload. A maximum frame size is enforced to prevent a malicious peer from
/// announcing a huge length (spec §13 denial of service).
public enum MessageFraming {
    public static let headerSize = 4

    /// Encodes a payload into a length-prefixed frame.
    public static func encode(_ payload: Data, maxBytes: Int = Constants.Security.maxMessageBytes) throws -> Data {
        guard payload.count <= maxBytes else {
            throw ProtocolError.messageTooLarge(payload.count)
        }
        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: headerSize)
        frame.append(payload)
        return frame
    }

    /// Attempts to decode a single frame from the head of `buffer`. On success,
    /// returns the payload and the number of bytes consumed. Returns nil when
    /// more bytes are needed. Throws if a frame exceeds the maximum size.
    public static func decode(
        from buffer: Data,
        maxBytes: Int = Constants.Security.maxMessageBytes
    ) throws -> (payload: Data, consumed: Int)? {
        guard buffer.count >= headerSize else { return nil }
        let lengthBytes = buffer.prefix(headerSize)
        let length = lengthBytes.withUnsafeBytes { raw in
            UInt32(bigEndian: raw.loadUnaligned(as: UInt32.self))
        }
        let len = Int(length)
        guard len <= maxBytes else { throw ProtocolError.messageTooLarge(len) }
        let total = headerSize + len
        guard buffer.count >= total else { return nil }
        let start = buffer.index(buffer.startIndex, offsetBy: headerSize)
        let end = buffer.index(buffer.startIndex, offsetBy: total)
        return (Data(buffer[start..<end]), total)
    }
}

/// Accumulates streamed bytes and yields complete message payloads.
public final class FrameDecoder {
    private var buffer = Data()
    private let maxBytes: Int

    public init(maxBytes: Int = Constants.Security.maxMessageBytes) {
        self.maxBytes = maxBytes
    }

    /// Appends bytes and returns any complete frames now available.
    public func append(_ data: Data) throws -> [Data] {
        buffer.append(data)
        var frames: [Data] = []
        while let (payload, consumed) = try MessageFraming.decode(from: buffer, maxBytes: maxBytes) {
            frames.append(payload)
            buffer.removeFirst(consumed)
        }
        return frames
    }
}
