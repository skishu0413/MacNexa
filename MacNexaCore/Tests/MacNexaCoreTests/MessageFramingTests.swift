import XCTest
@testable import MacNexaCore

final class MessageFramingTests: XCTestCase {
    func testEncodeDecodeRoundTrip() throws {
        let payload = Data("hello world".utf8)
        let frame = try MessageFraming.encode(payload)
        let decoded = try MessageFraming.decode(from: frame)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.payload, payload)
        XCTAssertEqual(decoded?.consumed, frame.count)
    }

    func testDecodeReturnsNilForPartialHeader() throws {
        XCTAssertNil(try MessageFraming.decode(from: Data([0x00, 0x01])))
    }

    func testDecodeReturnsNilForPartialBody() throws {
        var frame = try MessageFraming.encode(Data("abcdef".utf8))
        frame.removeLast(2)
        XCTAssertNil(try MessageFraming.decode(from: frame))
    }

    func testOversizedFrameThrows() {
        let huge = Data(repeating: 0, count: 10)
        // Announce a giant length via a hand-built header.
        var length = UInt32(Constants.Security.maxMessageBytes + 1).bigEndian
        var frame = Data(bytes: &length, count: 4)
        frame.append(huge)
        XCTAssertThrowsError(try MessageFraming.decode(from: frame))
    }

    func testFrameDecoderHandlesSplitAndCoalescedFrames() throws {
        let decoder = FrameDecoder()
        let f1 = try MessageFraming.encode(Data("one".utf8))
        let f2 = try MessageFraming.encode(Data("two".utf8))
        // Feed first frame split across two appends.
        XCTAssertEqual(try decoder.append(f1.prefix(3)).count, 0)
        let afterRest = try decoder.append(f1.suffix(from: f1.index(f1.startIndex, offsetBy: 3)))
        XCTAssertEqual(afterRest.map { String(data: $0, encoding: .utf8) }, ["one"])
        // Feed two frames coalesced.
        let both = try decoder.append(f2 + (try MessageFraming.encode(Data("three".utf8))))
        XCTAssertEqual(both.map { String(data: $0, encoding: .utf8) }, ["two", "three"])
    }
}
