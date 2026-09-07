import Foundation
import OSLog

/// Structured OSLog loggers, one per subsystem category (spec §6, §30).
/// Sensitive material must never be logged; device identifiers use privacy
/// redaction at the call site.
enum Log {
    private static let subsystem = "com.macnexa.app"

    static let bluetooth = Logger(subsystem: subsystem, category: "bluetooth")
    static let network = Logger(subsystem: subsystem, category: "network")
    static let discovery = Logger(subsystem: subsystem, category: "discovery")
    static let switching = Logger(subsystem: subsystem, category: "switching")
    static let security = Logger(subsystem: subsystem, category: "security")
    static let pairing = Logger(subsystem: subsystem, category: "pairing")
    static let storage = Logger(subsystem: subsystem, category: "storage")
    static let ui = Logger(subsystem: subsystem, category: "ui")
}
