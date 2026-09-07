// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MacNexaProbe",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "MacNexaProbe")
    ]
)
