// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MacNexa",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "MacNexaCore",
            targets: ["MacNexaCore"]
        )
    ],
    targets: [
        .target(
            name: "MacNexaCore",
            path: "MacNexaCore/Sources/MacNexaCore"
        ),
        .testTarget(
            name: "MacNexaCoreTests",
            dependencies: ["MacNexaCore"],
            path: "MacNexaCore/Tests/MacNexaCoreTests"
        )
    ]
)
