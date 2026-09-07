// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MacNexaCore",
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
            name: "MacNexaCore"
        ),
        .testTarget(
            name: "MacNexaCoreTests",
            dependencies: ["MacNexaCore"]
        )
    ]
)
