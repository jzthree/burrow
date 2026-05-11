// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "burrow",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "PortKeeperCore",
            targets: ["PortKeeperCore"]
        ),
        .executable(
            name: "burrow",
            targets: ["portkeeper"]
        ),
        .executable(
            name: "BurrowApp",
            targets: ["PortKeeperMenuBar"]
        ),
    ],
    targets: [
        .target(
            name: "PortKeeperCore"
        ),
        .executableTarget(
            name: "portkeeper",
            dependencies: ["PortKeeperCore"]
        ),
        .executableTarget(
            name: "PortKeeperMenuBar",
            dependencies: ["PortKeeperCore"]
        ),
        .testTarget(
            name: "portkeeperTests",
            dependencies: ["PortKeeperCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
