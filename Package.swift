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
    dependencies: [
        // Self-update: signed appcast, download, verify, swap-and-relaunch.
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.0"),
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
            dependencies: [
                "PortKeeperCore",
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            linkerSettings: [
                // Find the embedded Sparkle.framework in Contents/Frameworks
                // when running from the installed .app bundle.
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"]),
            ]
        ),
        .testTarget(
            name: "portkeeperTests",
            // The dependency on the `portkeeper` executable makes `swift test`
            // build the burrow binary so the CLI smoke tests can spawn it.
            dependencies: ["PortKeeperCore", "portkeeper"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
