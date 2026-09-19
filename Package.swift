// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AppSentinel",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "appsentinel", targets: ["appsentinel"]),
        .library(name: "AppSentinelCore", targets: ["AppSentinelCore"]),
        .library(name: "AppSentinelSystem", targets: ["AppSentinelSystem"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "AppSentinelCore",
            dependencies: []
        ),
        .target(
            name: "AppSentinelSystem",
            dependencies: ["AppSentinelCore"]
        ),
        .executableTarget(
            name: "appsentinel",
            dependencies: ["AppSentinelCore", "AppSentinelSystem"]
        ),
        .testTarget(
            name: "AppSentinelCoreTests",
            dependencies: ["AppSentinelCore"]
        ),
        .testTarget(
            name: "AppSentinelSystemTests",
            dependencies: ["AppSentinelSystem", "AppSentinelCore"]
        ),
        .testTarget(
            name: "appsentinelIntegrationTests",
            dependencies: ["appsentinel", "AppSentinelCore", "AppSentinelSystem"]
        )
    ]
)
