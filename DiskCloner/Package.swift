// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DiskCloner",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "DiskCloner",
            path: "DiskCloner",
            exclude: ["DiskCloner.entitlements"],
            resources: [
                .process("Assets.xcassets")
            ]
        )
    ]
)
