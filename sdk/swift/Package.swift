// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OpenEntityKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "OpenEntityKit", targets: ["OpenEntityKit"])],
    targets: [
        .target(name: "OpenEntityKit"),
        .testTarget(name: "OpenEntityKitTests", dependencies: ["OpenEntityKit"]),
    ]
)
