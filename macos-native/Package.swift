// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SSHKeyDeployer",
    platforms: [.macOS(.v13)],
    targets: [
        // Deployment logic with no UI dependency. Uses only Foundation, CryptoKit
        // and the OpenSSH tools that ship with macOS.
        .target(name: "DeployerCore"),
        .executableTarget(
            name: "SSHKeyDeployer",
            dependencies: ["DeployerCore"]),
        .testTarget(
            name: "DeployerCoreTests",
            dependencies: ["DeployerCore"]),
    ]
)
