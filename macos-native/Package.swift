// swift-tools-version:5.9
import PackageDescription

var targets: [Target] = [
    // Deployment logic with no UI dependency. Uses only Foundation, CryptoKit
    // (a portable fallback is used where CryptoKit is unavailable) and the
    // system OpenSSH tools.
    .target(name: "DeployerCore"),
    // Headless command-line driver used by the end-to-end tests (Linux and macOS).
    .executableTarget(
        name: "deployer-e2e",
        dependencies: ["DeployerCore"]),
]

var products: [Product] = [
    .executable(name: "deployer-e2e", targets: ["deployer-e2e"]),
]

#if os(macOS)
// The SwiftUI app and the unit tests are macOS-only.
targets += [
    .executableTarget(
        name: "SSHKeyDeployer",
        dependencies: ["DeployerCore"]),
    .testTarget(
        name: "DeployerCoreTests",
        dependencies: ["DeployerCore"]),
]
products.append(.executable(name: "SSHKeyDeployer", targets: ["SSHKeyDeployer"]))
#endif

let package = Package(
    name: "SSHKeyDeployer",
    platforms: [.macOS(.v13)],
    products: products,
    targets: targets
)
