// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftHPKE",
    platforms: [.macOS(.v10_15), .iOS(.v13), .watchOS(.v8)], // Due to the use of the CryptoKit framework
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "SwiftHPKE",
            targets: ["SwiftHPKE"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.15.0"),
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.3.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.2.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SwiftHPKE",
            dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(
            name: "SwiftHPKETests",
            dependencies: ["SwiftHPKE"]),
    ]
)
