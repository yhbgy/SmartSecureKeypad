// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SmartSecureKeypad",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "SmartSecureKeypadCore", targets: ["SmartSecureKeypadCore"]),
        .library(name: "SmartSecureKeypadUI", targets: ["SmartSecureKeypadUI"]),
    ],
    targets: [
        .target(
            name: "SmartSecureKeypadCore",
            path: "Sources/SmartSecureKeypadCore"
        ),
        .target(
            name: "SmartSecureKeypadUI",
            dependencies: ["SmartSecureKeypadCore"],
            path: "Sources/SmartSecureKeypadUI"
        ),
        .testTarget(
            name: "SmartSecureKeypadTests",
            dependencies: ["SmartSecureKeypadCore"],
            path: "Tests/SmartSecureKeypadTests"
        )
    ]
)
