// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SmartSecureKeypad",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "SmartSecureKeypad", targets: ["SmartSecureKeypad"]),
    ],

    targets: [
        .target(
            name: "SmartSecureKeypadCore",
            path: "Sources/SmartSecureKeypadCore"
        ),
        .target(
            name: "SmartSecureKeypadCrypto",
            dependencies: ["SmartSecureKeypadCore"],
            path: "Sources/SmartSecureKeypadCrypto"
        ),
        .target(
            name: "SmartSecureKeypadUI",
            dependencies: ["SmartSecureKeypadCore", "SmartSecureKeypadCrypto"],
            path: "Sources/SmartSecureKeypadUI"
        ),

        // ✅ Umbrella
        .target(
            name: "SmartSecureKeypad",
            dependencies: ["SmartSecureKeypadUI", "SmartSecureKeypadCore", "SmartSecureKeypadCrypto"],
            path: "Sources/SmartSecureKeypad"
        ),

        .testTarget(
            name: "SmartSecureKeypadTests",
            dependencies: ["SmartSecureKeypad"],
            path: "Tests/SmartSecureKeypadTests"
        )
    ]
)
