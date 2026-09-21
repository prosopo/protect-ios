// swift-tools-version: 6.0
// Copyright 2021-2026 Prosopo (UK) Ltd.

import PackageDescription

let package = Package(
    name: "ProsopoAttestIOS",
    platforms: [
        .iOS(.v17),
        // Not a shipping platform — declared only so `swift build` / `swift test`
        // work on a developer Mac. DeviceCheck's App Attest API needs macOS 11.
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "ProsopoAttestIOS",
            targets: ["ProsopoAttestIOS"]
        ),
    ],
    targets: [
        // Objective-C exception barrier around DeviceCheck. Must stay a separate
        // target: the @try/@catch has to sit in an Objective-C frame so an
        // NSException raised by DeviceCheck never unwinds through Swift.
        .target(
            name: "ProsopoAttestShim",
            path: "Sources/ProsopoAttestShim",
            linkerSettings: [
                .linkedFramework("DeviceCheck"),
            ]
        ),
        .target(
            name: "ProsopoAttestIOS",
            dependencies: ["ProsopoAttestShim"],
            path: "Sources/ProsopoAttestIOS",
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .testTarget(
            name: "ProsopoAttestIOSTests",
            dependencies: ["ProsopoAttestIOS", "ProsopoAttestShim"]
        ),
    ]
)
