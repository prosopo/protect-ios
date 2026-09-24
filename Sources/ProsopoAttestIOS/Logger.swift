// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation
import os

/// Centralized logger for the ProsopoAttestIOS SDK.
///
/// Every line carries the ``tag`` prefix. The subsystem and category already
/// identify us to `log stream` and Console, but neither survives the places the
/// SDK's output is actually read: a customer pasting a few lines into a support
/// thread, or Xcode's console, which shows the message and nothing else. The
/// prefix is what makes a stray line attributable to us rather than to the host
/// app.
enum ProsopoLogger {
    /// Prefixed to every message. Changing it changes what customers see in
    /// their own logs, so it is deliberately a single constant.
    static let tag = "[Prosopo-Protect]"

    /// The subsystem is the filter key customers are told to use
    /// (`subsystem == "io.prosopo.protect"`), so it is not renamed alongside
    /// the display tag.
    static let logger = os.Logger(subsystem: "io.prosopo.protect", category: "Prosopo-Protect")

    static func debug(_ message: String) {
        logger.debug("\(tag, privacy: .public) \(message, privacy: .public)")
    }

    static func info(_ message: String) {
        logger.info("\(tag, privacy: .public) \(message, privacy: .public)")
    }

    static func warning(_ message: String) {
        logger.warning("\(tag, privacy: .public) \(message, privacy: .public)")
    }

    static func error(_ message: String) {
        logger.error("\(tag, privacy: .public) \(message, privacy: .public)")
    }
}
