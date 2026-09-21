// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// Manages the challenge lifecycle for the assertion flow.
///
/// Challenges are piggybacked on API responses to avoid extra round trips.
/// The first request fetches a challenge explicitly; subsequent requests
/// use the challenge from the previous response.
///
/// # A challenge belongs to exactly one request
///
/// The server stores each challenge in Redis and consumes it with an atomic
/// delete, so the second assertion built on the same challenge is rejected —
/// there is no "mostly single use" here, the loser is simply refused.
///
/// That makes the take-and-clear below the load-bearing part of this type.
/// It used to be two calls: `getChallenge` returned the cached value and left
/// it in place, and `consumeCurrent()` cleared it *after* the caller had
/// finished minting an assertion. Between those two calls the actor was free to
/// serve the same challenge again, so any two overlapping requests — which is
/// most of them, an app screen rarely fetches one thing — raced, and whichever
/// assertion reached the server second was thrown out. The request then went
/// out unsigned and the edge refused it.
///
/// It is not rare. On a live integration, half of the denials were on devices
/// that had *already attested successfully* — which the cold-start race cannot
/// explain and this can.
///
/// Doing both halves in one actor-isolated call closes it. Nothing else may
/// hand the same challenge to two callers, so the only way to serve two
/// concurrent requests is to fetch a second challenge — which is correct, and
/// is what `NetworkClient.fetchChallenge` is for.
///
/// Note this is deliberately *not* single-flighted. Coalescing concurrent
/// fetches would hand one challenge to N callers and reintroduce the same bug
/// from the other end: each caller genuinely needs its own.
actor ChallengeManager {
    private let networkClient: NetworkClient
    private var currentChallenge: String?

    init(networkClient: NetworkClient) {
        self.networkClient = networkClient
    }

    /// Claim a challenge for one assertion.
    ///
    /// Takes the piggybacked challenge if one is banked — removing it in the
    /// same actor hop, so no other caller can be given it — and otherwise
    /// fetches a fresh one from the server.
    func takeChallenge(keyId: String) async throws -> String {
        if let cached = currentChallenge {
            currentChallenge = nil
            ProsopoLogger.debug("Claimed cached challenge")
            return cached
        }

        ProsopoLogger.debug("No cached challenge, fetching from server")
        return try await networkClient.fetchChallenge(keyId: keyId)
    }

    /// Fetch a challenge from the server, ignoring anything banked.
    ///
    /// The retry path uses this: if an assertion failed, the banked challenge
    /// is the prime suspect (already spent, or expired while the app sat in the
    /// background), so reaching for it again would just fail the same way.
    func fetchFreshChallenge(keyId: String) async throws -> String {
        try await networkClient.fetchChallenge(keyId: keyId)
    }

    /// Store a new challenge received from a response (piggybacking).
    func store(challenge: String) {
        guard !challenge.isEmpty else { return }
        currentChallenge = challenge
        ProsopoLogger.debug("Stored piggybacked challenge")
    }

    /// Whether a piggybacked challenge is currently banked. Test seam.
    var hasBankedChallenge: Bool {
        currentChallenge != nil
    }
}
