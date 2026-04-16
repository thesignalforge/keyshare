<?php
/**
 * KeyShare Extension for Signalforge Framework
 *
 * Implements Shamir's Secret Sharing over GF(256) using libgfshare for the
 * field arithmetic and libsodium for all envelope authentication and
 * password-based key derivation. Each share is wrapped in an authenticated
 * envelope (versioned header + MAC) so tampering is detected at recovery.
 *
 * @version 2.0.0
 * @package Signalforge\KeyShare
 */

declare(strict_types=1);

namespace Signalforge\KeyShare;

/**
 * Base exception for key share operations.
 *
 * Thrown for invalid arguments, oversized secrets, malformed envelopes,
 * decoding errors and other unrecoverable conditions (including shares
 * produced by the legacy 1.x format, which are not recoverable here).
 */
class Exception extends \Exception
{
}

/**
 * Thrown when share authentication (MAC verification) fails.
 *
 * Indicates either tampering or accidentally mixing shares from different
 * splits.
 */
class TamperingException extends Exception
{
}

/**
 * Thrown when there are not enough valid shares to reconstruct the secret.
 *
 * The threshold is encoded inside each share's envelope; recovery cannot
 * proceed if fewer than `threshold` shares are supplied.
 */
class InsufficientSharesException extends Exception
{
}

/**
 * Split a secret into authenticated shares using Shamir's Secret Sharing.
 *
 * Generates `$shares` envelopes, any `$threshold` of which can rebuild the
 * original secret via {@see recover()}. Each envelope is base64-encoded and
 * carries a libsodium crypto_auth (HMAC-SHA512/256) MAC keyed off the
 * secret, so tampering or mixed shares are detected on recovery.
 *
 * Constraints:
 *  - `$threshold` must be at least 2 and `<= $shares`
 *  - `$shares` must be in `2..255`
 *  - `$secret` must be non-empty and `<= 65535` bytes
 *
 * @param string $secret Raw secret bytes (binary-safe)
 * @param int $threshold Minimum shares required to recover (k in k-of-n)
 * @param int $shares Total shares to produce (n in k-of-n)
 * @return array<int, string> Base64-encoded authenticated shares
 * @throws Exception On invalid parameters or split failure
 *
 * @example
 * $shares = \Signalforge\KeyShare\share('top-secret', 3, 5);
 * // Distribute $shares to 5 holders; any 3 can recover.
 */
function share(string $secret, int $threshold, int $shares): array {}

/**
 * Reconstruct a secret from a subset of shares.
 *
 * Performs Lagrange interpolation over GF(256) via libgfshare to rebuild
 * the secret, then re-derives the authentication key and verifies every
 * supplied share's MAC via libsodium crypto_auth_verify (constant-time).
 * If any MAC fails, a {@see TamperingException} is raised.
 *
 * Shares produced by the legacy 1.x format (envelope version 1) are
 * rejected with a clear migration error; they must be re-issued with
 * 2.x.
 *
 * @param array<int, string> $shares Base64-encoded shares from {@see share()}
 * @return string The reconstructed secret bytes
 * @throws InsufficientSharesException If fewer than threshold shares are provided
 * @throws TamperingException If MAC verification fails (tampered or mixed shares)
 * @throws Exception On malformed envelopes, base64 errors, legacy format,
 *                   or interpolation failure
 *
 * @example
 * $secret = \Signalforge\KeyShare\recover([$shareA, $shareC, $shareE]);
 */
function recover(array $shares): string {}

/**
 * Derive a 32-byte key from a passphrase and split it into shares.
 *
 * Uses libsodium crypto_pwhash (Argon2id, MODERATE cost parameters) with
 * a deterministic salt derived from the passphrase to produce a 256-bit
 * key, then runs the same Shamir split as {@see share()}. The same
 * passphrase will always produce shares for the same underlying key.
 *
 * Argon2id MODERATE is intentionally slow — expect ~0.5-1 second per call
 * on typical server hardware. This cost is the primary defence against
 * offline brute force of a stolen share.
 *
 * @param string $passphrase Non-empty passphrase
 * @param int $threshold Minimum shares required to recover
 * @param int $shares Total shares to produce
 * @return array<int, string> Base64-encoded authenticated shares of the derived key
 * @throws Exception On invalid parameters, derivation failure, or split failure
 *
 * @example
 * $shares = \Signalforge\KeyShare\passphrase('correct horse battery staple', 2, 3);
 * $derivedKey = \Signalforge\KeyShare\recover([$shares[0], $shares[2]]);
 */
function passphrase(string $passphrase, int $threshold, int $shares): array {}
