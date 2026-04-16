/*
 * envelope.h - Authenticated Share Envelope (v2)
 *
 * Each Shamir share is wrapped in an authenticated envelope with integrity
 * protection. The envelope binds a share to (a) the secret it came from
 * (via the auth key derived from the secret), and (b) the threshold the
 * shares were produced against (via the `threshold` byte fed into the MAC).
 *
 * Envelope format (v2):
 *   [version:1][share_index:1][threshold:1][payload_len:2][payload:N][auth_tag:32]
 *
 * Total size: 5 + payload_len + 32 = 37 + payload_len bytes
 *
 * Version history:
 *   v1 — hand-rolled SHA-256/HMAC, PBKDF2 (1.x series; unsupported in 2.x).
 *   v2 — libsodium crypto_auth (HMAC-SHA512/256), Argon2id for passphrases.
 */

#ifndef KEYSHARE_ENVELOPE_H
#define KEYSHARE_ENVELOPE_H

#include <stdint.h>
#include <stddef.h>

/* Envelope version written by this code. */
#define ENVELOPE_VERSION 2

/* Legacy 1.x envelope version. Surfaced to produce a clear migration error. */
#define ENVELOPE_VERSION_LEGACY 1

/* Header size: version(1) + index(1) + threshold(1) + payload_len(2). */
#define ENVELOPE_HEADER_SIZE 5

/* Auth tag size (libsodium crypto_auth_BYTES = HMAC-SHA512/256 output). */
#define ENVELOPE_TAG_SIZE 32

/* Minimum envelope size (header + minimum 1-byte payload + tag). */
#define ENVELOPE_MIN_SIZE (ENVELOPE_HEADER_SIZE + 1 + ENVELOPE_TAG_SIZE)

/* Maximum payload length (limited by 16-bit length field). */
#define ENVELOPE_MAX_PAYLOAD 65535

/* Error codes. Callers distinguish ENVELOPE_ERR_LEGACY_VERSION from other
 * failures so they can surface a migration-specific message. */
#define ENVELOPE_OK 0
#define ENVELOPE_ERR_INVALID_VERSION -1
#define ENVELOPE_ERR_MAC_MISMATCH -2
#define ENVELOPE_ERR_TOO_SHORT -3
#define ENVELOPE_ERR_LENGTH_MISMATCH -4
#define ENVELOPE_ERR_PAYLOAD_TOO_LARGE -5
#define ENVELOPE_ERR_MEMORY -6
#define ENVELOPE_ERR_LEGACY_VERSION -7

/*
 * Calculate required envelope size for a given payload length.
 */
static inline size_t envelope_size(size_t payload_len) {
	return ENVELOPE_HEADER_SIZE + payload_len + ENVELOPE_TAG_SIZE;
}

/*
 * Create an authenticated envelope for a share.
 *
 * Parameters:
 *   share_index   - Share index (1-255)
 *   threshold     - Threshold value (2-255)
 *   payload       - Raw share bytes (from libgfshare)
 *   payload_len   - Length of payload
 *   auth_key      - 32-byte authentication key (caller-derived from secret)
 *   envelope      - Output buffer (must be at least envelope_size() bytes)
 *
 * Returns:
 *   Total envelope size on success, negative error code on failure.
 */
int envelope_create(
    uint8_t share_index,
    uint8_t threshold,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *envelope
);

/*
 * Parse and verify an authenticated envelope.
 *
 * Verification is done in constant time via libsodium's crypto_auth_verify().
 *
 * Parameters:
 *   envelope      - Input envelope bytes
 *   envelope_len  - Length of envelope
 *   auth_key      - 32-byte authentication key
 *   share_index   - Output: share index
 *   threshold     - Output: threshold value
 *   payload       - Output: pointer into envelope buffer (not copied)
 *   payload_len   - Output: payload length
 *
 * Returns:
 *   ENVELOPE_OK on success; ENVELOPE_ERR_LEGACY_VERSION if a v1 envelope
 *   was detected (caller should raise a migration-required error);
 *   other negative code on any other failure.
 */
int envelope_verify(
    const uint8_t *envelope,
    size_t envelope_len,
    const uint8_t *auth_key,
    uint8_t *share_index,
    uint8_t *threshold,
    const uint8_t **payload,
    size_t *payload_len
);

/*
 * Derive the 32-byte authentication key used to MAC envelopes, given a
 * master key (either the raw user secret or the Argon2id-derived key).
 *
 * Uses BLAKE2b with the KEYSHARE_AUTH_PERSONAL personalization for domain
 * separation. The master bytes are treated purely as input data to
 * generichash — they are never used as a MAC key directly, which avoids
 * any assumption on their entropy or length.
 *
 * Parameters:
 *   master      - Input master key material (the secret or derived key)
 *   master_len  - Length of master
 *   auth_key    - Output: 32-byte authentication key
 *
 * Returns:
 *   0 on success, -1 on failure (BLAKE2b only fails on bad parameters).
 */
int envelope_derive_auth_key(
    const uint8_t *master,
    size_t master_len,
    uint8_t *auth_key
);

#endif /* KEYSHARE_ENVELOPE_H */
