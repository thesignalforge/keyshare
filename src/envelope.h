/*
 * envelope.h - Authenticated Share Envelope
 *
 * Each share is wrapped in an authenticated envelope with integrity protection.
 *
 * Envelope format:
 *   [version:1][share_index:1][threshold:1][payload_len:2][payload:N][auth_tag:32]
 *
 * Total size: 5 + payload_len + 32 = 37 + payload_len bytes
 */

#ifndef KEYSHARE_ENVELOPE_H
#define KEYSHARE_ENVELOPE_H

#include <stdint.h>
#include <stddef.h>

/* Current envelope version */
#define ENVELOPE_VERSION 1

/* Header size: version(1) + index(1) + threshold(1) + payload_len(2) */
#define ENVELOPE_HEADER_SIZE 5

/* Auth tag size (HMAC-SHA256) */
#define ENVELOPE_TAG_SIZE 32

/* Minimum envelope size */
#define ENVELOPE_MIN_SIZE (ENVELOPE_HEADER_SIZE + 1 + ENVELOPE_TAG_SIZE)

/* Error codes */
#define ENVELOPE_OK 0
#define ENVELOPE_ERR_INVALID_VERSION -1
#define ENVELOPE_ERR_MAC_MISMATCH -2
#define ENVELOPE_ERR_TOO_SHORT -3
#define ENVELOPE_ERR_LENGTH_MISMATCH -4
#define ENVELOPE_ERR_THRESHOLD_MISMATCH -5

/*
 * Create an authenticated envelope for a share.
 *
 * Parameters:
 *   share_index   - Share index (1-255)
 *   threshold     - Threshold value (2-255)
 *   payload       - Raw share data
 *   payload_len   - Length of payload
 *   auth_key      - 32-byte authentication key (derived from secret)
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
 * Calculate required envelope size for given payload.
 */
static inline size_t envelope_size(size_t payload_len) {
    return ENVELOPE_HEADER_SIZE + payload_len + ENVELOPE_TAG_SIZE;
}

/*
 * Parse and verify an authenticated envelope.
 *
 * Parameters:
 *   envelope      - Input envelope data
 *   envelope_len  - Length of envelope
 *   auth_key      - 32-byte authentication key
 *   share_index   - Output: share index
 *   threshold     - Output: threshold value
 *   payload       - Output: pointer to payload within envelope (not copied)
 *   payload_len   - Output: payload length
 *
 * Returns:
 *   ENVELOPE_OK on success, negative error code on failure.
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
 * Derive authentication key from secret using HKDF-like expansion.
 *
 * Parameters:
 *   secret      - Input secret
 *   secret_len  - Length of secret
 *   auth_key    - Output: 32-byte authentication key
 */
void envelope_derive_auth_key(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *auth_key
);

/*
 * Constant-time memory comparison.
 *
 * Returns 0 if equal, non-zero if different.
 */
int envelope_ct_compare(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* KEYSHARE_ENVELOPE_H */
