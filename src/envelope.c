/*
 * envelope.c - Authenticated Share Envelope Implementation
 *
 * Provides integrity protection for shares using HMAC-SHA256.
 */

#include "envelope.h"
#include "kdf.h"
#include "../php_keyshare.h"
#include <string.h>
#include <stdlib.h>

/*
 * Constant-time memory comparison to prevent timing attacks.
 *
 * Always examines all bytes regardless of where differences occur.
 * Returns 0 if equal, non-zero if different.
 */
int envelope_ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    volatile size_t i;

    for (i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }

    return result;
}

/*
 * Derive authentication key from secret.
 * Uses HKDF-like expansion: HMAC(secret, info || 0x01)
 */
int envelope_derive_auth_key(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *auth_key
) {
    uint8_t info_with_counter[KEYSHARE_AUTH_CONTEXT_LEN + 1];

    memcpy(info_with_counter, KEYSHARE_AUTH_CONTEXT, KEYSHARE_AUTH_CONTEXT_LEN);
    info_with_counter[KEYSHARE_AUTH_CONTEXT_LEN] = 0x01;

    return hmac_sha256(secret, secret_len,
                       info_with_counter, sizeof(info_with_counter),
                       auth_key);
}

/*
 * Compute authentication tag for envelope header + payload.
 *
 * Uses stack buffer for small payloads to avoid allocation overhead.
 * Properly handles memory and clears sensitive data.
 */
static int compute_auth_tag(
    const uint8_t *header,
    size_t header_len,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *tag
) {
    size_t total_len;
    uint8_t stack_buf[ENVELOPE_STACK_BUF_SIZE];
    uint8_t *data = NULL;
    int allocated = 0;
    int result;

    /* Check for overflow */
    total_len = keyshare_safe_add(header_len, payload_len);
    if (total_len == 0 && (header_len != 0 || payload_len != 0)) {
        memset(tag, 0, ENVELOPE_TAG_SIZE);
        return ENVELOPE_ERR_MEMORY;
    }

    /* For small payloads, use stack; for large, allocate */
    if (total_len <= sizeof(stack_buf)) {
        data = stack_buf;
    } else {
        data = (uint8_t *)malloc(total_len);
        if (!data) {
            memset(tag, 0, ENVELOPE_TAG_SIZE);
            return ENVELOPE_ERR_MEMORY;
        }
        allocated = 1;
    }

    memcpy(data, header, header_len);
    memcpy(data + header_len, payload, payload_len);

    result = hmac_sha256(auth_key, KEYSHARE_SHA256_LEN, data, total_len, tag);

    /* Secure cleanup */
    keyshare_secure_zero(data, total_len);

    if (allocated) {
        free(data);
    }

    return (result == 0) ? ENVELOPE_OK : ENVELOPE_ERR_MEMORY;
}

int envelope_create(
    uint8_t share_index,
    uint8_t threshold,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *envelope
) {
    int result;

    if (payload_len > ENVELOPE_MAX_PAYLOAD) {
        return ENVELOPE_ERR_PAYLOAD_TOO_LARGE;
    }

    /* Build header */
    envelope[0] = ENVELOPE_VERSION;
    envelope[1] = share_index;
    envelope[2] = threshold;
    keyshare_write_be16(envelope + 3, (uint16_t)payload_len);

    /* Copy payload */
    memcpy(envelope + ENVELOPE_HEADER_SIZE, payload, payload_len);

    /* Compute and append auth tag */
    result = compute_auth_tag(
        envelope, ENVELOPE_HEADER_SIZE,
        payload, payload_len,
        auth_key,
        envelope + ENVELOPE_HEADER_SIZE + payload_len
    );

    if (result != ENVELOPE_OK) {
        return result;
    }

    return (int)envelope_size(payload_len);
}

int envelope_verify(
    const uint8_t *envelope,
    size_t envelope_len,
    const uint8_t *auth_key,
    uint8_t *share_index,
    uint8_t *threshold,
    const uint8_t **payload,
    size_t *payload_len
) {
    uint8_t expected_tag[ENVELOPE_TAG_SIZE];
    const uint8_t *stored_tag;
    size_t expected_len;
    int result;

    /* Check minimum size */
    if (envelope_len < ENVELOPE_MIN_SIZE) {
        return ENVELOPE_ERR_TOO_SHORT;
    }

    /* Check version */
    if (envelope[0] != ENVELOPE_VERSION) {
        return ENVELOPE_ERR_INVALID_VERSION;
    }

    /* Extract header fields */
    *share_index = envelope[1];
    *threshold = envelope[2];
    *payload_len = keyshare_read_be16(envelope + 3);

    /* Verify length consistency */
    expected_len = envelope_size(*payload_len);
    if (envelope_len != expected_len) {
        return ENVELOPE_ERR_LENGTH_MISMATCH;
    }

    /* Point to payload */
    *payload = envelope + ENVELOPE_HEADER_SIZE;

    /* Compute expected auth tag */
    result = compute_auth_tag(
        envelope, ENVELOPE_HEADER_SIZE,
        *payload, *payload_len,
        auth_key,
        expected_tag
    );

    if (result != ENVELOPE_OK) {
        *share_index = 0;
        *threshold = 0;
        *payload = NULL;
        *payload_len = 0;
        return result;
    }

    /* Constant-time comparison of auth tags */
    stored_tag = envelope + ENVELOPE_HEADER_SIZE + *payload_len;
    if (envelope_ct_compare(expected_tag, stored_tag, ENVELOPE_TAG_SIZE) != 0) {
        /* Clear output on failure */
        *share_index = 0;
        *threshold = 0;
        *payload = NULL;
        *payload_len = 0;
        keyshare_secure_zero(expected_tag, ENVELOPE_TAG_SIZE);
        return ENVELOPE_ERR_MAC_MISMATCH;
    }

    keyshare_secure_zero(expected_tag, ENVELOPE_TAG_SIZE);
    return ENVELOPE_OK;
}
