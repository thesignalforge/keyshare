/*
 * envelope.c - Authenticated Share Envelope Implementation
 *
 * Provides integrity protection for shares using HMAC-SHA256.
 */

#include "envelope.h"
#include "kdf.h"
#include <string.h>
#include <stdlib.h>

/* Static context for auth key derivation */
static const uint8_t AUTH_KEY_INFO[] = "signalforge-keyshare-auth-v1";
#define AUTH_KEY_INFO_LEN 28

/*
 * Constant-time memory comparison to prevent timing attacks.
 */
int envelope_ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    /* Return 0 if equal, non-zero if different */
    return result;
}

/*
 * Derive authentication key from secret.
 * Uses HKDF-like expansion: HMAC(secret, info || 0x01)
 */
void envelope_derive_auth_key(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *auth_key
) {
    uint8_t info_with_counter[AUTH_KEY_INFO_LEN + 1];
    memcpy(info_with_counter, AUTH_KEY_INFO, AUTH_KEY_INFO_LEN);
    info_with_counter[AUTH_KEY_INFO_LEN] = 0x01;

    hmac_sha256(secret, secret_len, info_with_counter, AUTH_KEY_INFO_LEN + 1, auth_key);
}

/*
 * Compute authentication tag for envelope header + payload.
 */
static void compute_auth_tag(
    const uint8_t *header,
    size_t header_len,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *tag
) {
    /* We need to HMAC(key, header || payload) */
    /* For efficiency, we'll compute it incrementally using a buffer */
    size_t total_len = header_len + payload_len;
    uint8_t *data = NULL;

    /* For small payloads, use stack; for large, allocate */
    uint8_t stack_buf[256];
    if (total_len <= sizeof(stack_buf)) {
        data = stack_buf;
    } else {
        data = (uint8_t *)malloc(total_len);
        if (!data) {
            memset(tag, 0, ENVELOPE_TAG_SIZE);
            return;
        }
    }

    memcpy(data, header, header_len);
    memcpy(data + header_len, payload, payload_len);

    hmac_sha256(auth_key, 32, data, total_len, tag);

    /* Clear and free if allocated */
    if (data != stack_buf) {
        memset(data, 0, total_len);
        free(data);
    }
}

int envelope_create(
    uint8_t share_index,
    uint8_t threshold,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *envelope
) {
    if (payload_len > 65535) {
        return -1;  /* Payload too large for 16-bit length field */
    }

    /* Build header */
    envelope[0] = ENVELOPE_VERSION;
    envelope[1] = share_index;
    envelope[2] = threshold;
    envelope[3] = (payload_len >> 8) & 0xFF;  /* Big-endian length */
    envelope[4] = payload_len & 0xFF;

    /* Copy payload */
    memcpy(envelope + ENVELOPE_HEADER_SIZE, payload, payload_len);

    /* Compute and append auth tag */
    compute_auth_tag(
        envelope, ENVELOPE_HEADER_SIZE,
        payload, payload_len,
        auth_key,
        envelope + ENVELOPE_HEADER_SIZE + payload_len
    );

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
    *payload_len = ((size_t)envelope[3] << 8) | envelope[4];

    /* Verify length consistency */
    size_t expected_len = envelope_size(*payload_len);
    if (envelope_len != expected_len) {
        return ENVELOPE_ERR_LENGTH_MISMATCH;
    }

    /* Point to payload */
    *payload = envelope + ENVELOPE_HEADER_SIZE;

    /* Compute expected auth tag */
    uint8_t expected_tag[ENVELOPE_TAG_SIZE];
    compute_auth_tag(
        envelope, ENVELOPE_HEADER_SIZE,
        *payload, *payload_len,
        auth_key,
        expected_tag
    );

    /* Constant-time comparison of auth tags */
    const uint8_t *stored_tag = envelope + ENVELOPE_HEADER_SIZE + *payload_len;
    if (envelope_ct_compare(expected_tag, stored_tag, ENVELOPE_TAG_SIZE) != 0) {
        /* Clear output on failure */
        *share_index = 0;
        *threshold = 0;
        *payload = NULL;
        *payload_len = 0;
        memset(expected_tag, 0, ENVELOPE_TAG_SIZE);
        return ENVELOPE_ERR_MAC_MISMATCH;
    }

    memset(expected_tag, 0, ENVELOPE_TAG_SIZE);
    return ENVELOPE_OK;
}
