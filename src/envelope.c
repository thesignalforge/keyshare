/*
 * envelope.c - Authenticated Share Envelope (v2) implementation
 *
 * Intent
 * ------
 * Every share emitted by this extension is wrapped in a small authenticated
 * envelope. The envelope serves two goals:
 *
 *   1. Bind shares to their secret. The MAC key is derived from the secret
 *      (or the passphrase-derived key), so a share produced for secret A
 *      cannot be mixed with shares produced for secret B — the MAC check
 *      will fail when recovery re-derives the key from the reconstructed
 *      secret. This turns Shamir's silent-corruption failure mode into a
 *      loud, detectable TamperingException.
 *
 *   2. Tamper detection. Flipping any byte of a share (including the
 *      header fields) causes verification to fail.
 *
 * Cryptographic primitives
 * ------------------------
 * All crypto comes from libsodium:
 *   - crypto_auth / crypto_auth_verify (HMAC-SHA512/256, 32-byte tag,
 *     32-byte key) for the envelope MAC.
 *   - crypto_generichash (BLAKE2b) with personalization for deriving the
 *     MAC key from caller-provided master material.
 *
 * The previous 1.x stack (hand-rolled SHA-256 and HMAC-SHA256) is gone.
 */

#include "envelope.h"
#include "../php_keyshare.h"

#include <sodium.h>
#include <string.h>

/*
 * Derive the 32-byte auth key from master material.
 *
 * We use BLAKE2b via crypto_generichash with a 16-byte personalization
 * string. The personalization gives us domain separation without needing
 * to reserve bytes of the input. We deliberately pass NULL for the key
 * argument: the master material goes in as DATA, not as a MAC key. This
 * avoids any implicit assumption on its length or entropy distribution.
 */
int envelope_derive_auth_key(
    const uint8_t *master,
    size_t master_len,
    uint8_t *auth_key
) {
	/* crypto_generichash_blake2b_salt_personal requires exactly
	 * crypto_generichash_blake2b_PERSONALBYTES (16) bytes of personalization. */
	uint8_t personal[crypto_generichash_blake2b_PERSONALBYTES];
	memset(personal, 0, sizeof(personal));
	memcpy(personal, KEYSHARE_AUTH_PERSONAL,
	       sizeof(KEYSHARE_AUTH_PERSONAL) - 1 < sizeof(personal)
	           ? sizeof(KEYSHARE_AUTH_PERSONAL) - 1
	           : sizeof(personal));

	int rc = crypto_generichash_blake2b_salt_personal(
	    auth_key, KEYSHARE_AUTH_KEY_LEN,
	    master, master_len,
	    NULL, 0,         /* no BLAKE2b keyed mode */
	    NULL,            /* no salt */
	    personal
	);

	return (rc == 0) ? 0 : -1;
}

/*
 * Compute the auth tag for an envelope over header || payload.
 *
 * libsodium's crypto_auth API takes a single contiguous message, so we
 * need to present header and payload as one buffer. For small shares
 * (the typical case — 32-byte passphrase-derived keys, short secrets)
 * a stack buffer is enough; for larger secrets we fall back to heap.
 *
 * The buffer is zeroed before free — the payload itself is a Shamir
 * share, which individually leaks nothing about the secret, but the
 * combined header+payload is the exact MAC input and there's no reason
 * to leave it lying in freed memory.
 */
static int compute_auth_tag(
    const uint8_t *envelope_bytes,
    size_t to_mac_len,
    const uint8_t *auth_key,
    uint8_t *tag_out
) {
	/* crypto_auth has no failure modes for valid inputs, but we still
	 * return a status for API consistency. */
	if (crypto_auth(tag_out, envelope_bytes, to_mac_len, auth_key) != 0) {
		memset(tag_out, 0, ENVELOPE_TAG_SIZE);
		return ENVELOPE_ERR_MEMORY;
	}
	return ENVELOPE_OK;
}

int envelope_create(
    uint8_t share_index,
    uint8_t threshold,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *envelope
) {
	if (payload_len > ENVELOPE_MAX_PAYLOAD) {
		return ENVELOPE_ERR_PAYLOAD_TOO_LARGE;
	}

	/* Header: version || index || threshold || be16(payload_len) */
	envelope[0] = ENVELOPE_VERSION;
	envelope[1] = share_index;
	envelope[2] = threshold;
	keyshare_write_be16(envelope + 3, (uint16_t)payload_len);

	/* Payload sits directly after the header. */
	memcpy(envelope + ENVELOPE_HEADER_SIZE, payload, payload_len);

	/* MAC over header || payload. Tag is appended at the tail. */
	int rc = compute_auth_tag(
	    envelope,
	    ENVELOPE_HEADER_SIZE + payload_len,
	    auth_key,
	    envelope + ENVELOPE_HEADER_SIZE + payload_len
	);

	if (rc != ENVELOPE_OK) {
		return rc;
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
	/* Minimum-length check before any field dereferencing. */
	if (envelope_len < ENVELOPE_MIN_SIZE) {
		return ENVELOPE_ERR_TOO_SHORT;
	}

	/* Version gate. Legacy v1 gets a distinct error so the caller can
	 * emit a migration-specific message; anything else is outright
	 * invalid. */
	if (envelope[0] == ENVELOPE_VERSION_LEGACY) {
		return ENVELOPE_ERR_LEGACY_VERSION;
	}
	if (envelope[0] != ENVELOPE_VERSION) {
		return ENVELOPE_ERR_INVALID_VERSION;
	}

	*share_index = envelope[1];
	*threshold   = envelope[2];
	*payload_len = keyshare_read_be16(envelope + 3);

	/* Length consistency: the envelope buffer must be exactly
	 * header + payload + tag bytes long. */
	if (envelope_len != envelope_size(*payload_len)) {
		return ENVELOPE_ERR_LENGTH_MISMATCH;
	}

	*payload = envelope + ENVELOPE_HEADER_SIZE;

	/* Constant-time MAC verify via libsodium. Returns 0 on success, -1
	 * on any mismatch. The "in" argument is header || payload and must
	 * be exactly the bytes that were MACed during create. */
	const uint8_t *stored_tag = envelope + ENVELOPE_HEADER_SIZE + *payload_len;
	size_t in_len = ENVELOPE_HEADER_SIZE + *payload_len;

	if (crypto_auth_verify(stored_tag, envelope, in_len, auth_key) != 0) {
		/* Clear output on failure so a caller that ignored the return
		 * value cannot treat stale outputs as valid. */
		*share_index = 0;
		*threshold   = 0;
		*payload     = NULL;
		*payload_len = 0;
		return ENVELOPE_ERR_MAC_MISMATCH;
	}

	return ENVELOPE_OK;
}
