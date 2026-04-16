/*
 * envelope_parser_extracted.c - Extracted envelope parser for fuzzing
 *
 * This is a faithful extraction of the envelope parsing and validation
 * logic from src/envelope.c and php_keyshare.h. It compiles standalone
 * against libc only (no PHP, no libsodium).
 *
 * What is extracted:
 *   - keyshare_read_be16() / keyshare_write_be16() inline helpers
 *   - envelope_verify() with all bounds checks, version gating, and
 *     length consistency validation
 *   - envelope_create() for generating well-formed envelopes in tests
 *
 * What is stubbed:
 *   - crypto_auth_verify() always returns 0 (MAC passes). We are
 *     fuzzing the PARSER, not the cryptography. The MAC check sits
 *     after all the parsing/bounds logic, so bypassing it lets the
 *     fuzzer reach every code path without needing valid keys.
 *   - crypto_auth() always returns 0 (for envelope_create).
 *
 * The code below is intentionally byte-for-byte equivalent to the
 * production paths. If you change src/envelope.c, update this file
 * to match.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * Constants - mirrored from envelope.h and php_keyshare.h
 * --------------------------------------------------------------- */

#define ENVELOPE_VERSION        2
#define ENVELOPE_VERSION_LEGACY 1
#define ENVELOPE_HEADER_SIZE    5
#define ENVELOPE_TAG_SIZE       32
#define ENVELOPE_MIN_SIZE       (ENVELOPE_HEADER_SIZE + 1 + ENVELOPE_TAG_SIZE)
#define ENVELOPE_MAX_PAYLOAD    65535

#define ENVELOPE_OK                  0
#define ENVELOPE_ERR_INVALID_VERSION -1
#define ENVELOPE_ERR_MAC_MISMATCH    -2
#define ENVELOPE_ERR_TOO_SHORT       -3
#define ENVELOPE_ERR_LENGTH_MISMATCH -4
#define ENVELOPE_ERR_PAYLOAD_TOO_LARGE -5
#define ENVELOPE_ERR_MEMORY          -6
#define ENVELOPE_ERR_LEGACY_VERSION  -7

/* ---------------------------------------------------------------
 * Inline helpers - exact copies from php_keyshare.h
 * --------------------------------------------------------------- */

static inline size_t envelope_size(size_t payload_len)
{
	return ENVELOPE_HEADER_SIZE + payload_len + ENVELOPE_TAG_SIZE;
}

static inline void keyshare_write_be16(uint8_t *buf, uint16_t val)
{
	buf[0] = (val >> 8) & 0xFF;
	buf[1] = val & 0xFF;
}

static inline uint16_t keyshare_read_be16(const uint8_t *buf)
{
	return ((uint16_t)buf[0] << 8) | buf[1];
}

/* ---------------------------------------------------------------
 * Crypto stubs - bypass MAC to reach the parser beneath it
 * --------------------------------------------------------------- */

static int crypto_auth_verify_stub(
    const unsigned char *tag,
    const unsigned char *in,
    unsigned long long inlen,
    const unsigned char *key
) {
	(void)tag; (void)in; (void)inlen; (void)key;
	return 0;  /* always pass */
}

static int crypto_auth_stub(
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen,
    const unsigned char *key
) {
	(void)in; (void)inlen; (void)key;
	memset(out, 0xAA, ENVELOPE_TAG_SIZE);
	return 0;
}

/* ---------------------------------------------------------------
 * compute_auth_tag - extracted from src/envelope.c
 * Uses the stub instead of real crypto_auth.
 * --------------------------------------------------------------- */
static int compute_auth_tag(
    const uint8_t *envelope_bytes,
    size_t to_mac_len,
    const uint8_t *auth_key,
    uint8_t *tag_out
) {
	if (crypto_auth_stub(tag_out, envelope_bytes, to_mac_len, auth_key) != 0) {
		memset(tag_out, 0, ENVELOPE_TAG_SIZE);
		return ENVELOPE_ERR_MEMORY;
	}
	return ENVELOPE_OK;
}

/* ---------------------------------------------------------------
 * envelope_create - extracted from src/envelope.c
 * --------------------------------------------------------------- */
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

/* ---------------------------------------------------------------
 * envelope_verify - extracted from src/envelope.c
 *
 * This is the primary fuzz target. Every bounds check, length
 * read, and version gate is identical to production.
 * --------------------------------------------------------------- */
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

	/* Constant-time MAC verify via stubbed libsodium. */
	const uint8_t *stored_tag = envelope + ENVELOPE_HEADER_SIZE + *payload_len;
	size_t in_len = ENVELOPE_HEADER_SIZE + *payload_len;

	if (crypto_auth_verify_stub(stored_tag, envelope, in_len, auth_key) != 0) {
		*share_index = 0;
		*threshold   = 0;
		*payload     = NULL;
		*payload_len = 0;
		return ENVELOPE_ERR_MAC_MISMATCH;
	}

	return ENVELOPE_OK;
}
