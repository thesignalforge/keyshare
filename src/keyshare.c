/*
 * keyshare.c - Signalforge KeyShare PHP Extension (v2)
 *
 * Implements Shamir's (k,n) Secret Sharing with authenticated envelopes.
 * Namespace: Signalforge\KeyShare
 *
 * Design
 * ------
 * This is the 2.x series of the extension. The crypto stack is:
 *
 *   Shamir GF(256) math ......... libgfshare (system library)
 *   Randomness (polynomials) .... libsodium randombytes_buf
 *   Envelope MAC ................ libsodium crypto_auth (HMAC-SHA512/256)
 *   Auth key derivation ......... libsodium crypto_generichash (BLAKE2b)
 *   Passphrase KDF .............. libsodium crypto_pwhash (Argon2id)
 *
 * The PHP surface area is unchanged from 1.x: share(), recover(),
 * passphrase(), and the three exception classes. The WIRE format is
 * NOT backward compatible — see MIGRATION.md.
 *
 * Threat model notes
 * ------------------
 * - The polynomial coefficients for Shamir are drawn from libsodium's
 *   CSPRNG, never from the secret itself, preserving Shamir's
 *   information-theoretic security.
 * - The MAC key is derived from the secret (for share()) or from the
 *   Argon2id output (for passphrase()). Supplying shares from two
 *   different secrets therefore fails the MAC check rather than silently
 *   producing garbage through Lagrange interpolation.
 * - All transient buffers containing secret material are zeroed via
 *   sodium_memzero before being freed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"

#include "../php_keyshare.h"
#include "base64.h"
#include "envelope.h"

#include <sodium.h>
#include <libgfshare.h>

#include <string.h>
#include <stdlib.h>

/* Exception classes exposed to PHP. */
static zend_class_entry *keyshare_exception_ce;
static zend_class_entry *keyshare_tampering_exception_ce;
static zend_class_entry *keyshare_insufficient_shares_exception_ce;

/*
 * libgfshare randomness callback.
 *
 * libgfshare exposes a single global function pointer, gfshare_fill_rand,
 * which it calls whenever it needs random bytes for polynomial coefficients.
 * We point it at libsodium's CSPRNG so the coefficients are drawn from the
 * same high-entropy source as the rest of the extension.
 *
 * This function is hot during share() — it is called once per secret byte
 * for (threshold - 1) coefficient bytes — so it must stay cheap. libsodium's
 * randombytes_buf is backed by getrandom()/getentropy()/RtlGenRandom on
 * modern platforms and is suitable here.
 */
static void keyshare_gfshare_rand(unsigned char *buf, unsigned int len) {
	randombytes_buf(buf, (size_t)len);
}

/*
 * Derive a deterministic Argon2id salt from a passphrase.
 *
 * A passphrase-derived share scheme MUST use a salt that can be
 * reconstructed during recovery from the same passphrase — otherwise
 * every call would produce a completely different derived key and
 * recover() could never get back to the original key.
 *
 * We therefore derive the salt as BLAKE2b(passphrase) with a fixed
 * personalization. This is deterministic in the passphrase but still
 * domain-separated from any other use of the passphrase bytes (because
 * a different personalization yields a different hash). It does mean
 * identical passphrases across different machines map to the same salt,
 * which is the price of determinism; the Argon2id cost parameters remain
 * the primary defence against offline brute force.
 */
static int derive_passphrase_salt(
    const char *pass, size_t pass_len,
    uint8_t salt[crypto_pwhash_SALTBYTES]
) {
	uint8_t personal[crypto_generichash_blake2b_PERSONALBYTES];
	memset(personal, 0, sizeof(personal));
	memcpy(personal, KEYSHARE_SALT_PERSONAL,
	       sizeof(KEYSHARE_SALT_PERSONAL) - 1);

	return crypto_generichash_blake2b_salt_personal(
	    salt, crypto_pwhash_SALTBYTES,
	    (const uint8_t *)pass, pass_len,
	    NULL, 0,
	    NULL,
	    personal
	);
}

/*
 * Validate threshold and share count parameters. Shared by share() and
 * passphrase() since both have the same (k,n) constraints.
 */
static int validate_share_params(
    zend_long threshold,
    zend_long num_shares,
    zend_class_entry *exception_ce
) {
	if (threshold < KEYSHARE_MIN_THRESHOLD || threshold > KEYSHARE_MAX_SHARES) {
		zend_throw_exception(exception_ce,
		    "Threshold must be between 2 and 255", 0);
		return 0;
	}

	if (num_shares < threshold || num_shares > KEYSHARE_MAX_SHARES) {
		zend_throw_exception(exception_ce,
		    "Number of shares must be >= threshold and <= 255", 0);
		return 0;
	}

	return 1;
}

/*
 * Encode one share into (envelope -> base64).
 *
 * Returns a heap-allocated C string on success (caller efree()s it), or
 * NULL on any failure. On success *out_len is the base64 string length.
 */
static char *encode_authenticated_share(
    uint8_t index,
    uint8_t threshold,
    const uint8_t *share_bytes,
    size_t share_len,
    const uint8_t *auth_key
) {
	size_t env_size = envelope_size(share_len);
	uint8_t *envelope = emalloc(env_size);

	int rc = envelope_create(index, threshold,
	                         share_bytes, share_len,
	                         auth_key, envelope);
	if (rc < 0) {
		keyshare_secure_zero(envelope, env_size);
		efree(envelope);
		return NULL;
	}

	size_t b64_cap = base64_encode_len(env_size);
	char *encoded = emalloc(b64_cap);
	base64_encode(envelope, env_size, encoded);

	keyshare_secure_zero(envelope, env_size);
	efree(envelope);
	return encoded;
}

/*
 * Split an in-memory buffer of length `secret_len` into `num_shares`
 * shares with threshold `threshold`, using libgfshare.
 *
 * The secret buffer MUST be exactly secret_len bytes; libgfshare will
 * dereference it across the whole length.
 *
 * Output:
 *   *out_shares  - a newly-allocated array of share byte buffers. Each
 *                  buffer is exactly secret_len bytes. Shares are indexed
 *                  [0..num_shares-1] corresponding to share numbers 1..n.
 *
 * The caller is responsible for zeroing and freeing the output buffers.
 *
 * Returns 0 on success, -1 on any failure.
 */
static int split_via_gfshare(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t threshold,
    uint8_t num_shares,
    uint8_t ***out_shares
) {
	unsigned char sharenrs[KEYSHARE_MAX_SHARES];

	/* Share numbers must be 1..num_shares — zero is not a valid x-value
	 * for a Shamir share (that's where the polynomial evaluates to the
	 * secret itself). */
	for (unsigned int i = 0; i < num_shares; i++) {
		sharenrs[i] = (unsigned char)(i + 1);
	}

	/* gfshare_ctx_init_enc copies sharenrs internally. The `size`
	 * parameter is the per-share byte count, which for a classical
	 * byte-wise Shamir scheme is the same as the secret length. */
	gfshare_ctx *ctx = gfshare_ctx_init_enc(
	    sharenrs,
	    (unsigned int)num_shares,
	    threshold,
	    (unsigned int)secret_len
	);
	if (!ctx) {
		*out_shares = NULL;
		return -1;
	}

	/* Feed the secret in. libgfshare makes an internal copy of the
	 * coefficients array and re-randomizes the polynomial on each call
	 * via gfshare_fill_rand (which we set in MINIT to use libsodium). */
	gfshare_ctx_enc_setsecret(ctx, (unsigned char *)secret);

	/* Allocate the output array. */
	uint8_t **shares = emalloc(sizeof(uint8_t *) * num_shares);
	for (unsigned int i = 0; i < num_shares; i++) {
		shares[i] = emalloc(secret_len);
	}

	/* Extract each share. The first argument to getshare is the INDEX
	 * into sharenrs[], NOT the share number. Because we filled sharenrs
	 * with 1..n in order, sharenrs[i] == i+1, so passing `i` here is
	 * the right thing. */
	for (unsigned int i = 0; i < num_shares; i++) {
		gfshare_ctx_enc_getshare(ctx, (unsigned char)i, shares[i]);
	}

	gfshare_ctx_free(ctx);
	*out_shares = shares;
	return 0;
}

/*
 * Reconstruct a secret of length `share_len` from `num_shares` shares.
 *
 * `share_bytes[i]` must be a buffer of exactly share_len bytes, and
 * `indices[i]` must be its share number (1..255). The caller has
 * already verified that indices are unique and share lengths match.
 *
 * Output `secret_out` must be at least share_len bytes.
 *
 * Returns 0 on success, -1 on failure.
 */
static int recover_via_gfshare(
    uint8_t **share_bytes,
    const uint8_t *indices,
    size_t num_shares,
    size_t share_len,
    uint8_t *secret_out
) {
	if (num_shares == 0 || num_shares > KEYSHARE_MAX_SHARES) {
		return -1;
	}

	unsigned char sharenrs[KEYSHARE_MAX_SHARES];
	for (size_t i = 0; i < num_shares; i++) {
		if (indices[i] == 0) {
			return -1;  /* 0 is not a valid share index. */
		}
		sharenrs[i] = indices[i];
	}

	gfshare_ctx *ctx = gfshare_ctx_init_dec(
	    sharenrs,
	    (unsigned int)num_shares,
	    (unsigned int)share_len
	);
	if (!ctx) {
		return -1;
	}

	/* Feed each share in. Same indexing convention as split: the first
	 * arg is the index into sharenrs[], not the share number. */
	for (unsigned int i = 0; i < num_shares; i++) {
		gfshare_ctx_dec_giveshare(ctx, (unsigned char)i, share_bytes[i]);
	}

	gfshare_ctx_dec_extract(ctx, secret_out);
	gfshare_ctx_free(ctx);
	return 0;
}

/*
 * Build the PHP return array for share()/passphrase().
 *
 * Takes ownership of the `shares` array of buffers: every buffer is
 * zeroed and freed, then `shares` itself is freed. Also zeroes the
 * auth_key that the caller passed in (the caller typically already
 * has its own copy too, but double-zeroing is harmless).
 */
static void build_shares_array(
    zval *return_value,
    uint8_t **shares,
    size_t share_len,
    zend_long num_shares,
    uint8_t threshold,
    const uint8_t *auth_key
) {
	array_init(return_value);

	for (zend_long i = 0; i < num_shares; i++) {
		char *encoded = encode_authenticated_share(
		    (uint8_t)(i + 1), threshold,
		    shares[i], share_len,
		    auth_key
		);
		if (encoded) {
			add_index_string(return_value, i + 1, encoded);
			efree(encoded);
		}
		keyshare_secure_zero(shares[i], share_len);
		efree(shares[i]);
	}

	efree(shares);
}

/* Argument info for share() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_share, 0, 3, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, secret, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, shares, IS_LONG, 0)
ZEND_END_ARG_INFO()

/* Argument info for recover() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_recover, 0, 1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, shares, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

/* Argument info for passphrase() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_passphrase, 0, 3, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, passphrase, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, shares, IS_LONG, 0)
ZEND_END_ARG_INFO()

/* {{{ Signalforge\KeyShare\share(string $secret, int $threshold, int $shares): array */
PHP_FUNCTION(share)
{
	char *secret;
	size_t secret_len;
	zend_long threshold, num_shares;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(secret, secret_len)
		Z_PARAM_LONG(threshold)
		Z_PARAM_LONG(num_shares)
	ZEND_PARSE_PARAMETERS_END();

	if (!validate_share_params(threshold, num_shares, keyshare_exception_ce)) {
		RETURN_THROWS();
	}

	if (secret_len == 0) {
		zend_throw_exception(keyshare_exception_ce,
		    "Secret cannot be empty", 0);
		RETURN_THROWS();
	}

	if (secret_len > KEYSHARE_MAX_SECRET_LEN) {
		zend_throw_exception(keyshare_exception_ce,
		    "Secret too long (max 65535 bytes)", 0);
		RETURN_THROWS();
	}

	/* Derive the envelope auth key from the secret. This ties shares to
	 * their secret: recover() re-derives the key from the reconstructed
	 * secret and a mismatch surfaces as a TamperingException. */
	uint8_t auth_key[KEYSHARE_AUTH_KEY_LEN];
	if (envelope_derive_auth_key((const uint8_t *)secret, secret_len, auth_key) != 0) {
		zend_throw_exception(keyshare_exception_ce,
		    "Failed to derive authentication key", 0);
		RETURN_THROWS();
	}

	uint8_t **shares = NULL;
	if (split_via_gfshare((const uint8_t *)secret, secret_len,
	                      (uint8_t)threshold, (uint8_t)num_shares,
	                      &shares) != 0) {
		keyshare_secure_zero(auth_key, sizeof(auth_key));
		zend_throw_exception(keyshare_exception_ce,
		    "Failed to split secret", 0);
		RETURN_THROWS();
	}

	build_shares_array(return_value, shares, secret_len, num_shares,
	                   (uint8_t)threshold, auth_key);

	keyshare_secure_zero(auth_key, sizeof(auth_key));
}
/* }}} */

/* {{{ Signalforge\KeyShare\recover(array $shares): string */
PHP_FUNCTION(recover)
{
	zval *shares_array;
	HashTable *ht;
	zval *val;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_ARRAY(shares_array)
	ZEND_PARSE_PARAMETERS_END();

	ht = Z_ARRVAL_P(shares_array);
	size_t count = zend_hash_num_elements(ht);

	if (count < KEYSHARE_MIN_THRESHOLD) {
		zend_throw_exception(keyshare_exception_ce,
		    "At least 2 shares are required", 0);
		RETURN_THROWS();
	}

	if (count > KEYSHARE_MAX_SHARES) {
		zend_throw_exception(keyshare_exception_ce,
		    "Too many shares (max 255)", 0);
		RETURN_THROWS();
	}

	/*
	 * Recovery proceeds in two passes:
	 *
	 *   Pass 1: Decode envelopes, extract share payloads, validate
	 *           structure (version, length, threshold consistency).
	 *           MAC verification is deferred because we need the
	 *           reconstructed secret to derive the auth key.
	 *
	 *   Pass 2: Reconstruct the secret via Lagrange interpolation,
	 *           derive the auth key, then MAC-verify every input
	 *           envelope. Any failure => TamperingException.
	 */

	/* Working storage. ecalloc() so partial failure paths see NULL
	 * pointers rather than uninitialized garbage. */
	uint8_t *indices        = ecalloc(count, sizeof(uint8_t));
	uint8_t **share_data    = ecalloc(count, sizeof(uint8_t *));
	size_t *share_lens      = ecalloc(count, sizeof(size_t));
	uint8_t **decoded_envs  = ecalloc(count, sizeof(uint8_t *));
	size_t *decoded_env_lens = ecalloc(count, sizeof(size_t));
	uint8_t *secret_buf     = NULL;
	size_t secret_len       = 0;
	uint8_t auth_key[KEYSHARE_AUTH_KEY_LEN];
	sodium_memzero(auth_key, sizeof(auth_key));

	uint8_t first_threshold = 0;
	const char *err_msg     = NULL;
	int err_is_tamper       = 0;
	int err_is_insufficient = 0;
	int err_is_legacy       = 0;

	size_t i = 0;

	ZEND_HASH_FOREACH_VAL(ht, val) {
		if (Z_TYPE_P(val) != IS_STRING) {
			err_msg = "All shares must be strings";
			goto cleanup;
		}

		size_t encoded_len = Z_STRLEN_P(val);
		size_t max_decoded = base64_decode_len(encoded_len);
		uint8_t *decoded   = emalloc(max_decoded);
		size_t decoded_len = 0;

		if (base64_decode(Z_STRVAL_P(val), encoded_len, decoded, &decoded_len) != 0) {
			efree(decoded);
			err_msg = "Invalid base64 in share";
			goto cleanup;
		}

		if (decoded_len < ENVELOPE_MIN_SIZE) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Share envelope too short";
			goto cleanup;
		}

		/* Version gate happens before any other structural check so
		 * legacy v1 shares surface the right error even when the
		 * rest of the buffer is nonsense. */
		if (decoded[0] == ENVELOPE_VERSION_LEGACY) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_is_legacy = 1;
			err_msg = "This share was created by keyshare 1.x using legacy crypto. "
			          "Re-issue shares with keyshare 2.x.";
			goto cleanup;
		}
		if (decoded[0] != ENVELOPE_VERSION) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Invalid envelope version";
			goto cleanup;
		}

		uint8_t idx            = decoded[1];
		uint8_t share_threshold = decoded[2];
		size_t  payload_len    = keyshare_read_be16(decoded + 3);

		if (decoded_len != envelope_size(payload_len)) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Share envelope length mismatch";
			goto cleanup;
		}

		if (idx == 0) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Invalid share index (must be 1-255)";
			goto cleanup;
		}

		if (i == 0) {
			first_threshold = share_threshold;
		} else if (share_threshold != first_threshold) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Shares have mismatched thresholds";
			goto cleanup;
		}

		if (i > 0 && payload_len != share_lens[0]) {
			keyshare_secure_zero(decoded, max_decoded);
			efree(decoded);
			err_msg = "Shares have mismatched lengths";
			goto cleanup;
		}

		/* Duplicate-index detection. libgfshare will return garbage
		 * (or an undefined result) if we hand it two shares with the
		 * same x-coordinate, so reject that up front. */
		for (size_t j = 0; j < i; j++) {
			if (indices[j] == idx) {
				keyshare_secure_zero(decoded, max_decoded);
				efree(decoded);
				err_msg = "Duplicate share indices detected";
				goto cleanup;
			}
		}

		indices[i]     = idx;
		share_lens[i]  = payload_len;

		/* Copy the payload out so the decoded envelope buffer stays
		 * untouched for the MAC pass. */
		share_data[i] = emalloc(payload_len);
		memcpy(share_data[i], decoded + ENVELOPE_HEADER_SIZE, payload_len);

		/* Keep the full decoded envelope for MAC verification. */
		decoded_envs[i]     = decoded;
		decoded_env_lens[i] = decoded_len;

		i++;
	} ZEND_HASH_FOREACH_END();

	if (count < first_threshold) {
		err_is_insufficient = 1;
		err_msg = "Insufficient shares for recovery (need more shares to meet threshold)";
		goto cleanup;
	}

	/* Reconstruct. */
	secret_len = share_lens[0];
	secret_buf = emalloc(secret_len + 1);

	if (recover_via_gfshare(share_data, indices, count, secret_len, secret_buf) != 0) {
		err_msg = "Failed to recover secret";
		goto cleanup;
	}

	/* Derive auth key from the reconstructed secret and verify every
	 * input envelope against it. A failure here means either one share
	 * was tampered with, OR the shares came from different secrets
	 * (different auth keys => MAC won't match). Both cases are
	 * reported as TamperingException. */
	if (envelope_derive_auth_key(secret_buf, secret_len, auth_key) != 0) {
		err_msg = "Failed to derive authentication key";
		goto cleanup;
	}

	for (size_t k = 0; k < count; k++) {
		uint8_t vi, vt;
		const uint8_t *vp;
		size_t vpl;
		int rc = envelope_verify(
		    decoded_envs[k], decoded_env_lens[k],
		    auth_key,
		    &vi, &vt, &vp, &vpl
		);

		if (rc == ENVELOPE_ERR_LEGACY_VERSION) {
			/* Shouldn't reach here — caught in pass 1 — but defend. */
			err_is_legacy = 1;
			err_msg = "This share was created by keyshare 1.x using legacy crypto. "
			          "Re-issue shares with keyshare 2.x.";
			goto cleanup;
		}
		if (rc != ENVELOPE_OK) {
			err_is_tamper = 1;
			err_msg = "Share authentication failed: MAC mismatch (tampered or mixed shares)";
			goto cleanup;
		}
	}

	/* Success. Build the return string (binary-safe, NUL-terminated
	 * for printf-style callers). */
	secret_buf[secret_len] = '\0';
	RETVAL_STRINGL((char *)secret_buf, secret_len);

cleanup:
	if (share_data) {
		for (size_t j = 0; j < count; j++) {
			if (share_data[j]) {
				keyshare_secure_zero(share_data[j], share_lens ? share_lens[j] : 0);
				efree(share_data[j]);
			}
		}
		efree(share_data);
	}

	if (decoded_envs) {
		for (size_t j = 0; j < count; j++) {
			if (decoded_envs[j]) {
				keyshare_secure_zero(decoded_envs[j], decoded_env_lens[j]);
				efree(decoded_envs[j]);
			}
		}
		efree(decoded_envs);
	}

	if (decoded_env_lens) efree(decoded_env_lens);
	if (share_lens)       efree(share_lens);
	if (indices)          efree(indices);

	if (secret_buf) {
		keyshare_secure_zero(secret_buf, secret_len);
		efree(secret_buf);
	}

	keyshare_secure_zero(auth_key, sizeof(auth_key));

	if (err_msg) {
		zend_class_entry *ce;
		if (err_is_tamper) {
			ce = keyshare_tampering_exception_ce;
		} else if (err_is_insufficient) {
			ce = keyshare_insufficient_shares_exception_ce;
		} else if (err_is_legacy) {
			/* Legacy format is a plain Exception — it's not a
			 * tampering event and it's not an insufficient-shares
			 * condition; it's a version mismatch. */
			ce = keyshare_exception_ce;
		} else {
			ce = keyshare_exception_ce;
		}
		zend_throw_exception(ce, err_msg, 0);
		RETURN_THROWS();
	}
}
/* }}} */

/* {{{ Signalforge\KeyShare\passphrase(string $passphrase, int $threshold, int $shares): array */
PHP_FUNCTION(passphrase)
{
	char *pass;
	size_t pass_len;
	zend_long threshold, num_shares;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(pass, pass_len)
		Z_PARAM_LONG(threshold)
		Z_PARAM_LONG(num_shares)
	ZEND_PARSE_PARAMETERS_END();

	if (!validate_share_params(threshold, num_shares, keyshare_exception_ce)) {
		RETURN_THROWS();
	}

	if (pass_len == 0) {
		zend_throw_exception(keyshare_exception_ce,
		    "Passphrase cannot be empty", 0);
		RETURN_THROWS();
	}

	/* Deterministic salt from the passphrase. See derive_passphrase_salt
	 * for the rationale. */
	uint8_t salt[crypto_pwhash_SALTBYTES];
	if (derive_passphrase_salt(pass, pass_len, salt) != 0) {
		zend_throw_exception(keyshare_exception_ce,
		    "Failed to derive passphrase salt", 0);
		RETURN_THROWS();
	}

	/* Argon2id (via libsodium crypto_pwhash) at MODERATE parameters.
	 * MODERATE is ~0.7s and 256MB memory on a typical modern CPU; that
	 * is intentional and is the primary defence against offline brute
	 * force on a stolen share. See MIGRATION.md for tuning guidance. */
	uint8_t derived_key[KEYSHARE_DERIVED_KEY_LEN];
	int pw_rc = crypto_pwhash(
	    derived_key, KEYSHARE_DERIVED_KEY_LEN,
	    pass, pass_len,
	    salt,
	    crypto_pwhash_OPSLIMIT_MODERATE,
	    crypto_pwhash_MEMLIMIT_MODERATE,
	    crypto_pwhash_ALG_ARGON2ID13
	);

	keyshare_secure_zero(salt, sizeof(salt));

	if (pw_rc != 0) {
		/* crypto_pwhash fails if the OS can't honour the memory limit
		 * (e.g. under cgroup pressure). Surface a clear error rather
		 * than silently falling back to a weaker KDF. */
		zend_throw_exception(keyshare_exception_ce,
		    "Argon2id key derivation failed (insufficient memory?)", 0);
		RETURN_THROWS();
	}

	/* The envelope auth key is derived from the Argon2id output, not
	 * from the passphrase itself — that way a future re-key can swap
	 * the KDF without changing the envelope derivation path. */
	uint8_t auth_key[KEYSHARE_AUTH_KEY_LEN];
	if (envelope_derive_auth_key(derived_key, KEYSHARE_DERIVED_KEY_LEN, auth_key) != 0) {
		keyshare_secure_zero(derived_key, sizeof(derived_key));
		zend_throw_exception(keyshare_exception_ce,
		    "Failed to derive authentication key", 0);
		RETURN_THROWS();
	}

	/* Split the derived key via libgfshare. Polynomial randomness still
	 * flows from libsodium via gfshare_fill_rand, so each call produces
	 * fresh shares even though the derived_key is deterministic. */
	uint8_t **shares = NULL;
	int split_rc = split_via_gfshare(
	    derived_key, KEYSHARE_DERIVED_KEY_LEN,
	    (uint8_t)threshold, (uint8_t)num_shares,
	    &shares
	);

	keyshare_secure_zero(derived_key, sizeof(derived_key));

	if (split_rc != 0) {
		keyshare_secure_zero(auth_key, sizeof(auth_key));
		zend_throw_exception(keyshare_exception_ce,
		    "Failed to split derived key", 0);
		RETURN_THROWS();
	}

	build_shares_array(return_value, shares, KEYSHARE_DERIVED_KEY_LEN, num_shares,
	                   (uint8_t)threshold, auth_key);

	keyshare_secure_zero(auth_key, sizeof(auth_key));
}
/* }}} */

/* Function entries */
static const zend_function_entry keyshare_functions[] = {
	ZEND_NS_FE("Signalforge\\KeyShare", share, arginfo_share)
	ZEND_NS_FE("Signalforge\\KeyShare", recover, arginfo_recover)
	ZEND_NS_FE("Signalforge\\KeyShare", passphrase, arginfo_passphrase)
	PHP_FE_END
};

/* Module init */
PHP_MINIT_FUNCTION(keyshare)
{
	/* libsodium MUST be initialised before anything else here —
	 * envelope_derive_auth_key, randombytes_buf, and crypto_pwhash
	 * all require it. sodium_init() is idempotent and returns 1 on
	 * repeated calls; only a negative return is fatal. */
	if (sodium_init() < 0) {
		php_error_docref(NULL, E_ERROR,
		    "keyshare: failed to initialize libsodium");
		return FAILURE;
	}

	/* Compile-time sanity: the envelope tag size matches libsodium's
	 * reported crypto_auth_BYTES. If libsodium ever changes this (it
	 * won't — the default is stable), the envelope format breaks. */
#if crypto_auth_BYTES != KEYSHARE_AUTH_TAG_LEN
#error "libsodium crypto_auth_BYTES no longer matches KEYSHARE_AUTH_TAG_LEN"
#endif
#if crypto_auth_KEYBYTES != KEYSHARE_AUTH_KEY_LEN
#error "libsodium crypto_auth_KEYBYTES no longer matches KEYSHARE_AUTH_KEY_LEN"
#endif

	/* Wire libgfshare's PRNG hook to libsodium. This must be done
	 * before the first gfshare_ctx_enc_setsecret() call — we do it in
	 * MINIT so it's set for the lifetime of the process. The
	 * assignment is to a single global function pointer in libgfshare;
	 * it's safe to set once and read repeatedly from multiple threads
	 * (all readers see the same function pointer after MINIT). */
	gfshare_fill_rand = keyshare_gfshare_rand;

	/* Register exception classes. */
	zend_class_entry ce;
	INIT_NS_CLASS_ENTRY(ce, "Signalforge\\KeyShare", "Exception", NULL);
	keyshare_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);

	zend_class_entry tampering_ce;
	INIT_NS_CLASS_ENTRY(tampering_ce, "Signalforge\\KeyShare", "TamperingException", NULL);
	keyshare_tampering_exception_ce = zend_register_internal_class_ex(&tampering_ce, keyshare_exception_ce);

	zend_class_entry insufficient_ce;
	INIT_NS_CLASS_ENTRY(insufficient_ce, "Signalforge\\KeyShare", "InsufficientSharesException", NULL);
	keyshare_insufficient_shares_exception_ce = zend_register_internal_class_ex(&insufficient_ce, keyshare_exception_ce);

	return SUCCESS;
}

/* Module shutdown */
PHP_MSHUTDOWN_FUNCTION(keyshare)
{
	return SUCCESS;
}

/* Module info */
PHP_MINFO_FUNCTION(keyshare)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "Signalforge KeyShare", "enabled");
	php_info_print_table_row(2, "Version", PHP_KEYSHARE_VERSION);
	php_info_print_table_row(2, "Envelope format", "v2");
	php_info_print_table_row(2, "Shamir math", "libgfshare");
	php_info_print_table_row(2, "Envelope MAC", "libsodium crypto_auth (HMAC-SHA512/256)");
	php_info_print_table_row(2, "Passphrase KDF", "libsodium crypto_pwhash (Argon2id)");
	php_info_print_table_row(2, "CSPRNG", "libsodium randombytes_buf");
	php_info_print_table_end();
}

/* Module entry */
zend_module_entry keyshare_module_entry = {
	STANDARD_MODULE_HEADER,
	PHP_KEYSHARE_EXTNAME,
	keyshare_functions,
	PHP_MINIT(keyshare),
	PHP_MSHUTDOWN(keyshare),
	NULL,  /* RINIT */
	NULL,  /* RSHUTDOWN */
	PHP_MINFO(keyshare),
	PHP_KEYSHARE_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_KEYSHARE
ZEND_GET_MODULE(keyshare)
#endif
