/*
 * php_keyshare.h - Signalforge KeyShare PHP Extension
 *
 * Shamir's Secret Sharing implementation for PHP 8.3+
 * Namespace: Signalforge\KeyShare
 *
 * This is the 2.x series. The crypto primitives are now sourced from
 * libsodium (HMAC-SHA512/256, Argon2id, BLAKE2b, CSPRNG) and libgfshare
 * (GF(256) secret sharing math). The 1.x series used a hand-rolled stack;
 * 1.x shares are NOT recoverable by 2.x — see MIGRATION.md.
 */

#ifndef PHP_KEYSHARE_H
#define PHP_KEYSHARE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"

#include <sodium.h>

#define PHP_KEYSHARE_VERSION "2.0.0"
#define PHP_KEYSHARE_EXTNAME "keyshare"

/*
 * Cryptographic Constants
 *
 * These values define the security parameters for the extension.
 * Changes here affect security guarantees — modify with caution.
 */

/* Maximum number of shares (limited by GF(256) field size). */
#define KEYSHARE_MAX_SHARES 255

/* Maximum secret length in bytes. */
#define KEYSHARE_MAX_SECRET_LEN 65535

/* Minimum threshold for secret sharing. */
#define KEYSHARE_MIN_THRESHOLD 2

/* Derived key length for passphrase-based sharing (256 bits). */
#define KEYSHARE_DERIVED_KEY_LEN 32

/*
 * Authentication tag size. Equal to libsodium crypto_auth_BYTES (32).
 * We redeclare as a preprocessor symbol so envelope sizing can be used
 * in static-array contexts. Verified against libsodium in MINIT.
 */
#define KEYSHARE_AUTH_TAG_LEN 32

/* Authentication key size. Equal to libsodium crypto_auth_KEYBYTES (32). */
#define KEYSHARE_AUTH_KEY_LEN 32

/*
 * Domain-separation personalizations for BLAKE2b-based derivations.
 *
 * These strings give each key/salt its own namespace so a compromise
 * of one derived value cannot be replayed against another use. We use
 * the BLAKE2b "personal" input rather than prefix-and-hash because the
 * primitive supports it natively and it has no length-extension edges.
 *
 * v2 prefix is deliberate: if a future v3 needs new keys, it must pick
 * a new personalization string to remain incompatible with v2.
 */
#define KEYSHARE_SALT_PERSONAL     "keyshare-v2-salt"      /* 16 bytes */
#define KEYSHARE_AUTH_PERSONAL     "keyshare-v2-authkey"   /* 19 bytes */

/*
 * Secure memory clearing — delegates to libsodium's sodium_memzero().
 *
 * libsodium's implementation is hardened against compiler dead-store
 * elimination (uses platform-specific memory barriers like SecureZeroMemory
 * on Windows, explicit_bzero on BSD/glibc, etc). The previous hand-rolled
 * volatile loop could still be elided by sufficiently aggressive optimizers.
 */
static inline void keyshare_secure_zero(void *ptr, size_t len) {
	sodium_memzero(ptr, len);
}

/*
 * Safe size addition with overflow check.
 * Returns 0 on overflow, otherwise returns a + b.
 */
static inline size_t keyshare_safe_add(size_t a, size_t b) {
	if (a > SIZE_MAX - b) {
		return 0;  /* Overflow */
	}
	return a + b;
}

/*
 * Write a 16-bit big-endian value to a buffer.
 */
static inline void keyshare_write_be16(uint8_t *buf, uint16_t val) {
	buf[0] = (val >> 8) & 0xFF;
	buf[1] = val & 0xFF;
}

/*
 * Read a 16-bit big-endian value from a buffer.
 */
static inline uint16_t keyshare_read_be16(const uint8_t *buf) {
	return ((uint16_t)buf[0] << 8) | buf[1];
}

extern zend_module_entry keyshare_module_entry;
#define phpext_keyshare_ptr &keyshare_module_entry

PHP_MINIT_FUNCTION(keyshare);
PHP_MSHUTDOWN_FUNCTION(keyshare);
PHP_MINFO_FUNCTION(keyshare);

/* Signalforge\KeyShare\share() */
PHP_FUNCTION(share);

/* Signalforge\KeyShare\recover() */
PHP_FUNCTION(recover);

/* Signalforge\KeyShare\passphrase() */
PHP_FUNCTION(passphrase);

#endif /* PHP_KEYSHARE_H */
