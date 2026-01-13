/*
 * php_keyshare.h - Signalforge KeyShare PHP Extension
 *
 * Shamir's Secret Sharing implementation for PHP 8.3+
 * Namespace: Signalforge\KeyShare
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

#define PHP_KEYSHARE_VERSION "1.0.0"
#define PHP_KEYSHARE_EXTNAME "keyshare"

/*
 * Cryptographic Constants
 *
 * These values define the security parameters for the extension.
 * Changes here affect security guarantees - modify with caution.
 */

/* Maximum number of shares (limited by GF(256) field size) */
#define KEYSHARE_MAX_SHARES 255

/* Maximum secret length in bytes */
#define KEYSHARE_MAX_SECRET_LEN 65535

/* Minimum threshold for secret sharing */
#define KEYSHARE_MIN_THRESHOLD 2

/* Derived key length for passphrase-based sharing (256 bits) */
#define KEYSHARE_DERIVED_KEY_LEN 32

/* PBKDF2 salt length */
#define KEYSHARE_SALT_LEN 16

/* Default PBKDF2 iterations (100,000 for security) */
#define KEYSHARE_PBKDF2_ITERATIONS 100000

/* SHA-256 output size */
#define KEYSHARE_SHA256_LEN 32

/* HMAC-SHA256 block size */
#define KEYSHARE_HMAC_BLOCK_SIZE 64

/*
 * Context strings for key derivation.
 * These provide domain separation between different key uses.
 */
#define KEYSHARE_SALT_CONTEXT "signalforge-keyshare-salt-v1"
#define KEYSHARE_SALT_CONTEXT_LEN 28

#define KEYSHARE_AUTH_CONTEXT "signalforge-keyshare-auth-v1"
#define KEYSHARE_AUTH_CONTEXT_LEN 28

/*
 * Secure memory clearing macro.
 *
 * Uses volatile pointer to prevent compiler optimization.
 * This is critical for clearing sensitive data like keys.
 */
static inline void keyshare_secure_zero(void *ptr, size_t len) {
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (len--) {
		*p++ = 0;
	}
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

/*
 * Write a 64-bit big-endian value to a buffer.
 */
static inline void keyshare_write_be64(uint8_t *buf, uint64_t val) {
	buf[0] = (val >> 56) & 0xFF;
	buf[1] = (val >> 48) & 0xFF;
	buf[2] = (val >> 40) & 0xFF;
	buf[3] = (val >> 32) & 0xFF;
	buf[4] = (val >> 24) & 0xFF;
	buf[5] = (val >> 16) & 0xFF;
	buf[6] = (val >> 8) & 0xFF;
	buf[7] = val & 0xFF;
}

/*
 * Write a 32-bit big-endian value to a buffer.
 */
static inline void keyshare_write_be32(uint8_t *buf, uint32_t val) {
	buf[0] = (val >> 24) & 0xFF;
	buf[1] = (val >> 16) & 0xFF;
	buf[2] = (val >> 8) & 0xFF;
	buf[3] = val & 0xFF;
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
