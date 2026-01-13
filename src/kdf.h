/*
 * kdf.h - Key Derivation Functions
 *
 * Implements SHA-256 and PBKDF2-SHA256 without external dependencies.
 */

#ifndef KEYSHARE_KDF_H
#define KEYSHARE_KDF_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 constants */
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

/* PBKDF2 defaults */
#define PBKDF2_DEFAULT_ITERATIONS 100000

/* HMAC constants */
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

/*
 * SHA-256 hash function.
 *
 * Parameters:
 *   data    - Input data to hash
 *   len     - Length of input data
 *   hash    - Output buffer (32 bytes)
 */
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

/*
 * HMAC-SHA256.
 *
 * Parameters:
 *   key      - HMAC key
 *   key_len  - Length of key
 *   data     - Input data
 *   data_len - Length of data
 *   mac      - Output buffer (32 bytes)
 *
 * Returns:
 *   0 on success, -1 on memory allocation failure.
 */
int hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *mac
);

/*
 * PBKDF2-HMAC-SHA256.
 *
 * Parameters:
 *   password     - Input password
 *   password_len - Length of password
 *   salt         - Salt value
 *   salt_len     - Length of salt
 *   iterations   - Number of iterations
 *   dk           - Output derived key buffer
 *   dk_len       - Desired derived key length
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *dk, size_t dk_len
);

/*
 * Generate deterministic "random" bytes from a seed.
 * Uses HKDF-like expansion.
 *
 * Parameters:
 *   seed     - Input seed
 *   seed_len - Length of seed
 *   info     - Context info
 *   info_len - Length of info
 *   out      - Output buffer
 *   out_len  - Desired output length
 *
 * Returns:
 *   0 on success, -1 on memory allocation failure.
 */
int kdf_expand(
    const uint8_t *seed, size_t seed_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len
);

#endif /* KEYSHARE_KDF_H */
