/*
 * shamir.h - Shamir's Secret Sharing over GF(256)
 *
 * Implements (k,n) threshold secret sharing using polynomial interpolation.
 * Uses SIMD-accelerated GF(256) operations when available.
 */

#ifndef KEYSHARE_SHAMIR_H
#define KEYSHARE_SHAMIR_H

#include <stdint.h>
#include <stddef.h>

/* Maximum values */
#define SHAMIR_MAX_SHARES 255
#define SHAMIR_MAX_SECRET_LEN 65535

/* Minimum threshold for meaningful secret sharing */
#define SHAMIR_MIN_THRESHOLD 2

/* PRNG buffer size for coefficient generation */
#define SHAMIR_PRNG_BUFFER_SIZE 32

/* Error codes */
#define SHAMIR_OK 0
#define SHAMIR_ERR_INVALID_THRESHOLD -1
#define SHAMIR_ERR_INVALID_SHARES -2
#define SHAMIR_ERR_INSUFFICIENT_SHARES -3
#define SHAMIR_ERR_DUPLICATE_INDEX -4
#define SHAMIR_ERR_INVALID_INDEX -5
#define SHAMIR_ERR_MEMORY -6

/*
 * Split a secret into n shares with threshold k.
 *
 * Parameters:
 *   secret      - Input secret bytes
 *   secret_len  - Length of secret
 *   threshold   - Minimum shares needed to reconstruct (k)
 *   num_shares  - Total number of shares to generate (n)
 *   shares      - Output: array of share buffers (each secret_len bytes)
 *   rng_seed    - Random seed for coefficient generation
 *   seed_len    - Length of seed
 *
 * Returns:
 *   SHAMIR_OK on success, negative error code on failure.
 */
int shamir_split(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t threshold,
    uint8_t num_shares,
    uint8_t **shares,
    const uint8_t *rng_seed,
    size_t seed_len
);

/*
 * Recover a secret from k or more shares using Lagrange interpolation.
 *
 * Parameters:
 *   shares       - Array of share data pointers
 *   indices      - Array of share indices (1..255)
 *   num_shares   - Number of shares provided
 *   share_len    - Length of each share (= secret length)
 *   secret       - Output buffer for reconstructed secret
 *
 * Returns:
 *   SHAMIR_OK on success, negative error code on failure.
 */
int shamir_recover(
    const uint8_t **shares,
    const uint8_t *indices,
    size_t num_shares,
    size_t share_len,
    uint8_t *secret
);

/*
 * Compute Lagrange basis polynomial l_i(0) for reconstruction.
 */
uint8_t shamir_lagrange_basis(uint8_t i, const uint8_t *indices, size_t k);

#endif /* KEYSHARE_SHAMIR_H */
