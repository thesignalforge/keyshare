/*
 * shamir.c - Shamir's Secret Sharing Implementation
 *
 * Uses SIMD-accelerated GF(256) arithmetic when available.
 * Polynomial coefficients are generated deterministically from a seed.
 */

#include "shamir.h"
#include "gf256_simd.h"
#include "kdf.h"
#include "../php_keyshare.h"
#include <string.h>
#include <stdlib.h>

/*
 * Deterministic PRNG using SHA-256 in counter mode.
 *
 * Used to generate polynomial coefficients from seed.
 * This ensures reproducible share generation for the same seed,
 * which is essential for deterministic secret sharing.
 */
typedef struct {
    uint8_t key[SHA256_DIGEST_SIZE];
    uint64_t counter;
    uint8_t buffer[SHAMIR_PRNG_BUFFER_SIZE];
    size_t buffer_pos;
} prng_state;

/*
 * Initialize PRNG state from seed.
 *
 * The seed is hashed to derive the internal key, providing
 * uniform distribution regardless of seed quality.
 */
static void prng_init(prng_state *state, const uint8_t *seed, size_t seed_len) {
    sha256(seed, seed_len, state->key);
    state->counter = 0;
    state->buffer_pos = SHAMIR_PRNG_BUFFER_SIZE;  /* Force refill on first use */
}

/*
 * Generate the next pseudorandom byte.
 *
 * Uses SHA-256(key || counter) to generate blocks of random bytes.
 * Counter is incremented after each block to ensure forward secrecy.
 */
static uint8_t prng_next(prng_state *state) {
    if (state->buffer_pos >= SHAMIR_PRNG_BUFFER_SIZE) {
        uint8_t input[SHA256_DIGEST_SIZE + 8];

        /* Prepare input: key || counter (big-endian) */
        memcpy(input, state->key, SHA256_DIGEST_SIZE);
        keyshare_write_be64(input + SHA256_DIGEST_SIZE, state->counter);

        sha256(input, sizeof(input), state->buffer);
        state->counter++;
        state->buffer_pos = 0;

        /* Clear sensitive input data */
        keyshare_secure_zero(input, sizeof(input));
    }
    return state->buffer[state->buffer_pos++];
}

/*
 * Generate random bytes into buffer.
 */
static void prng_fill(prng_state *state, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = prng_next(state);
    }
}

/*
 * Securely clear PRNG state.
 */
static void prng_clear(prng_state *state) {
    keyshare_secure_zero(state, sizeof(prng_state));
}

/*
 * Compute Lagrange basis polynomial l_i(0).
 *
 * For reconstruction at x=0:
 *   l_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
 *          = product_{j!=i} x_j / (x_i ^ x_j)  [in GF(256)]
 *
 * In GF(256), subtraction is XOR, and 0 - x_j = x_j.
 */
uint8_t shamir_lagrange_basis(uint8_t i, const uint8_t *indices, size_t k) {
    uint8_t xi = indices[i];
    uint8_t num = 1;
    uint8_t den = 1;

    for (size_t j = 0; j < k; j++) {
        if (j == i) continue;
        uint8_t xj = indices[j];
        num = gf256_mul(num, xj);
        den = gf256_mul(den, gf256_sub(xi, xj));
    }

    return gf256_div(num, den);
}

/*
 * Split a secret into shares using SIMD-accelerated operations.
 *
 * For each byte position, we construct a polynomial of degree (threshold-1)
 * where the constant term is the secret byte and other coefficients are random.
 * Each share is the polynomial evaluated at a distinct non-zero point.
 */
int shamir_split(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t threshold,
    uint8_t num_shares,
    uint8_t **shares,
    const uint8_t *rng_seed,
    size_t seed_len
) {
    prng_state rng;
    uint8_t **coeffs = NULL;
    uint8_t c;
    int result = SHAMIR_OK;

    /* Validate parameters */
    if (threshold < SHAMIR_MIN_THRESHOLD) {
        return SHAMIR_ERR_INVALID_THRESHOLD;
    }
    if (num_shares < threshold) {
        return SHAMIR_ERR_INVALID_SHARES;
    }
    if (secret_len == 0 || secret_len > SHAMIR_MAX_SECRET_LEN) {
        return SHAMIR_ERR_INVALID_SHARES;
    }

    prng_init(&rng, rng_seed, seed_len);

    /*
     * For SIMD efficiency, we generate all coefficients upfront and
     * then evaluate the polynomial for each share.
     *
     * Coefficient layout: coeffs[degree][byte_index]
     * coeffs[0] = secret (constant term)
     * coeffs[1..threshold-1] = random coefficients
     */
    coeffs = malloc(sizeof(uint8_t *) * threshold);
    if (!coeffs) {
        prng_clear(&rng);
        return SHAMIR_ERR_MEMORY;
    }

    /* Initialize all pointers to NULL for safe cleanup */
    for (c = 0; c < threshold; c++) {
        coeffs[c] = NULL;
    }

    /* Allocate coefficient buffers */
    for (c = 0; c < threshold; c++) {
        coeffs[c] = malloc(secret_len);
        if (!coeffs[c]) {
            result = SHAMIR_ERR_MEMORY;
            goto cleanup;
        }
    }

    /* Set constant term to secret */
    memcpy(coeffs[0], secret, secret_len);

    /* Generate random coefficients for higher degree terms */
    for (c = 1; c < threshold; c++) {
        prng_fill(&rng, coeffs[c], secret_len);
    }

    /* Evaluate polynomial at each share index (1..num_shares) */
    for (uint8_t s = 0; s < num_shares; s++) {
        uint8_t x = s + 1;
        gf256_eval_poly_batch(shares[s], (const uint8_t **)coeffs, threshold, secret_len, x);
    }

cleanup:
    /* Secure cleanup of all coefficient buffers */
    if (coeffs) {
        for (c = 0; c < threshold; c++) {
            if (coeffs[c]) {
                keyshare_secure_zero(coeffs[c], secret_len);
                free(coeffs[c]);
            }
        }
        free(coeffs);
    }
    prng_clear(&rng);

    return result;
}

/*
 * Recover secret from shares using SIMD-accelerated Lagrange interpolation.
 *
 * Given k shares, the secret is recovered by evaluating the interpolating
 * polynomial at x=0:
 *   secret[b] = sum_{i=0}^{k-1} share[i][b] * l_i(0)
 *
 * where l_i(0) is the Lagrange basis polynomial.
 */
int shamir_recover(
    const uint8_t **shares,
    const uint8_t *indices,
    size_t num_shares,
    size_t share_len,
    uint8_t *secret
) {
    if (num_shares < SHAMIR_MIN_THRESHOLD) {
        return SHAMIR_ERR_INSUFFICIENT_SHARES;
    }

    /* Validate indices are unique and non-zero */
    for (size_t i = 0; i < num_shares; i++) {
        if (indices[i] == 0) {
            return SHAMIR_ERR_INVALID_INDEX;
        }
        for (size_t j = i + 1; j < num_shares; j++) {
            if (indices[i] == indices[j]) {
                return SHAMIR_ERR_DUPLICATE_INDEX;
            }
        }
    }

    /* Initialize secret to zero */
    memset(secret, 0, share_len);

    /*
     * Lagrange interpolation at x=0:
     *   secret = sum_{i=0}^{k-1} share[i] * l_i(0)
     *
     * Using SIMD-accelerated addmul for efficiency.
     */
    for (size_t i = 0; i < num_shares; i++) {
        uint8_t basis = shamir_lagrange_basis(i, indices, num_shares);
        gf256_addmul_batch(secret, shares[i], basis, share_len);
    }

    return SHAMIR_OK;
}
