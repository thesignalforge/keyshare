/*
 * shamir.c - Shamir's Secret Sharing Implementation
 *
 * Uses SIMD-accelerated GF(256) arithmetic when available.
 * Polynomial coefficients are generated deterministically from a seed.
 */

#include "shamir.h"
#include "gf256_simd.h"
#include "kdf.h"
#include <string.h>
#include <stdlib.h>

/*
 * Deterministic PRNG using SHA-256 in counter mode.
 * Used to generate polynomial coefficients from seed.
 */
typedef struct {
    uint8_t key[32];
    uint64_t counter;
    uint8_t buffer[32];
    size_t buffer_pos;
} prng_state;

static void prng_init(prng_state *state, const uint8_t *seed, size_t seed_len) {
    sha256(seed, seed_len, state->key);
    state->counter = 0;
    state->buffer_pos = 32;
}

static uint8_t prng_next(prng_state *state) {
    if (state->buffer_pos >= 32) {
        uint8_t input[40];
        memcpy(input, state->key, 32);
        input[32] = (state->counter >> 56) & 0xFF;
        input[33] = (state->counter >> 48) & 0xFF;
        input[34] = (state->counter >> 40) & 0xFF;
        input[35] = (state->counter >> 32) & 0xFF;
        input[36] = (state->counter >> 24) & 0xFF;
        input[37] = (state->counter >> 16) & 0xFF;
        input[38] = (state->counter >> 8) & 0xFF;
        input[39] = state->counter & 0xFF;
        sha256(input, 40, state->buffer);
        state->counter++;
        state->buffer_pos = 0;
    }
    return state->buffer[state->buffer_pos++];
}

/* Generate random bytes into buffer */
static void prng_fill(prng_state *state, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = prng_next(state);
    }
}

/*
 * Compute Lagrange basis polynomial l_i(0).
 *
 * l_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
 *        = product_{j!=i} x_j / (x_i ^ x_j)  [in GF(256)]
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
    /* Validate parameters */
    if (threshold < 2) {
        return SHAMIR_ERR_INVALID_THRESHOLD;
    }
    if (num_shares < threshold) {
        return SHAMIR_ERR_INVALID_SHARES;
    }
    if (secret_len == 0 || secret_len > SHAMIR_MAX_SECRET_LEN) {
        return SHAMIR_ERR_INVALID_SHARES;
    }

    prng_state rng;
    prng_init(&rng, rng_seed, seed_len);

    /*
     * For SIMD efficiency, we generate all coefficients upfront and
     * then evaluate the polynomial for each share.
     *
     * Coefficient layout: coeffs[degree][byte_index]
     * coeffs[0] = secret (constant term)
     * coeffs[1..threshold-1] = random coefficients
     */
    uint8_t **coeffs = malloc(sizeof(uint8_t *) * threshold);
    if (!coeffs) {
        return SHAMIR_ERR_MEMORY;
    }

    for (uint8_t c = 0; c < threshold; c++) {
        coeffs[c] = malloc(secret_len);
        if (!coeffs[c]) {
            for (uint8_t j = 0; j < c; j++) {
                memset(coeffs[j], 0, secret_len);
                free(coeffs[j]);
            }
            free(coeffs);
            return SHAMIR_ERR_MEMORY;
        }
    }

    /* Set constant term to secret */
    memcpy(coeffs[0], secret, secret_len);

    /* Generate random coefficients */
    for (uint8_t c = 1; c < threshold; c++) {
        prng_fill(&rng, coeffs[c], secret_len);
    }

    /* Evaluate polynomial at each share index (1..num_shares) */
    for (uint8_t s = 0; s < num_shares; s++) {
        uint8_t x = s + 1;
        gf256_eval_poly_batch(shares[s], (const uint8_t **)coeffs, threshold, secret_len, x);
    }

    /* Clear and free coefficients */
    for (uint8_t c = 0; c < threshold; c++) {
        memset(coeffs[c], 0, secret_len);
        free(coeffs[c]);
    }
    free(coeffs);
    memset(&rng, 0, sizeof(rng));

    return SHAMIR_OK;
}

/*
 * Recover secret from shares using SIMD-accelerated Lagrange interpolation.
 */
int shamir_recover(
    const uint8_t **shares,
    const uint8_t *indices,
    size_t num_shares,
    size_t share_len,
    uint8_t *secret
) {
    if (num_shares < 2) {
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

    /* Lagrange interpolation at x=0:
     * secret = sum_{i=0}^{k-1} share[i] * l_i(0)
     */
    for (size_t i = 0; i < num_shares; i++) {
        uint8_t basis = shamir_lagrange_basis(i, indices, num_shares);
        gf256_addmul_batch(secret, shares[i], basis, share_len);
    }

    return SHAMIR_OK;
}
