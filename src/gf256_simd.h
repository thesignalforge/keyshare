/*
 * gf256_simd.h - SIMD-Optimized GF(256) Galois Field Arithmetic
 *
 * Provides AVX2, SSE2, and scalar implementations with runtime dispatch.
 * All paths produce identical output.
 */

#ifndef KEYSHARE_GF256_SIMD_H
#define KEYSHARE_GF256_SIMD_H

#include <stdint.h>
#include <stddef.h>

/* CPU feature flags */
#define GF256_CPU_SCALAR  0
#define GF256_CPU_SSE2    1
#define GF256_CPU_AVX2    2

/* Initialize GF(256) tables and detect CPU features (call once at MINIT) */
void gf256_simd_init(void);

/* Get detected CPU feature level */
int gf256_get_cpu_level(void);

/* Single-byte operations (always scalar, used for small operations) */
uint8_t gf256_mul(uint8_t a, uint8_t b);
uint8_t gf256_div(uint8_t a, uint8_t b);
uint8_t gf256_inv(uint8_t a);

static inline uint8_t gf256_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

static inline uint8_t gf256_sub(uint8_t a, uint8_t b) {
    return a ^ b;
}

/*
 * SIMD-accelerated bulk operations.
 * Automatically dispatches to best available implementation.
 */

/* dst[i] = src[i] * scalar for all i in [0, len) */
void gf256_mul_scalar_batch(uint8_t *dst, const uint8_t *src, uint8_t scalar, size_t len);

/* dst[i] ^= src[i] * scalar for all i in [0, len) - used in Lagrange interpolation */
void gf256_addmul_batch(uint8_t *dst, const uint8_t *src, uint8_t scalar, size_t len);

/* XOR two buffers: dst[i] ^= src[i] */
void gf256_xor_batch(uint8_t *dst, const uint8_t *src, size_t len);

/*
 * Polynomial evaluation at point x for multiple secrets simultaneously.
 * Evaluates polynomial with coefficients at each byte position.
 *
 * For each byte index b in [0, secret_len):
 *   result[b] = coeffs[0][b] + coeffs[1][b]*x + coeffs[2][b]*x^2 + ...
 *
 * Parameters:
 *   result     - Output buffer (secret_len bytes)
 *   coeffs     - Array of coefficient buffers (threshold pointers, each secret_len bytes)
 *   threshold  - Number of coefficients (polynomial degree + 1)
 *   secret_len - Length of each coefficient buffer
 *   x          - Point at which to evaluate (share index)
 */
void gf256_eval_poly_batch(
    uint8_t *result,
    const uint8_t **coeffs,
    uint8_t threshold,
    size_t secret_len,
    uint8_t x
);

#endif /* KEYSHARE_GF256_SIMD_H */
