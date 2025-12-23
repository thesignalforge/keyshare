/*
 * gf256_simd.c - SIMD-Optimized GF(256) Implementation
 *
 * Provides three implementations:
 *   - AVX2: Processes 32 bytes per iteration
 *   - SSE2: Processes 16 bytes per iteration
 *   - Scalar: Fallback for all platforms
 *
 * Uses irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
 */

#include "gf256_simd.h"
#include <string.h>

/* Check for x86 SIMD support */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define GF256_X86 1
    #include <cpuid.h>
    #ifdef __SSE2__
        #include <emmintrin.h>
        #define GF256_HAS_SSE2 1
    #endif
    #ifdef __AVX2__
        #include <immintrin.h>
        #define GF256_HAS_AVX2 1
    #endif
#else
    #define GF256_X86 0
#endif

/* Lookup tables for GF(256) arithmetic */
static uint8_t gf256_exp_table[512];  /* Double size to avoid modulo */
static uint8_t gf256_log_table[256];

/* Multiplication tables for SIMD: mul_lo[a] and mul_hi[a] for each possible scalar */
/* For scalar a: result = mul_lo[a][lo_nibble] ^ mul_hi[a][hi_nibble] */
static uint8_t gf256_mul_lo[256][16];
static uint8_t gf256_mul_hi[256][16];

/* Detected CPU feature level */
static int cpu_level = GF256_CPU_SCALAR;
static int initialized = 0;

/* Detect CPU features at runtime */
static int detect_cpu_features(void) {
#if GF256_X86
    unsigned int eax, ebx, ecx, edx;

    /* Check for basic CPUID support */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        /* SSE2 is in EDX bit 26 */
        if (edx & (1 << 26)) {
            /* Check for AVX2: need to check CPUID leaf 7 */
            if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                /* AVX2 is in EBX bit 5 */
                if (ebx & (1 << 5)) {
                    /* Also verify OS supports AVX (XGETBV) */
                    unsigned int xcr0_lo, xcr0_hi;
                    __asm__ volatile (
                        "xgetbv"
                        : "=a" (xcr0_lo), "=d" (xcr0_hi)
                        : "c" (0)
                    );
                    /* Check XMM and YMM state are enabled */
                    if ((xcr0_lo & 0x6) == 0x6) {
                        return GF256_CPU_AVX2;
                    }
                }
            }
            return GF256_CPU_SSE2;
        }
    }
#endif
    return GF256_CPU_SCALAR;
}

/* Build multiplication lookup tables for SIMD */
static void build_mul_tables(void) {
    for (int a = 0; a < 256; a++) {
        for (int nibble = 0; nibble < 16; nibble++) {
            /* Low nibble: multiply a by nibble */
            gf256_mul_lo[a][nibble] = gf256_mul((uint8_t)a, (uint8_t)nibble);
            /* High nibble: multiply a by (nibble << 4) */
            gf256_mul_hi[a][nibble] = gf256_mul((uint8_t)a, (uint8_t)(nibble << 4));
        }
    }
}

void gf256_simd_init(void) {
    if (initialized) {
        return;
    }

    /* Build exp/log tables first (needed for scalar mul) */
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf256_exp_table[i] = (uint8_t)x;
        gf256_exp_table[i + 255] = (uint8_t)x;
        gf256_log_table[x] = (uint8_t)i;

        /* Multiply by generator (0x03) */
        x = x ^ (x << 1);
        if (x & 0x100) {
            x ^= 0x11B;
        }
    }
    gf256_log_table[0] = 0;
    gf256_exp_table[510] = gf256_exp_table[0];
    gf256_exp_table[511] = gf256_exp_table[1];

    /* Detect CPU and build SIMD tables */
    cpu_level = detect_cpu_features();
    build_mul_tables();

    initialized = 1;
}

int gf256_get_cpu_level(void) {
    return cpu_level;
}

/* Scalar single-byte multiplication */
uint8_t gf256_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) {
        return 0;
    }
    uint16_t sum = gf256_log_table[a] + gf256_log_table[b];
    return gf256_exp_table[sum];
}

/* Scalar division */
uint8_t gf256_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;
    if (a == 0) return 0;
    int16_t diff = (int16_t)gf256_log_table[a] - (int16_t)gf256_log_table[b];
    if (diff < 0) diff += 255;
    return gf256_exp_table[diff];
}

/* Scalar inverse */
uint8_t gf256_inv(uint8_t a) {
    if (a == 0) return 0;
    return gf256_exp_table[255 - gf256_log_table[a]];
}

/*
 * Scalar batch multiplication: dst[i] = src[i] * scalar
 */
static void gf256_mul_scalar_batch_scalar(uint8_t *dst, const uint8_t *src,
                                           uint8_t scalar, size_t len) {
    if (scalar == 0) {
        memset(dst, 0, len);
        return;
    }
    if (scalar == 1) {
        if (dst != src) memcpy(dst, src, len);
        return;
    }

    const uint8_t *lo_tbl = gf256_mul_lo[scalar];
    const uint8_t *hi_tbl = gf256_mul_hi[scalar];

    for (size_t i = 0; i < len; i++) {
        uint8_t v = src[i];
        dst[i] = lo_tbl[v & 0x0F] ^ hi_tbl[v >> 4];
    }
}

/*
 * Scalar batch addmul: dst[i] ^= src[i] * scalar
 */
static void gf256_addmul_batch_scalar(uint8_t *dst, const uint8_t *src,
                                       uint8_t scalar, size_t len) {
    if (scalar == 0) return;

    const uint8_t *lo_tbl = gf256_mul_lo[scalar];
    const uint8_t *hi_tbl = gf256_mul_hi[scalar];

    for (size_t i = 0; i < len; i++) {
        uint8_t v = src[i];
        dst[i] ^= lo_tbl[v & 0x0F] ^ hi_tbl[v >> 4];
    }
}

/*
 * Scalar batch XOR
 */
static void gf256_xor_batch_scalar(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

#ifdef GF256_HAS_SSE2
/*
 * SSE2 batch multiplication using nibble lookup tables.
 * Processes 16 bytes per iteration.
 */
static void gf256_mul_scalar_batch_sse2(uint8_t *dst, const uint8_t *src,
                                         uint8_t scalar, size_t len) {
    if (scalar == 0) {
        memset(dst, 0, len);
        return;
    }
    if (scalar == 1) {
        if (dst != src) memcpy(dst, src, len);
        return;
    }

    /* Load multiplication tables into XMM registers */
    __m128i lo_tbl = _mm_loadu_si128((const __m128i *)gf256_mul_lo[scalar]);
    __m128i hi_tbl = _mm_loadu_si128((const __m128i *)gf256_mul_hi[scalar]);
    __m128i mask_0f = _mm_set1_epi8(0x0F);

    size_t i = 0;

    /* Process 16 bytes at a time */
    for (; i + 16 <= len; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(src + i));

        /* Split into low and high nibbles */
        __m128i lo_nibbles = _mm_and_si128(v, mask_0f);
        __m128i hi_nibbles = _mm_and_si128(_mm_srli_epi16(v, 4), mask_0f);

        /* Table lookup using pshufb */
        __m128i lo_result = _mm_shuffle_epi8(lo_tbl, lo_nibbles);
        __m128i hi_result = _mm_shuffle_epi8(hi_tbl, hi_nibbles);

        /* Combine with XOR */
        __m128i result = _mm_xor_si128(lo_result, hi_result);
        _mm_storeu_si128((__m128i *)(dst + i), result);
    }

    /* Handle remaining bytes with scalar */
    gf256_mul_scalar_batch_scalar(dst + i, src + i, scalar, len - i);
}

static void gf256_addmul_batch_sse2(uint8_t *dst, const uint8_t *src,
                                     uint8_t scalar, size_t len) {
    if (scalar == 0) return;

    __m128i lo_tbl = _mm_loadu_si128((const __m128i *)gf256_mul_lo[scalar]);
    __m128i hi_tbl = _mm_loadu_si128((const __m128i *)gf256_mul_hi[scalar]);
    __m128i mask_0f = _mm_set1_epi8(0x0F);

    size_t i = 0;

    for (; i + 16 <= len; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(src + i));
        __m128i d = _mm_loadu_si128((const __m128i *)(dst + i));

        __m128i lo_nibbles = _mm_and_si128(v, mask_0f);
        __m128i hi_nibbles = _mm_and_si128(_mm_srli_epi16(v, 4), mask_0f);

        __m128i lo_result = _mm_shuffle_epi8(lo_tbl, lo_nibbles);
        __m128i hi_result = _mm_shuffle_epi8(hi_tbl, hi_nibbles);

        __m128i product = _mm_xor_si128(lo_result, hi_result);
        __m128i result = _mm_xor_si128(d, product);
        _mm_storeu_si128((__m128i *)(dst + i), result);
    }

    gf256_addmul_batch_scalar(dst + i, src + i, scalar, len - i);
}

static void gf256_xor_batch_sse2(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0;

    for (; i + 16 <= len; i += 16) {
        __m128i d = _mm_loadu_si128((const __m128i *)(dst + i));
        __m128i s = _mm_loadu_si128((const __m128i *)(src + i));
        _mm_storeu_si128((__m128i *)(dst + i), _mm_xor_si128(d, s));
    }

    gf256_xor_batch_scalar(dst + i, src + i, len - i);
}
#endif /* GF256_HAS_SSE2 */

#ifdef GF256_HAS_AVX2
/*
 * AVX2 batch multiplication.
 * Processes 32 bytes per iteration.
 */
static void gf256_mul_scalar_batch_avx2(uint8_t *dst, const uint8_t *src,
                                         uint8_t scalar, size_t len) {
    if (scalar == 0) {
        memset(dst, 0, len);
        return;
    }
    if (scalar == 1) {
        if (dst != src) memcpy(dst, src, len);
        return;
    }

    /* Broadcast tables to both 128-bit lanes */
    __m128i lo_tbl_128 = _mm_loadu_si128((const __m128i *)gf256_mul_lo[scalar]);
    __m128i hi_tbl_128 = _mm_loadu_si128((const __m128i *)gf256_mul_hi[scalar]);
    __m256i lo_tbl = _mm256_broadcastsi128_si256(lo_tbl_128);
    __m256i hi_tbl = _mm256_broadcastsi128_si256(hi_tbl_128);
    __m256i mask_0f = _mm256_set1_epi8(0x0F);

    size_t i = 0;

    /* Process 32 bytes at a time */
    for (; i + 32 <= len; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));

        __m256i lo_nibbles = _mm256_and_si256(v, mask_0f);
        __m256i hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask_0f);

        __m256i lo_result = _mm256_shuffle_epi8(lo_tbl, lo_nibbles);
        __m256i hi_result = _mm256_shuffle_epi8(hi_tbl, hi_nibbles);

        __m256i result = _mm256_xor_si256(lo_result, hi_result);
        _mm256_storeu_si256((__m256i *)(dst + i), result);
    }

    /* Handle remaining with SSE2 or scalar */
#ifdef GF256_HAS_SSE2
    gf256_mul_scalar_batch_sse2(dst + i, src + i, scalar, len - i);
#else
    gf256_mul_scalar_batch_scalar(dst + i, src + i, scalar, len - i);
#endif
}

static void gf256_addmul_batch_avx2(uint8_t *dst, const uint8_t *src,
                                     uint8_t scalar, size_t len) {
    if (scalar == 0) return;

    __m128i lo_tbl_128 = _mm_loadu_si128((const __m128i *)gf256_mul_lo[scalar]);
    __m128i hi_tbl_128 = _mm_loadu_si128((const __m128i *)gf256_mul_hi[scalar]);
    __m256i lo_tbl = _mm256_broadcastsi128_si256(lo_tbl_128);
    __m256i hi_tbl = _mm256_broadcastsi128_si256(hi_tbl_128);
    __m256i mask_0f = _mm256_set1_epi8(0x0F);

    size_t i = 0;

    for (; i + 32 <= len; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));
        __m256i d = _mm256_loadu_si256((const __m256i *)(dst + i));

        __m256i lo_nibbles = _mm256_and_si256(v, mask_0f);
        __m256i hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask_0f);

        __m256i lo_result = _mm256_shuffle_epi8(lo_tbl, lo_nibbles);
        __m256i hi_result = _mm256_shuffle_epi8(hi_tbl, hi_nibbles);

        __m256i product = _mm256_xor_si256(lo_result, hi_result);
        __m256i result = _mm256_xor_si256(d, product);
        _mm256_storeu_si256((__m256i *)(dst + i), result);
    }

#ifdef GF256_HAS_SSE2
    gf256_addmul_batch_sse2(dst + i, src + i, scalar, len - i);
#else
    gf256_addmul_batch_scalar(dst + i, src + i, scalar, len - i);
#endif
}

static void gf256_xor_batch_avx2(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0;

    for (; i + 32 <= len; i += 32) {
        __m256i d = _mm256_loadu_si256((const __m256i *)(dst + i));
        __m256i s = _mm256_loadu_si256((const __m256i *)(src + i));
        _mm256_storeu_si256((__m256i *)(dst + i), _mm256_xor_si256(d, s));
    }

#ifdef GF256_HAS_SSE2
    gf256_xor_batch_sse2(dst + i, src + i, len - i);
#else
    gf256_xor_batch_scalar(dst + i, src + i, len - i);
#endif
}
#endif /* GF256_HAS_AVX2 */

/*
 * Public dispatch functions - select best available implementation
 */

void gf256_mul_scalar_batch(uint8_t *dst, const uint8_t *src, uint8_t scalar, size_t len) {
#ifdef GF256_HAS_AVX2
    if (cpu_level >= GF256_CPU_AVX2) {
        gf256_mul_scalar_batch_avx2(dst, src, scalar, len);
        return;
    }
#endif
#ifdef GF256_HAS_SSE2
    if (cpu_level >= GF256_CPU_SSE2) {
        gf256_mul_scalar_batch_sse2(dst, src, scalar, len);
        return;
    }
#endif
    gf256_mul_scalar_batch_scalar(dst, src, scalar, len);
}

void gf256_addmul_batch(uint8_t *dst, const uint8_t *src, uint8_t scalar, size_t len) {
#ifdef GF256_HAS_AVX2
    if (cpu_level >= GF256_CPU_AVX2) {
        gf256_addmul_batch_avx2(dst, src, scalar, len);
        return;
    }
#endif
#ifdef GF256_HAS_SSE2
    if (cpu_level >= GF256_CPU_SSE2) {
        gf256_addmul_batch_sse2(dst, src, scalar, len);
        return;
    }
#endif
    gf256_addmul_batch_scalar(dst, src, scalar, len);
}

void gf256_xor_batch(uint8_t *dst, const uint8_t *src, size_t len) {
#ifdef GF256_HAS_AVX2
    if (cpu_level >= GF256_CPU_AVX2) {
        gf256_xor_batch_avx2(dst, src, len);
        return;
    }
#endif
#ifdef GF256_HAS_SSE2
    if (cpu_level >= GF256_CPU_SSE2) {
        gf256_xor_batch_sse2(dst, src, len);
        return;
    }
#endif
    gf256_xor_batch_scalar(dst, src, len);
}

/*
 * Batch polynomial evaluation using Horner's method.
 * Evaluates the polynomial at point x for each byte position simultaneously.
 */
void gf256_eval_poly_batch(
    uint8_t *result,
    const uint8_t **coeffs,
    uint8_t threshold,
    size_t secret_len,
    uint8_t x
) {
    if (threshold == 0 || secret_len == 0) return;

    /* Start with highest degree coefficient */
    memcpy(result, coeffs[threshold - 1], secret_len);

    /* Horner's method: result = result * x + coeffs[i] */
    for (int i = threshold - 2; i >= 0; i--) {
        /* result = result * x */
        gf256_mul_scalar_batch(result, result, x, secret_len);
        /* result = result + coeffs[i] */
        gf256_xor_batch(result, coeffs[i], secret_len);
    }
}
