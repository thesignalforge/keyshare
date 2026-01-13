/*
 * kdf.c - Key Derivation Functions Implementation
 *
 * Implements SHA-256 and PBKDF2-SHA256 from scratch.
 * No external cryptographic library dependencies.
 */

#include "kdf.h"
#include "../php_keyshare.h"
#include <string.h>
#include <stdlib.h>

/* SHA-256 round constants */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 initial hash values */
static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* Rotate right */
static inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/* SHA-256 functions */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define EP1(x)       (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define SIG0(x)      (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

/* Process a single 512-bit block */
static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        T2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    /* Add to state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    uint32_t state[8];
    uint8_t block[SHA256_BLOCK_SIZE];
    size_t total_len = len;
    uint64_t bit_len;
    int i;

    /* Initialize state */
    memcpy(state, H_INIT, sizeof(H_INIT));

    /* Process complete blocks */
    while (len >= SHA256_BLOCK_SIZE) {
        sha256_transform(state, data);
        data += SHA256_BLOCK_SIZE;
        len -= SHA256_BLOCK_SIZE;
    }

    /* Prepare final block(s) with padding */
    memset(block, 0, SHA256_BLOCK_SIZE);
    memcpy(block, data, len);
    block[len] = 0x80;  /* Append bit '1' */

    if (len >= 56) {
        /* Not enough room for length - process this block and add another */
        sha256_transform(state, block);
        memset(block, 0, SHA256_BLOCK_SIZE);
    }

    /* Append original message length in bits (big-endian) */
    bit_len = total_len * 8;
    keyshare_write_be64(block + 56, bit_len);

    sha256_transform(state, block);

    /* Output hash (big-endian) */
    for (i = 0; i < 8; i++) {
        keyshare_write_be32(hash + i * 4, state[i]);
    }
}

int hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *mac
) {
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    uint8_t outer_data[SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE];
    uint8_t *inner_data = NULL;
    uint8_t key_hash[SHA256_DIGEST_SIZE];
    size_t inner_len;
    int i;
    int result = 0;

    /* Check for overflow in inner buffer size calculation */
    inner_len = keyshare_safe_add(SHA256_BLOCK_SIZE, data_len);
    if (inner_len == 0 && data_len != 0) {
        return -1;  /* Overflow */
    }

    /* Allocate buffer for inner hash input */
    inner_data = (uint8_t *)malloc(inner_len);
    if (!inner_data) {
        return -1;
    }

    /* If key is longer than block size, hash it */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = SHA256_DIGEST_SIZE;
    }

    /* Prepare key pad */
    memset(k_pad, 0, SHA256_BLOCK_SIZE);
    memcpy(k_pad, key, key_len);

    /* Inner hash: SHA256((key XOR ipad) || data) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_data[i] = k_pad[i] ^ HMAC_IPAD;
    }
    memcpy(inner_data + SHA256_BLOCK_SIZE, data, data_len);
    sha256(inner_data, inner_len, inner_hash);

    /* Outer hash: SHA256((key XOR opad) || inner_hash) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        outer_data[i] = k_pad[i] ^ HMAC_OPAD;
    }
    memcpy(outer_data + SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_SIZE);
    sha256(outer_data, SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE, mac);

    /* Secure cleanup of sensitive data */
    keyshare_secure_zero(k_pad, sizeof(k_pad));
    keyshare_secure_zero(key_hash, sizeof(key_hash));
    keyshare_secure_zero(inner_hash, sizeof(inner_hash));
    keyshare_secure_zero(inner_data, inner_len);

    free(inner_data);
    return result;
}

int pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *dk, size_t dk_len
) {
    uint8_t U[SHA256_DIGEST_SIZE], T[SHA256_DIGEST_SIZE];
    uint8_t *salt_block = NULL;
    uint32_t block_num = 1;
    size_t dk_offset = 0;
    uint32_t i, j;
    size_t salt_block_len;
    int result = 0;

    /* Check for overflow in salt block size */
    salt_block_len = keyshare_safe_add(salt_len, 4);
    if (salt_block_len == 0 && salt_len != 0) {
        return -1;  /* Overflow */
    }

    /* Allocate salt block buffer */
    salt_block = (uint8_t *)malloc(salt_block_len);
    if (!salt_block) {
        return -1;
    }

    while (dk_offset < dk_len) {
        /* U_1 = PRF(Password, Salt || INT_32_BE(block_num)) */
        memcpy(salt_block, salt, salt_len);
        keyshare_write_be32(salt_block + salt_len, block_num);

        if (hmac_sha256(password, password_len, salt_block, salt_block_len, U) != 0) {
            result = -1;
            goto cleanup;
        }
        memcpy(T, U, SHA256_DIGEST_SIZE);

        /* U_2 ... U_c */
        for (i = 1; i < iterations; i++) {
            if (hmac_sha256(password, password_len, U, SHA256_DIGEST_SIZE, U) != 0) {
                result = -1;
                goto cleanup;
            }
            for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
                T[j] ^= U[j];
            }
        }

        /* Copy to derived key */
        size_t copy_len = (dk_len - dk_offset > SHA256_DIGEST_SIZE)
                          ? SHA256_DIGEST_SIZE
                          : (dk_len - dk_offset);
        memcpy(dk + dk_offset, T, copy_len);
        dk_offset += copy_len;
        block_num++;
    }

cleanup:
    /* Secure cleanup */
    keyshare_secure_zero(U, sizeof(U));
    keyshare_secure_zero(T, sizeof(T));
    keyshare_secure_zero(salt_block, salt_block_len);
    free(salt_block);

    return result;
}

int kdf_expand(
    const uint8_t *seed, size_t seed_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len
) {
    uint8_t T[SHA256_DIGEST_SIZE] = {0};
    uint8_t counter = 1;
    size_t offset = 0;
    uint8_t *hmac_data = NULL;
    size_t hmac_len;
    size_t hmac_buf_size;
    int result = 0;

    /* Check for overflow: 32 + info_len + 1 */
    hmac_buf_size = keyshare_safe_add(SHA256_DIGEST_SIZE, info_len);
    if (hmac_buf_size == 0 && info_len != 0) {
        return -1;  /* Overflow */
    }
    hmac_buf_size = keyshare_safe_add(hmac_buf_size, 1);
    if (hmac_buf_size == 0) {
        return -1;  /* Overflow */
    }

    /* Allocate buffer */
    hmac_data = (uint8_t *)malloc(hmac_buf_size);
    if (!hmac_data) {
        memset(out, 0, out_len);
        return -1;
    }

    while (offset < out_len) {
        /* T(n) = HMAC(seed, T(n-1) || info || counter) */
        hmac_len = 0;
        if (counter > 1) {
            memcpy(hmac_data, T, SHA256_DIGEST_SIZE);
            hmac_len = SHA256_DIGEST_SIZE;
        }
        memcpy(hmac_data + hmac_len, info, info_len);
        hmac_len += info_len;
        hmac_data[hmac_len++] = counter;

        if (hmac_sha256(seed, seed_len, hmac_data, hmac_len, T) != 0) {
            result = -1;
            goto cleanup;
        }

        size_t copy_len = (out_len - offset > SHA256_DIGEST_SIZE)
                          ? SHA256_DIGEST_SIZE
                          : (out_len - offset);
        memcpy(out + offset, T, copy_len);
        offset += copy_len;
        counter++;
    }

cleanup:
    keyshare_secure_zero(T, sizeof(T));
    keyshare_secure_zero(hmac_data, hmac_buf_size);
    free(hmac_data);

    return result;
}
