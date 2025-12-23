/*
 * base64.c - Base64 Encoding/Decoding Implementation
 */

#include "base64.h"
#include <string.h>

static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Decoding table: -1 = invalid, -2 = padding */
static const int8_t BASE64_DECODE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0-15 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 16-31 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,  /* 32-47 */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,  /* 48-63 */
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 64-79 */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,  /* 80-95 */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  /* 96-111 */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,  /* 112-127 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

size_t base64_encode(const uint8_t *input, size_t input_len, char *output) {
    size_t i, j;
    uint32_t triple;

    for (i = 0, j = 0; i < input_len; ) {
        /* Combine up to 3 bytes into a 24-bit number */
        triple = (i < input_len) ? input[i++] << 16 : 0;
        triple |= (i < input_len) ? input[i++] << 8 : 0;
        triple |= (i < input_len) ? input[i++] : 0;

        /* Encode 4 characters */
        output[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
        output[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
        output[j++] = BASE64_CHARS[(triple >> 6) & 0x3F];
        output[j++] = BASE64_CHARS[triple & 0x3F];
    }

    /* Add padding if needed */
    size_t mod = input_len % 3;
    if (mod > 0) {
        /* Rewind and encode last group with padding */
        i = (input_len / 3) * 3;
        j = (input_len / 3) * 4;

        triple = input[i++] << 16;
        if (mod == 2) {
            triple |= input[i] << 8;
        }

        output[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
        output[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
        output[j++] = (mod == 2) ? BASE64_CHARS[(triple >> 6) & 0x3F] : '=';
        output[j++] = '=';
    }

    output[j] = '\0';
    return j;
}

int base64_decode(const char *input, uint8_t *output, size_t *output_len) {
    size_t len = strlen(input);
    size_t i, j;
    int8_t a, b, c, d;
    uint32_t triple;

    if (len == 0) {
        *output_len = 0;
        return 0;
    }

    /* Length must be multiple of 4 */
    if (len % 4 != 0) {
        return -1;
    }

    /* Calculate output length */
    *output_len = (len / 4) * 3;
    if (input[len - 1] == '=') (*output_len)--;
    if (input[len - 2] == '=') (*output_len)--;

    for (i = 0, j = 0; i < len; ) {
        a = BASE64_DECODE[(unsigned char)input[i++]];
        b = BASE64_DECODE[(unsigned char)input[i++]];
        c = BASE64_DECODE[(unsigned char)input[i++]];
        d = BASE64_DECODE[(unsigned char)input[i++]];

        /* Check for invalid characters (but allow padding) */
        if (a == -1 || b == -1) {
            return -1;
        }
        if (c == -1 || d == -1) {
            return -1;
        }

        /* Handle padding */
        if (c == -2) c = 0;
        if (d == -2) d = 0;

        triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                 ((uint32_t)c << 6) | (uint32_t)d;

        if (j < *output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len) output[j++] = triple & 0xFF;
    }

    return 0;
}
