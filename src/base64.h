/*
 * base64.h - Base64 Encoding/Decoding
 *
 * Simple Base64 implementation for share serialization.
 */

#ifndef KEYSHARE_BASE64_H
#define KEYSHARE_BASE64_H

#include <stdint.h>
#include <stddef.h>

/*
 * Calculate encoded length for given input length.
 */
static inline size_t base64_encode_len(size_t input_len) {
    return ((input_len + 2) / 3) * 4 + 1;  /* +1 for null terminator */
}

/*
 * Calculate maximum decoded length for given encoded string.
 */
static inline size_t base64_decode_len(size_t encoded_len) {
    return (encoded_len / 4) * 3;
}

/*
 * Encode binary data to Base64 string.
 *
 * Parameters:
 *   input     - Input binary data
 *   input_len - Length of input
 *   output    - Output buffer (must be at least base64_encode_len(input_len) bytes)
 *
 * Returns:
 *   Length of encoded string (not including null terminator)
 */
size_t base64_encode(const uint8_t *input, size_t input_len, char *output);

/*
 * Decode Base64 string to binary data.
 *
 * Parameters:
 *   input      - Input Base64 string (null-terminated)
 *   output     - Output buffer
 *   output_len - Pointer to store actual decoded length
 *
 * Returns:
 *   0 on success, -1 on invalid input
 */
int base64_decode(const char *input, uint8_t *output, size_t *output_len);

#endif /* KEYSHARE_BASE64_H */
