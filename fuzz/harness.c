/*
 * libFuzzer harness for the Signalforge keyshare envelope parser.
 *
 * Target: envelope_verify() - the deserialization entry point that
 * parses version, share_index, threshold, payload_len (big-endian
 * u16), payload pointer, and auth tag from a flat byte buffer.
 *
 * Input: raw bytes. The real format is:
 *   [version:1][share_index:1][threshold:1][payload_len:2][payload:N][auth_tag:32]
 *
 * We feed arbitrary bytes. The parser must reject malformed input
 * cleanly - no OOB reads, no UB on truncated buffers.
 *
 * What we want to catch:
 *   - OOB reads when the 16-bit payload_len claims more bytes than
 *     the buffer actually contains
 *   - UB from reading header fields on buffers shorter than the
 *     minimum envelope size (38 bytes)
 *   - Arithmetic overflow in envelope_size() if payload_len is at
 *     the uint16_t maximum (65535)
 *   - Any path where output pointers (payload, share_index, etc.)
 *     are set without proper validation
 *
 * The crypto_auth_verify call is stubbed to always pass, so the
 * fuzzer reaches all parser paths without needing valid MAC keys.
 * This is deliberate: we are testing the byte parser, not the
 * cryptography.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Declarations from envelope_parser_extracted.c */
extern int envelope_verify(
    const uint8_t *envelope,
    size_t envelope_len,
    const uint8_t *auth_key,
    uint8_t *share_index,
    uint8_t *threshold,
    const uint8_t **payload,
    size_t *payload_len
);

extern int envelope_create(
    uint8_t share_index,
    uint8_t threshold,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *auth_key,
    uint8_t *envelope
);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/*
	 * Cap input size. The real max envelope is 5 + 65535 + 32 = 65572
	 * bytes. Allow a bit more so the fuzzer can explore length-mismatch
	 * paths with oversized buffers.
	 */
	if (size > 128 * 1024) {
		return 0;
	}

	/*
	 * Copy input into a separate allocation so ASan can detect OOB
	 * reads past the end of the buffer. If we passed the fuzzer's
	 * buffer directly, adjacent pages might be mapped and OOB reads
	 * could silently succeed.
	 */
	uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
	if (!buf) {
		return 0;
	}
	if (size) {
		memcpy(buf, data, size);
	}

	/* Dummy auth key - content irrelevant since MAC is stubbed. */
	uint8_t auth_key[32];
	memset(auth_key, 0x42, sizeof(auth_key));

	/* Output variables for envelope_verify. */
	uint8_t share_index = 0;
	uint8_t threshold = 0;
	const uint8_t *payload = NULL;
	size_t payload_len = 0;

	int rc = envelope_verify(
	    buf, size,
	    auth_key,
	    &share_index, &threshold,
	    &payload, &payload_len
	);

	/*
	 * If verification succeeded, do a sanity read of the payload to
	 * trigger ASan if the pointer is out-of-bounds. We read each byte
	 * into a volatile sink to prevent the compiler from optimizing
	 * this away.
	 */
	if (rc == 0 && payload != NULL && payload_len > 0) {
		volatile uint8_t sink = 0;
		for (size_t i = 0; i < payload_len; i++) {
			sink ^= payload[i];
		}
		(void)sink;
	}

	free(buf);
	return 0;
}
