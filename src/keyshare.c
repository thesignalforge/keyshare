/*
 * keyshare.c - Signalforge KeyShare PHP Extension
 *
 * Implements Shamir's Secret Sharing with authenticated envelopes for PHP 8.3+
 * Namespace: Signalforge\KeyShare
 *
 * Features:
 *   - SIMD-optimized GF(256) with AVX2/SSE2/scalar fallback
 *   - Authenticated share envelopes with HMAC-SHA256
 *   - Deterministic secret sharing
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"

#include "../php_keyshare.h"
#include "gf256_simd.h"
#include "shamir.h"
#include "kdf.h"
#include "base64.h"
#include "envelope.h"

#include <string.h>
#include <stdlib.h>

/* Exception class */
static zend_class_entry *keyshare_exception_ce;

/* Encode a share with authenticated envelope to base64 */
static char *encode_authenticated_share(
    uint8_t index,
    uint8_t threshold,
    const uint8_t *share_data,
    size_t data_len,
    const uint8_t *auth_key
) {
    size_t env_size = envelope_size(data_len);
    uint8_t *envelope = emalloc(env_size);

    int result = envelope_create(index, threshold, share_data, data_len, auth_key, envelope);
    if (result < 0) {
        efree(envelope);
        return NULL;
    }

    size_t b64_len = base64_encode_len(env_size);
    char *encoded = emalloc(b64_len);
    base64_encode(envelope, env_size, encoded);

    efree(envelope);
    return encoded;
}

/* Decode and verify an authenticated share from base64 */
static int decode_authenticated_share(
    const char *encoded,
    const uint8_t *auth_key,
    uint8_t *index,
    uint8_t *threshold,
    uint8_t **data,
    size_t *data_len
) {
    size_t encoded_len = strlen(encoded);
    size_t max_decoded = base64_decode_len(encoded_len);
    uint8_t *decoded = emalloc(max_decoded);
    size_t decoded_len;

    if (base64_decode(encoded, decoded, &decoded_len) != 0) {
        efree(decoded);
        return -1;  /* Invalid base64 */
    }

    const uint8_t *payload;
    size_t payload_len;

    int result = envelope_verify(
        decoded, decoded_len,
        auth_key,
        index, threshold,
        &payload, &payload_len
    );

    if (result != ENVELOPE_OK) {
        efree(decoded);
        return result;
    }

    /* Copy payload to output */
    *data = emalloc(payload_len);
    memcpy(*data, payload, payload_len);
    *data_len = payload_len;

    efree(decoded);
    return 0;
}

/* Argument info for share() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_share, 0, 3, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, secret, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, shares, IS_LONG, 0)
ZEND_END_ARG_INFO()

/* Argument info for recover() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_recover, 0, 1, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, shares, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

/* Argument info for passphrase() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_passphrase, 0, 3, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, passphrase, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, shares, IS_LONG, 0)
ZEND_END_ARG_INFO()

/* {{{ Signalforge\KeyShare\share(string $secret, int $threshold, int $shares): array */
PHP_FUNCTION(share)
{
    char *secret;
    size_t secret_len;
    zend_long threshold, num_shares;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(secret, secret_len)
        Z_PARAM_LONG(threshold)
        Z_PARAM_LONG(num_shares)
    ZEND_PARSE_PARAMETERS_END();

    /* Validate parameters */
    if (threshold < 2 || threshold > 255) {
        zend_throw_exception(keyshare_exception_ce,
            "Threshold must be between 2 and 255", 0);
        RETURN_THROWS();
    }

    if (num_shares < threshold || num_shares > 255) {
        zend_throw_exception(keyshare_exception_ce,
            "Number of shares must be >= threshold and <= 255", 0);
        RETURN_THROWS();
    }

    if (secret_len == 0) {
        zend_throw_exception(keyshare_exception_ce,
            "Secret cannot be empty", 0);
        RETURN_THROWS();
    }

    if (secret_len > SHAMIR_MAX_SECRET_LEN) {
        zend_throw_exception(keyshare_exception_ce,
            "Secret too long (max 65535 bytes)", 0);
        RETURN_THROWS();
    }

    /* Derive authentication key from secret */
    uint8_t auth_key[32];
    envelope_derive_auth_key((const uint8_t *)secret, secret_len, auth_key);

    /* Allocate share buffers */
    uint8_t **shares = emalloc(sizeof(uint8_t *) * num_shares);
    for (zend_long i = 0; i < num_shares; i++) {
        shares[i] = emalloc(secret_len);
    }

    /* Generate deterministic seed from secret */
    uint8_t seed[32];
    sha256((const uint8_t *)secret, secret_len, seed);

    /* Split the secret */
    int result = shamir_split(
        (const uint8_t *)secret, secret_len,
        (uint8_t)threshold, (uint8_t)num_shares,
        shares, seed, 32
    );

    if (result != SHAMIR_OK) {
        for (zend_long i = 0; i < num_shares; i++) {
            efree(shares[i]);
        }
        efree(shares);
        memset(auth_key, 0, 32);
        zend_throw_exception(keyshare_exception_ce,
            "Failed to split secret", 0);
        RETURN_THROWS();
    }

    /* Build return array with authenticated envelopes */
    array_init(return_value);

    for (zend_long i = 0; i < num_shares; i++) {
        char *encoded = encode_authenticated_share(
            (uint8_t)(i + 1), (uint8_t)threshold,
            shares[i], secret_len,
            auth_key
        );
        if (encoded) {
            add_index_string(return_value, i + 1, encoded);
            efree(encoded);
        }
        memset(shares[i], 0, secret_len);
        efree(shares[i]);
    }

    efree(shares);
    memset(auth_key, 0, 32);
    memset(seed, 0, 32);
}
/* }}} */

/* {{{ Signalforge\KeyShare\recover(array $shares): string */
PHP_FUNCTION(recover)
{
    zval *shares_array;
    HashTable *ht;
    zval *val;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(shares_array)
    ZEND_PARSE_PARAMETERS_END();

    ht = Z_ARRVAL_P(shares_array);
    size_t count = zend_hash_num_elements(ht);

    if (count < 2) {
        zend_throw_exception(keyshare_exception_ce,
            "At least 2 shares are required", 0);
        RETURN_THROWS();
    }

    if (count > 255) {
        zend_throw_exception(keyshare_exception_ce,
            "Too many shares (max 255)", 0);
        RETURN_THROWS();
    }

    /*
     * Two-pass recovery:
     * 1. First pass: decode shares without MAC verification to get the secret
     * 2. Recover secret using Lagrange interpolation
     * 3. Derive auth key from recovered secret
     * 4. Second pass: verify all share MACs
     */

    /* Temporary storage for first pass */
    uint8_t *indices = emalloc(count);
    uint8_t **share_data = emalloc(sizeof(uint8_t *) * count);
    size_t *share_lens = emalloc(sizeof(size_t) * count);
    char **raw_shares = emalloc(sizeof(char *) * count);  /* Store raw base64 for second pass */
    uint8_t first_threshold = 0;
    size_t i = 0;

    /* First pass: extract data from envelopes (verify structure only) */
    ZEND_HASH_FOREACH_VAL(ht, val) {
        if (Z_TYPE_P(val) != IS_STRING) {
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "All shares must be strings", 0);
            RETURN_THROWS();
        }

        /* Store raw share for second pass */
        raw_shares[i] = Z_STRVAL_P(val);

        /* Decode base64 */
        size_t encoded_len = Z_STRLEN_P(val);
        size_t max_decoded = base64_decode_len(encoded_len);
        uint8_t *decoded = emalloc(max_decoded);
        size_t decoded_len;

        if (base64_decode(Z_STRVAL_P(val), decoded, &decoded_len) != 0) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Invalid base64 in share", 0);
            RETURN_THROWS();
        }

        /* Parse envelope structure (without MAC verification) */
        if (decoded_len < ENVELOPE_MIN_SIZE) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Share envelope too short", 0);
            RETURN_THROWS();
        }

        if (decoded[0] != ENVELOPE_VERSION) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Invalid envelope version", 0);
            RETURN_THROWS();
        }

        indices[i] = decoded[1];
        uint8_t share_threshold = decoded[2];
        size_t payload_len = ((size_t)decoded[3] << 8) | decoded[4];

        /* Verify length consistency */
        if (decoded_len != envelope_size(payload_len)) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Share envelope length mismatch", 0);
            RETURN_THROWS();
        }

        /* Check threshold consistency */
        if (i == 0) {
            first_threshold = share_threshold;
        } else if (share_threshold != first_threshold) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Shares have mismatched thresholds", 0);
            RETURN_THROWS();
        }

        /* Check share length consistency */
        if (i > 0 && payload_len != share_lens[0]) {
            efree(decoded);
            for (size_t j = 0; j < i; j++) {
                efree(share_data[j]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            zend_throw_exception(keyshare_exception_ce,
                "Shares have mismatched lengths", 0);
            RETURN_THROWS();
        }

        /* Copy payload */
        share_data[i] = emalloc(payload_len);
        memcpy(share_data[i], decoded + ENVELOPE_HEADER_SIZE, payload_len);
        share_lens[i] = payload_len;

        efree(decoded);
        i++;
    } ZEND_HASH_FOREACH_END();

    /* Check we have enough shares */
    if (count < first_threshold) {
        for (size_t j = 0; j < count; j++) {
            efree(share_data[j]);
        }
        efree(indices);
        efree(share_data);
        efree(share_lens);
        efree(raw_shares);
        zend_throw_exception(keyshare_exception_ce,
            "Insufficient shares for recovery (need more shares to meet threshold)", 0);
        RETURN_THROWS();
    }

    /* Recover the secret */
    size_t secret_len = share_lens[0];
    uint8_t *secret = emalloc(secret_len + 1);

    int result = shamir_recover(
        (const uint8_t **)share_data,
        indices,
        count,
        secret_len,
        secret
    );

    if (result != SHAMIR_OK) {
        for (size_t j = 0; j < count; j++) {
            efree(share_data[j]);
        }
        efree(indices);
        efree(share_data);
        efree(share_lens);
        efree(raw_shares);
        efree(secret);

        const char *errmsg;
        switch (result) {
            case SHAMIR_ERR_DUPLICATE_INDEX:
                errmsg = "Duplicate share indices detected";
                break;
            case SHAMIR_ERR_INVALID_INDEX:
                errmsg = "Invalid share index (must be 1-255)";
                break;
            default:
                errmsg = "Failed to recover secret";
        }
        zend_throw_exception(keyshare_exception_ce, errmsg, 0);
        RETURN_THROWS();
    }

    /* Derive auth key from recovered secret */
    uint8_t auth_key[32];
    envelope_derive_auth_key(secret, secret_len, auth_key);

    /* Second pass: verify all share MACs */
    for (size_t j = 0; j < count; j++) {
        uint8_t verify_index, verify_threshold;
        uint8_t *verify_data;
        size_t verify_len;

        int verify_result = decode_authenticated_share(
            raw_shares[j],
            auth_key,
            &verify_index, &verify_threshold,
            &verify_data, &verify_len
        );

        if (verify_result != 0) {
            /* MAC verification failed - shares are tampered or from different secrets */
            for (size_t k = 0; k < count; k++) {
                efree(share_data[k]);
            }
            efree(indices);
            efree(share_data);
            efree(share_lens);
            efree(raw_shares);
            memset(secret, 0, secret_len);
            efree(secret);
            memset(auth_key, 0, 32);

            zend_throw_exception(keyshare_exception_ce,
                "Share authentication failed: MAC mismatch (tampered or mixed shares)", 0);
            RETURN_THROWS();
        }

        efree(verify_data);
    }

    /* Cleanup */
    for (size_t j = 0; j < count; j++) {
        efree(share_data[j]);
    }
    efree(indices);
    efree(share_data);
    efree(share_lens);
    efree(raw_shares);
    memset(auth_key, 0, 32);

    secret[secret_len] = '\0';
    RETVAL_STRINGL((char *)secret, secret_len);
    memset(secret, 0, secret_len);
    efree(secret);
}
/* }}} */

/* {{{ Signalforge\KeyShare\passphrase(string $passphrase, int $threshold, int $shares): array */
PHP_FUNCTION(passphrase)
{
    char *passphrase;
    size_t passphrase_len;
    zend_long threshold, num_shares;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(passphrase, passphrase_len)
        Z_PARAM_LONG(threshold)
        Z_PARAM_LONG(num_shares)
    ZEND_PARSE_PARAMETERS_END();

    /* Validate parameters */
    if (threshold < 2 || threshold > 255) {
        zend_throw_exception(keyshare_exception_ce,
            "Threshold must be between 2 and 255", 0);
        RETURN_THROWS();
    }

    if (num_shares < threshold || num_shares > 255) {
        zend_throw_exception(keyshare_exception_ce,
            "Number of shares must be >= threshold and <= 255", 0);
        RETURN_THROWS();
    }

    if (passphrase_len == 0) {
        zend_throw_exception(keyshare_exception_ce,
            "Passphrase cannot be empty", 0);
        RETURN_THROWS();
    }

    /* Derive key from passphrase using PBKDF2-SHA256 */
    /* Use a deterministic salt derived from the passphrase */
    uint8_t salt[16];
    uint8_t salt_input[64];
    memset(salt_input, 0, sizeof(salt_input));
    memcpy(salt_input, "signalforge-keyshare-salt-v1", 28);

    uint8_t pass_hash[32];
    sha256((const uint8_t *)passphrase, passphrase_len, pass_hash);
    memcpy(salt_input + 28, pass_hash, 16);
    sha256(salt_input, 44, pass_hash);
    memcpy(salt, pass_hash, 16);

    /* Derive 32-byte secret key */
    uint8_t derived_key[32];
    if (pbkdf2_sha256(
            (const uint8_t *)passphrase, passphrase_len,
            salt, 16,
            PBKDF2_DEFAULT_ITERATIONS,
            derived_key, 32) != 0) {
        zend_throw_exception(keyshare_exception_ce,
            "Key derivation failed", 0);
        RETURN_THROWS();
    }

    /* Derive authentication key from the derived secret */
    uint8_t auth_key[32];
    envelope_derive_auth_key(derived_key, 32, auth_key);

    /* Allocate share buffers */
    uint8_t **shares = emalloc(sizeof(uint8_t *) * num_shares);
    for (zend_long i = 0; i < num_shares; i++) {
        shares[i] = emalloc(32);
    }

    /* Split the derived key */
    int result = shamir_split(
        derived_key, 32,
        (uint8_t)threshold, (uint8_t)num_shares,
        shares, derived_key, 32
    );

    if (result != SHAMIR_OK) {
        for (zend_long i = 0; i < num_shares; i++) {
            efree(shares[i]);
        }
        efree(shares);
        memset(derived_key, 0, 32);
        memset(auth_key, 0, 32);
        zend_throw_exception(keyshare_exception_ce,
            "Failed to split derived key", 0);
        RETURN_THROWS();
    }

    /* Build return array with authenticated envelopes */
    array_init(return_value);

    for (zend_long i = 0; i < num_shares; i++) {
        char *encoded = encode_authenticated_share(
            (uint8_t)(i + 1), (uint8_t)threshold,
            shares[i], 32,
            auth_key
        );
        if (encoded) {
            add_index_string(return_value, i + 1, encoded);
            efree(encoded);
        }
        memset(shares[i], 0, 32);
        efree(shares[i]);
    }

    efree(shares);
    memset(derived_key, 0, 32);
    memset(auth_key, 0, 32);
}
/* }}} */

/* Function entries */
static const zend_function_entry keyshare_functions[] = {
    ZEND_NS_FE("Signalforge\\KeyShare", share, arginfo_share)
    ZEND_NS_FE("Signalforge\\KeyShare", recover, arginfo_recover)
    ZEND_NS_FE("Signalforge\\KeyShare", passphrase, arginfo_passphrase)
    PHP_FE_END
};

/* Module init */
PHP_MINIT_FUNCTION(keyshare)
{
    /* Initialize SIMD-optimized GF(256) */
    gf256_simd_init();

    /* Register exception class */
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\KeyShare", "Exception", NULL);
    keyshare_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);

    return SUCCESS;
}

/* Module shutdown */
PHP_MSHUTDOWN_FUNCTION(keyshare)
{
    return SUCCESS;
}

/* Module info */
PHP_MINFO_FUNCTION(keyshare)
{
    const char *simd_level;
    switch (gf256_get_cpu_level()) {
        case GF256_CPU_AVX2:
            simd_level = "AVX2";
            break;
        case GF256_CPU_SSE2:
            simd_level = "SSE2";
            break;
        default:
            simd_level = "Scalar";
    }

    php_info_print_table_start();
    php_info_print_table_header(2, "Signalforge KeyShare", "enabled");
    php_info_print_table_row(2, "Version", PHP_KEYSHARE_VERSION);
    php_info_print_table_row(2, "Shamir's Secret Sharing", "GF(256) SIMD-optimized");
    php_info_print_table_row(2, "SIMD Level", simd_level);
    php_info_print_table_row(2, "Envelope Authentication", "HMAC-SHA256");
    php_info_print_table_row(2, "KDF", "PBKDF2-SHA256");
    php_info_print_table_end();
}

/* Module entry */
zend_module_entry keyshare_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_KEYSHARE_EXTNAME,
    keyshare_functions,
    PHP_MINIT(keyshare),
    PHP_MSHUTDOWN(keyshare),
    NULL,  /* RINIT */
    NULL,  /* RSHUTDOWN */
    PHP_MINFO(keyshare),
    PHP_KEYSHARE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_KEYSHARE
ZEND_GET_MODULE(keyshare)
#endif
