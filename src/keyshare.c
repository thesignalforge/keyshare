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

/* Exception classes */
static zend_class_entry *keyshare_exception_ce;
static zend_class_entry *keyshare_tampering_exception_ce;
static zend_class_entry *keyshare_insufficient_shares_exception_ce;

/*
 * Recovery context structure.
 *
 * Holds all allocated resources during share recovery, enabling
 * centralized cleanup via a single function call.
 */
typedef struct {
    uint8_t *indices;
    uint8_t **share_data;
    size_t *share_lens;
    char **raw_shares;
    uint8_t *secret;
    size_t count;
    size_t secret_len;
    uint8_t auth_key[KEYSHARE_SHA256_LEN];
} recovery_context;

/*
 * Initialize recovery context.
 */
static void recovery_ctx_init(recovery_context *ctx) {
    memset(ctx, 0, sizeof(recovery_context));
}

/*
 * Free all resources in recovery context.
 *
 * Securely clears sensitive data before freeing.
 */
static void recovery_ctx_free(recovery_context *ctx) {
    if (ctx->share_data) {
        for (size_t i = 0; i < ctx->count; i++) {
            if (ctx->share_data[i]) {
                keyshare_secure_zero(ctx->share_data[i], ctx->share_lens ? ctx->share_lens[i] : 0);
                efree(ctx->share_data[i]);
            }
        }
        efree(ctx->share_data);
    }

    if (ctx->indices) {
        efree(ctx->indices);
    }
    if (ctx->share_lens) {
        efree(ctx->share_lens);
    }
    if (ctx->raw_shares) {
        efree(ctx->raw_shares);
    }
    if (ctx->secret) {
        keyshare_secure_zero(ctx->secret, ctx->secret_len);
        efree(ctx->secret);
    }

    keyshare_secure_zero(ctx->auth_key, sizeof(ctx->auth_key));
}

/*
 * Encode a share with authenticated envelope to base64.
 *
 * Creates a complete authenticated envelope and base64-encodes it
 * for safe transport/storage as a string.
 *
 * Returns allocated string on success, NULL on failure.
 * Caller must efree() the returned string.
 */
static char *encode_authenticated_share(
    uint8_t index,
    uint8_t threshold,
    const uint8_t *share_data,
    size_t data_len,
    const uint8_t *auth_key
) {
    size_t env_size = envelope_size(data_len);
    uint8_t *envelope = emalloc(env_size);
    char *encoded = NULL;

    int result = envelope_create(index, threshold, share_data, data_len, auth_key, envelope);
    if (result < 0) {
        efree(envelope);
        return NULL;
    }

    size_t b64_len = base64_encode_len(env_size);
    encoded = emalloc(b64_len);
    base64_encode(envelope, env_size, encoded);

    keyshare_secure_zero(envelope, env_size);
    efree(envelope);

    return encoded;
}

/*
 * Decode and verify an authenticated share from base64.
 *
 * Performs base64 decoding and envelope verification with MAC check.
 *
 * Returns 0 on success, negative envelope error code on failure.
 * On success, caller must efree() *data.
 */
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
        return ENVELOPE_ERR_INVALID_VERSION;  /* Invalid base64 */
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
        keyshare_secure_zero(decoded, decoded_len);
        efree(decoded);
        return result;
    }

    /* Copy payload to output */
    *data = emalloc(payload_len);
    memcpy(*data, payload, payload_len);
    *data_len = payload_len;

    keyshare_secure_zero(decoded, decoded_len);
    efree(decoded);

    return ENVELOPE_OK;
}

/*
 * Validate threshold and share count parameters.
 *
 * Common validation used by both share() and passphrase().
 * Throws exception and returns 0 on failure, 1 on success.
 */
static int validate_share_params(
    zend_long threshold,
    zend_long num_shares,
    zend_class_entry *exception_ce
) {
    if (threshold < KEYSHARE_MIN_THRESHOLD || threshold > KEYSHARE_MAX_SHARES) {
        zend_throw_exception(exception_ce,
            "Threshold must be between 2 and 255", 0);
        return 0;
    }

    if (num_shares < threshold || num_shares > KEYSHARE_MAX_SHARES) {
        zend_throw_exception(exception_ce,
            "Number of shares must be >= threshold and <= 255", 0);
        return 0;
    }

    return 1;
}

/*
 * Build shares array with authenticated envelopes.
 *
 * Common logic for encoding shares and building return array.
 * Used by both share() and passphrase().
 */
static void build_shares_array(
    zval *return_value,
    uint8_t **shares,
    size_t share_len,
    zend_long num_shares,
    uint8_t threshold,
    const uint8_t *auth_key
) {
    array_init(return_value);

    for (zend_long i = 0; i < num_shares; i++) {
        char *encoded = encode_authenticated_share(
            (uint8_t)(i + 1), threshold,
            shares[i], share_len,
            auth_key
        );
        if (encoded) {
            add_index_string(return_value, i + 1, encoded);
            efree(encoded);
        }
        keyshare_secure_zero(shares[i], share_len);
        efree(shares[i]);
    }

    efree(shares);
}

/*
 * Derive deterministic salt from passphrase.
 *
 * Creates a salt value that is deterministic for the same passphrase,
 * enabling reproducible key derivation.
 */
static void derive_passphrase_salt(
    const char *passphrase,
    size_t passphrase_len,
    uint8_t salt[KEYSHARE_SALT_LEN]
) {
    uint8_t salt_input[KEYSHARE_SALT_CONTEXT_LEN + KEYSHARE_SALT_LEN];
    uint8_t pass_hash[KEYSHARE_SHA256_LEN];

    /* salt_input = context || first 16 bytes of SHA256(passphrase) */
    memcpy(salt_input, KEYSHARE_SALT_CONTEXT, KEYSHARE_SALT_CONTEXT_LEN);
    sha256((const uint8_t *)passphrase, passphrase_len, pass_hash);
    memcpy(salt_input + KEYSHARE_SALT_CONTEXT_LEN, pass_hash, KEYSHARE_SALT_LEN);

    /* salt = first 16 bytes of SHA256(salt_input) */
    sha256(salt_input, sizeof(salt_input), pass_hash);
    memcpy(salt, pass_hash, KEYSHARE_SALT_LEN);

    keyshare_secure_zero(salt_input, sizeof(salt_input));
    keyshare_secure_zero(pass_hash, sizeof(pass_hash));
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
    if (!validate_share_params(threshold, num_shares, keyshare_exception_ce)) {
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
    uint8_t auth_key[KEYSHARE_SHA256_LEN];
    if (envelope_derive_auth_key((const uint8_t *)secret, secret_len, auth_key) != 0) {
        zend_throw_exception(keyshare_exception_ce,
            "Failed to derive authentication key", 0);
        RETURN_THROWS();
    }

    /* Allocate share buffers */
    uint8_t **shares = emalloc(sizeof(uint8_t *) * num_shares);
    for (zend_long i = 0; i < num_shares; i++) {
        shares[i] = emalloc(secret_len);
    }

    /* Generate deterministic seed from secret */
    uint8_t seed[KEYSHARE_SHA256_LEN];
    sha256((const uint8_t *)secret, secret_len, seed);

    /* Split the secret */
    int result = shamir_split(
        (const uint8_t *)secret, secret_len,
        (uint8_t)threshold, (uint8_t)num_shares,
        shares, seed, KEYSHARE_SHA256_LEN
    );

    keyshare_secure_zero(seed, sizeof(seed));

    if (result != SHAMIR_OK) {
        for (zend_long i = 0; i < num_shares; i++) {
            keyshare_secure_zero(shares[i], secret_len);
            efree(shares[i]);
        }
        efree(shares);
        keyshare_secure_zero(auth_key, sizeof(auth_key));
        zend_throw_exception(keyshare_exception_ce,
            "Failed to split secret", 0);
        RETURN_THROWS();
    }

    /* Build return array with authenticated envelopes */
    build_shares_array(return_value, shares, secret_len, num_shares,
                       (uint8_t)threshold, auth_key);

    keyshare_secure_zero(auth_key, sizeof(auth_key));
}
/* }}} */

/* {{{ Signalforge\KeyShare\recover(array $shares): string */
PHP_FUNCTION(recover)
{
    zval *shares_array;
    HashTable *ht;
    zval *val;
    recovery_context ctx;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(shares_array)
    ZEND_PARSE_PARAMETERS_END();

    recovery_ctx_init(&ctx);

    ht = Z_ARRVAL_P(shares_array);
    ctx.count = zend_hash_num_elements(ht);

    if (ctx.count < KEYSHARE_MIN_THRESHOLD) {
        zend_throw_exception(keyshare_exception_ce,
            "At least 2 shares are required", 0);
        RETURN_THROWS();
    }

    if (ctx.count > KEYSHARE_MAX_SHARES) {
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

    /* Allocate temporary storage */
    ctx.indices = emalloc(ctx.count);
    ctx.share_data = emalloc(sizeof(uint8_t *) * ctx.count);
    ctx.share_lens = emalloc(sizeof(size_t) * ctx.count);
    ctx.raw_shares = emalloc(sizeof(char *) * ctx.count);

    /* Initialize share_data pointers to NULL for safe cleanup */
    for (size_t i = 0; i < ctx.count; i++) {
        ctx.share_data[i] = NULL;
    }

    uint8_t first_threshold = 0;
    size_t i = 0;

    /* First pass: extract data from envelopes (verify structure only) */
    ZEND_HASH_FOREACH_VAL(ht, val) {
        if (Z_TYPE_P(val) != IS_STRING) {
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "All shares must be strings", 0);
            RETURN_THROWS();
        }

        /* Store raw share for second pass */
        ctx.raw_shares[i] = Z_STRVAL_P(val);

        /* Decode base64 */
        size_t encoded_len = Z_STRLEN_P(val);
        size_t max_decoded = base64_decode_len(encoded_len);
        uint8_t *decoded = emalloc(max_decoded);
        size_t decoded_len;

        if (base64_decode(Z_STRVAL_P(val), decoded, &decoded_len) != 0) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Invalid base64 in share", 0);
            RETURN_THROWS();
        }

        /* Parse envelope structure (without MAC verification) */
        if (decoded_len < ENVELOPE_MIN_SIZE) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Share envelope too short", 0);
            RETURN_THROWS();
        }

        if (decoded[0] != ENVELOPE_VERSION) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Invalid envelope version", 0);
            RETURN_THROWS();
        }

        ctx.indices[i] = decoded[1];
        uint8_t share_threshold = decoded[2];
        size_t payload_len = keyshare_read_be16(decoded + 3);

        /* Verify length consistency */
        if (decoded_len != envelope_size(payload_len)) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Share envelope length mismatch", 0);
            RETURN_THROWS();
        }

        /* Check threshold consistency */
        if (i == 0) {
            first_threshold = share_threshold;
        } else if (share_threshold != first_threshold) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Shares have mismatched thresholds", 0);
            RETURN_THROWS();
        }

        /* Check share length consistency */
        if (i > 0 && payload_len != ctx.share_lens[0]) {
            efree(decoded);
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_exception_ce,
                "Shares have mismatched lengths", 0);
            RETURN_THROWS();
        }

        /* Copy payload */
        ctx.share_data[i] = emalloc(payload_len);
        memcpy(ctx.share_data[i], decoded + ENVELOPE_HEADER_SIZE, payload_len);
        ctx.share_lens[i] = payload_len;

        efree(decoded);
        i++;
    } ZEND_HASH_FOREACH_END();

    /* Check we have enough shares */
    if (ctx.count < first_threshold) {
        recovery_ctx_free(&ctx);
        zend_throw_exception(keyshare_insufficient_shares_exception_ce,
            "Insufficient shares for recovery (need more shares to meet threshold)", 0);
        RETURN_THROWS();
    }

    /* Recover the secret */
    ctx.secret_len = ctx.share_lens[0];
    ctx.secret = emalloc(ctx.secret_len + 1);

    int result = shamir_recover(
        (const uint8_t **)ctx.share_data,
        ctx.indices,
        ctx.count,
        ctx.secret_len,
        ctx.secret
    );

    if (result != SHAMIR_OK) {
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
        recovery_ctx_free(&ctx);
        zend_throw_exception(keyshare_exception_ce, errmsg, 0);
        RETURN_THROWS();
    }

    /* Derive auth key from recovered secret */
    if (envelope_derive_auth_key(ctx.secret, ctx.secret_len, ctx.auth_key) != 0) {
        recovery_ctx_free(&ctx);
        zend_throw_exception(keyshare_exception_ce,
            "Failed to derive authentication key", 0);
        RETURN_THROWS();
    }

    /* Second pass: verify all share MACs */
    for (size_t j = 0; j < ctx.count; j++) {
        uint8_t verify_index, verify_threshold;
        uint8_t *verify_data;
        size_t verify_len;

        int verify_result = decode_authenticated_share(
            ctx.raw_shares[j],
            ctx.auth_key,
            &verify_index, &verify_threshold,
            &verify_data, &verify_len
        );

        if (verify_result != ENVELOPE_OK) {
            recovery_ctx_free(&ctx);
            zend_throw_exception(keyshare_tampering_exception_ce,
                "Share authentication failed: MAC mismatch (tampered or mixed shares)", 0);
            RETURN_THROWS();
        }

        keyshare_secure_zero(verify_data, verify_len);
        efree(verify_data);
    }

    /* Build return value */
    ctx.secret[ctx.secret_len] = '\0';
    RETVAL_STRINGL((char *)ctx.secret, ctx.secret_len);

    recovery_ctx_free(&ctx);
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
    if (!validate_share_params(threshold, num_shares, keyshare_exception_ce)) {
        RETURN_THROWS();
    }

    if (passphrase_len == 0) {
        zend_throw_exception(keyshare_exception_ce,
            "Passphrase cannot be empty", 0);
        RETURN_THROWS();
    }

    /* Derive deterministic salt from passphrase */
    uint8_t salt[KEYSHARE_SALT_LEN];
    derive_passphrase_salt(passphrase, passphrase_len, salt);

    /* Derive 32-byte secret key using PBKDF2 */
    uint8_t derived_key[KEYSHARE_DERIVED_KEY_LEN];
    if (pbkdf2_sha256(
            (const uint8_t *)passphrase, passphrase_len,
            salt, KEYSHARE_SALT_LEN,
            PBKDF2_DEFAULT_ITERATIONS,
            derived_key, KEYSHARE_DERIVED_KEY_LEN) != 0) {
        keyshare_secure_zero(salt, sizeof(salt));
        zend_throw_exception(keyshare_exception_ce,
            "Key derivation failed", 0);
        RETURN_THROWS();
    }

    keyshare_secure_zero(salt, sizeof(salt));

    /* Derive authentication key from the derived secret */
    uint8_t auth_key[KEYSHARE_SHA256_LEN];
    if (envelope_derive_auth_key(derived_key, KEYSHARE_DERIVED_KEY_LEN, auth_key) != 0) {
        keyshare_secure_zero(derived_key, sizeof(derived_key));
        zend_throw_exception(keyshare_exception_ce,
            "Failed to derive authentication key", 0);
        RETURN_THROWS();
    }

    /* Allocate share buffers */
    uint8_t **shares = emalloc(sizeof(uint8_t *) * num_shares);
    for (zend_long i = 0; i < num_shares; i++) {
        shares[i] = emalloc(KEYSHARE_DERIVED_KEY_LEN);
    }

    /* Split the derived key */
    int result = shamir_split(
        derived_key, KEYSHARE_DERIVED_KEY_LEN,
        (uint8_t)threshold, (uint8_t)num_shares,
        shares, derived_key, KEYSHARE_DERIVED_KEY_LEN
    );

    keyshare_secure_zero(derived_key, sizeof(derived_key));

    if (result != SHAMIR_OK) {
        for (zend_long i = 0; i < num_shares; i++) {
            keyshare_secure_zero(shares[i], KEYSHARE_DERIVED_KEY_LEN);
            efree(shares[i]);
        }
        efree(shares);
        keyshare_secure_zero(auth_key, sizeof(auth_key));
        zend_throw_exception(keyshare_exception_ce,
            "Failed to split derived key", 0);
        RETURN_THROWS();
    }

    /* Build return array with authenticated envelopes */
    build_shares_array(return_value, shares, KEYSHARE_DERIVED_KEY_LEN, num_shares,
                       (uint8_t)threshold, auth_key);

    keyshare_secure_zero(auth_key, sizeof(auth_key));
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

    /* Register exception classes */
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "Signalforge\\KeyShare", "Exception", NULL);
    keyshare_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);

    zend_class_entry tampering_ce;
    INIT_NS_CLASS_ENTRY(tampering_ce, "Signalforge\\KeyShare", "TamperingException", NULL);
    keyshare_tampering_exception_ce = zend_register_internal_class_ex(&tampering_ce, keyshare_exception_ce);

    zend_class_entry insufficient_ce;
    INIT_NS_CLASS_ENTRY(insufficient_ce, "Signalforge\\KeyShare", "InsufficientSharesException", NULL);
    keyshare_insufficient_shares_exception_ce = zend_register_internal_class_ex(&insufficient_ce, keyshare_exception_ce);

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
