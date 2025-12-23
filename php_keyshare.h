/*
 * php_keyshare.h - Signalforge KeyShare PHP Extension
 *
 * Shamir's Secret Sharing implementation for PHP 8.3+
 * Namespace: Signalforge\KeyShare
 */

#ifndef PHP_KEYSHARE_H
#define PHP_KEYSHARE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"

#define PHP_KEYSHARE_VERSION "1.0.0"
#define PHP_KEYSHARE_EXTNAME "keyshare"

/* Maximum limits */
#define KEYSHARE_MAX_SHARES 255
#define KEYSHARE_MAX_SECRET_LEN 65536
#define KEYSHARE_DERIVED_KEY_LEN 32
#define KEYSHARE_SALT_LEN 16
#define KEYSHARE_PBKDF2_ITERATIONS 100000
#define KEYSHARE_CHECKSUM_LEN 4

extern zend_module_entry keyshare_module_entry;
#define phpext_keyshare_ptr &keyshare_module_entry

PHP_MINIT_FUNCTION(keyshare);
PHP_MSHUTDOWN_FUNCTION(keyshare);
PHP_MINFO_FUNCTION(keyshare);

/* Signalforge\KeyShare\share() */
PHP_FUNCTION(share);

/* Signalforge\KeyShare\recover() */
PHP_FUNCTION(recover);

/* Signalforge\KeyShare\passphrase() */
PHP_FUNCTION(passphrase);

#endif /* PHP_KEYSHARE_H */
