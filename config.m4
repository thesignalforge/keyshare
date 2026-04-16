dnl config.m4 for extension keyshare

PHP_ARG_ENABLE([keyshare],
  [whether to enable keyshare support],
  [AS_HELP_STRING([--enable-keyshare],
    [Enable keyshare support])],
  [no])

if test "$PHP_KEYSHARE" != "no"; then
  AC_DEFINE(HAVE_KEYSHARE, 1, [ Have keyshare support ])

  dnl libsodium provides:
  dnl   - crypto_auth / crypto_auth_verify (HMAC-SHA512/256, 32-byte MAC)
  dnl   - crypto_pwhash (Argon2id) for passphrase-based key derivation
  dnl   - crypto_generichash (BLAKE2b) for domain-separated key/salt derivation
  dnl   - randombytes_buf for CSPRNG seed material
  dnl   - sodium_memzero for hardened secure-erase
  dnl PHP itself ships with sodium (--with-sodium), so the headers and lib
  dnl should be available system-wide on any modern build.
  AC_CHECK_LIB([sodium], [sodium_init], [
    PHP_ADD_LIBRARY([sodium],, KEYSHARE_SHARED_LIBADD)
  ], [
    AC_MSG_ERROR([libsodium is required. Install libsodium-dev (Debian/Ubuntu) or libsodium-devel (RHEL/Fedora).])
  ])

  dnl libgfshare provides GF(256) Shamir's Secret Sharing math.
  dnl We use gfshare_ctx_init_enc / gfshare_ctx_init_dec and drive the
  dnl per-byte random coefficient fill through gfshare_fill_rand, which
  dnl we set to a libsodium-backed randombytes_buf wrapper at MINIT.
  AC_CHECK_LIB([gfshare], [gfshare_ctx_init_enc], [
    PHP_ADD_LIBRARY([gfshare],, KEYSHARE_SHARED_LIBADD)
  ], [
    AC_MSG_ERROR([libgfshare is required. Install libgfshare-dev (Debian/Ubuntu) or libgfshare-devel (RHEL/Fedora).])
  ])

  PHP_SUBST(KEYSHARE_SHARED_LIBADD)

  PHP_NEW_EXTENSION(keyshare,
    src/keyshare.c src/base64.c src/envelope.c,
    $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 -Wall -O2)
  PHP_ADD_BUILD_DIR($ext_builddir/src)
fi
