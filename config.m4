dnl config.m4 for extension keyshare

PHP_ARG_ENABLE([keyshare],
  [whether to enable keyshare support],
  [AS_HELP_STRING([--enable-keyshare],
    [Enable keyshare support])],
  [no])

if test "$PHP_KEYSHARE" != "no"; then
  AC_DEFINE(HAVE_KEYSHARE, 1, [ Have keyshare support ])

  dnl Check for SIMD support and set appropriate flags
  SIMD_FLAGS=""

  dnl Check if we're on x86/x86_64
  case $host_cpu in
    i?86|x86_64)
      dnl Enable SSE2 (standard on x86_64)
      SIMD_FLAGS="-msse2 -mssse3"

      dnl Check for AVX2 support in compiler
      AC_MSG_CHECKING([for AVX2 support])
      old_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -mavx2"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <immintrin.h>
      ]], [[
        __m256i a = _mm256_setzero_si256();
        (void)a;
      ]])], [
        AC_MSG_RESULT([yes])
        SIMD_FLAGS="-msse2 -mssse3 -mavx2"
      ], [
        AC_MSG_RESULT([no])
      ])
      CFLAGS="$old_CFLAGS"
      ;;
  esac

  PHP_NEW_EXTENSION(keyshare,
    src/keyshare.c src/gf256_simd.c src/shamir.c src/kdf.c src/base64.c src/envelope.c,
    $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 -Wall -O2 $SIMD_FLAGS)
  PHP_ADD_BUILD_DIR($ext_builddir/src)
fi
