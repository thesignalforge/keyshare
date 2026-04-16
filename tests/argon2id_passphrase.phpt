--TEST--
Signalforge\KeyShare: passphrase() uses Argon2id and is deterministic in the derived key
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\passphrase;
use function Signalforge\KeyShare\recover;

/*
 * We cannot directly observe which KDF was used, but we can verify the
 * EXPECTED BEHAVIOUR of Argon2id-through-deterministic-salt:
 *
 *   - Two runs with the same passphrase produce DIFFERENT share bytes
 *     (because the Shamir polynomial coefficients come from CSPRNG).
 *   - But both share-sets reconstruct to the SAME 32-byte derived key
 *     (because Argon2id is deterministic in (passphrase, salt) and the
 *     salt is deterministic in the passphrase).
 *   - Different passphrases ALWAYS produce different derived keys.
 *
 * These invariants hold under Argon2id in a way that they did not under
 * PBKDF2-with-random-salt — the previous implementation re-used the same
 * deterministic-salt approach on PBKDF2, so this test also passed there.
 * What confirms Argon2id specifically is:
 *
 *   - Run time is noticeably non-trivial (>= ~50ms even in CI) because
 *     Argon2id MODERATE is 3 ops * 256MiB of memory. PBKDF2-100k was
 *     well under 10ms on the same hardware.
 */

echo "=== Test 1: Deterministic derived key across multiple passphrase() calls ===\n";
$pass = "correct horse battery staple";
$a = passphrase($pass, 2, 3);
$b = passphrase($pass, 2, 3);

// Shares themselves must differ (CSPRNG-driven polynomial).
echo "Share sets differ: " . ($a !== $b ? "YES" : "NO") . "\n";

$key_a = recover([1 => $a[1], 2 => $a[2]]);
$key_b = recover([1 => $b[1], 2 => $b[2]]);

echo "Both recover to same key: " . ($key_a === $key_b ? "YES" : "NO") . "\n";
echo "Derived key is 32 bytes: " . (strlen($key_a) === 32 ? "YES" : "NO") . "\n";

echo "\n=== Test 2: Different passphrases => different derived keys ===\n";
$c = passphrase($pass . "!", 2, 3);
$key_c = recover([1 => $c[1], 2 => $c[2]]);
echo "Different passphrase yields different key: " . ($key_a !== $key_c ? "YES" : "NO") . "\n";

echo "\n=== Test 3: Argon2id cost parameters take measurable time ===\n";
/*
 * PBKDF2-100k-SHA256 ran in ~2-5ms on a typical server. Argon2id
 * MODERATE runs in 200-1000ms depending on memory bandwidth. Even
 * under the most aggressive CI schedulers we expect >= 50ms.
 *
 * If this assertion fails it suggests either:
 *   a) Argon2id fell back to a weaker profile (bad), or
 *   b) The crypto_pwhash call is being skipped entirely (very bad).
 */
$t0 = microtime(true);
passphrase("timing check passphrase", 2, 3);
$elapsed_ms = (microtime(true) - $t0) * 1000;

echo "passphrase() call took >= 50 ms: "
    . ($elapsed_ms >= 50 ? "YES" : "NO (only {$elapsed_ms}ms)") . "\n";

echo "\n=== Test 4: Cross-passphrase share mixing fails authentication ===\n";
use Signalforge\KeyShare\TamperingException;
try {
    // Mix shares from passphrase "pass1" and passphrase "pass2". Since
    // auth keys are derived from the Argon2id output (which differs
    // between passphrases), the MAC check must fail.
    recover([
        1 => $a[1],   // from $pass
        2 => $c[2],   // from $pass . "!"
    ]);
    echo "FAIL: mixed-passphrase recovery should have thrown\n";
} catch (TamperingException $e) {
    echo "OK: mixed-passphrase shares rejected\n";
}

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: Deterministic derived key across multiple passphrase() calls ===
Share sets differ: YES
Both recover to same key: YES
Derived key is 32 bytes: YES

=== Test 2: Different passphrases => different derived keys ===
Different passphrase yields different key: YES

=== Test 3: Argon2id cost parameters take measurable time ===
passphrase() call took >= 50 ms: YES

=== Test 4: Cross-passphrase share mixing fails authentication ===
OK: mixed-passphrase shares rejected

PASS
