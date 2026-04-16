--TEST--
Signalforge\KeyShare\passphrase() functionality with authenticated envelopes
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\passphrase;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\Exception;

echo "=== Test 1: Basic passphrase sharing ===\n";
$pass = "correct horse battery staple";
$shares = passphrase($pass, 3, 5);

echo "Share count: " . count($shares) . "\n";
echo "Share indices: " . implode(",", array_keys($shares)) . "\n";

// All shares should be non-empty strings
$all_valid = true;
foreach ($shares as $s) {
    if (!is_string($s) || strlen($s) === 0) {
        $all_valid = false;
        break;
    }
}
echo "All shares valid: " . ($all_valid ? "YES" : "NO") . "\n";

echo "\n=== Test 2: Recovery with threshold shares ===\n";
$recovered = recover([
    1 => $shares[1],
    3 => $shares[3],
    5 => $shares[5],
]);
echo "Recovered key length: " . strlen($recovered) . " bytes\n";

echo "\n=== Test 3: Non-determinism (Shamir security property) ===\n";
// Same passphrase MUST produce different shares — the polynomial seed
// comes from a CSPRNG, not from the passphrase. (audit C-K-1)
$shares2 = passphrase($pass, 3, 5);
echo "Two splits produce different shares: " . ($shares !== $shares2 ? "YES" : "NO") . "\n";

// But the underlying key (derived from passphrase) is the same, so both
// share-sets recover to the same key.
$key_a = recover([1 => $shares[1], 2 => $shares[2], 3 => $shares[3]]);
$key_b = recover([1 => $shares2[1], 2 => $shares2[2], 3 => $shares2[3]]);
echo "Both share-sets recover the same derived key: "
    . ($key_a === $key_b ? "YES" : "NO") . "\n";

echo "\n=== Test 4: Different passphrase produces different key ===\n";
$shares3 = passphrase("different passphrase", 3, 5);
$key_c = recover([1 => $shares3[1], 2 => $shares3[2], 3 => $shares3[3]]);
echo "Different passphrase yields different key: " . ($key_a !== $key_c ? "YES" : "NO") . "\n";

echo "\n=== Test 5: Any valid combination works ===\n";
$recovered2 = recover([
    2 => $shares[2],
    4 => $shares[4],
    5 => $shares[5],
]);
echo "Different combination produces same key: " . ($recovered === $recovered2 ? "YES" : "NO") . "\n";

echo "\n=== Test 6: Tamper detection on passphrase shares ===\n";
$tampered = $shares[1];
$decoded = base64_decode($tampered);
$decoded[10] = chr(ord($decoded[10]) ^ 0xFF);  // Corrupt a byte
$tampered = base64_encode($decoded);
try {
    recover([
        1 => $tampered,
        2 => $shares[2],
        3 => $shares[3],
    ]);
    echo "FAIL: Should have detected tampered share\n";
} catch (Exception $e) {
    echo "OK: Detected tampering\n";
}

echo "\n=== Test 7: Error handling ===\n";
try {
    passphrase("", 3, 5);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for empty passphrase\n";
}

try {
    passphrase($pass, 1, 5);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for invalid threshold\n";
}

try {
    passphrase($pass, 5, 3);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for shares < threshold\n";
}

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: Basic passphrase sharing ===
Share count: 5
Share indices: 1,2,3,4,5
All shares valid: YES

=== Test 2: Recovery with threshold shares ===
Recovered key length: 32 bytes

=== Test 3: Non-determinism (Shamir security property) ===
Two splits produce different shares: YES
Both share-sets recover the same derived key: YES

=== Test 4: Different passphrase produces different key ===
Different passphrase yields different key: YES

=== Test 5: Any valid combination works ===
Different combination produces same key: YES

=== Test 6: Tamper detection on passphrase shares ===
OK: Detected tampering

=== Test 7: Error handling ===
OK: Caught exception for empty passphrase
OK: Caught exception for invalid threshold
OK: Caught exception for shares < threshold

PASS
