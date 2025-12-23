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

echo "\n=== Test 3: Determinism ===\n";
$shares2 = passphrase($pass, 3, 5);
echo "Same passphrase produces same shares: " . ($shares === $shares2 ? "YES" : "NO") . "\n";

echo "\n=== Test 4: Different passphrase produces different shares ===\n";
$shares3 = passphrase("different passphrase", 3, 5);
echo "Different passphrase produces different shares: " . ($shares !== $shares3 ? "YES" : "NO") . "\n";

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

=== Test 3: Determinism ===
Same passphrase produces same shares: YES

=== Test 4: Different passphrase produces different shares ===
Different passphrase produces different shares: YES

=== Test 5: Any valid combination works ===
Different combination produces same key: YES

=== Test 6: Tamper detection on passphrase shares ===
OK: Detected tampering

=== Test 7: Error handling ===
OK: Caught exception for empty passphrase
OK: Caught exception for invalid threshold
OK: Caught exception for shares < threshold

PASS
