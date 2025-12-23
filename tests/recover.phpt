--TEST--
Signalforge\KeyShare\recover() error handling and tamper detection
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\Exception;

$secret = "Test secret message";
$shares = share($secret, 3, 5);

echo "=== Test 1: Insufficient shares ===\n";
try {
    recover([
        1 => $shares[1],
        2 => $shares[2],
    ]);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: " . $e->getMessage() . "\n";
}

echo "\n=== Test 2: Invalid base64 ===\n";
try {
    recover([
        1 => "!!!invalid-base64!!!",
        2 => $shares[2],
        3 => $shares[3],
    ]);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for invalid base64\n";
}

echo "\n=== Test 3: Non-string share ===\n";
try {
    recover([
        1 => $shares[1],
        2 => 12345,
        3 => $shares[3],
    ]);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for non-string share\n";
}

echo "\n=== Test 4: Single bit flip - TAMPER DETECTION ===\n";
$tampered = $shares[1];
// Flip a single bit in the middle of the base64 string
$pos = (int)(strlen($tampered) / 2);
$char = ord($tampered[$pos]);
$flipped = chr($char ^ 0x01);  // Flip lowest bit
$tampered[$pos] = $flipped;

try {
    recover([
        1 => $tampered,
        2 => $shares[2],
        3 => $shares[3],
    ]);
    echo "FAIL: Should have detected tampered share\n";
} catch (Exception $e) {
    echo "OK: Detected tampering: " . $e->getMessage() . "\n";
}

echo "\n=== Test 5: Mixed shares from different secrets ===\n";
// Use same-length secrets to test MAC detection
$secret2 = "Different secretXXX";  // Exactly 19 chars like $secret
$shares2 = share($secret2, 3, 5);
try {
    recover([
        1 => $shares[1],    // From secret 1
        2 => $shares2[2],   // From secret 2
        3 => $shares[3],    // From secret 1
    ]);
    echo "FAIL: Should have detected mixed shares\n";
} catch (Exception $e) {
    echo "OK: Detected mixed shares: " . $e->getMessage() . "\n";
}

echo "\n=== Test 6: Empty array ===\n";
try {
    recover([]);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for empty array\n";
}

echo "\n=== Test 7: Single share ===\n";
try {
    recover([1 => $shares[1]]);
    echo "FAIL: Should have thrown exception\n";
} catch (Exception $e) {
    echo "OK: Caught exception for single share\n";
}

echo "\n=== Test 8: Corrupted envelope header ===\n";
$decoded = base64_decode($shares[1]);
$decoded[0] = chr(0xFF);  // Invalid version
$corrupted = base64_encode($decoded);
try {
    recover([
        1 => $corrupted,
        2 => $shares[2],
        3 => $shares[3],
    ]);
    echo "FAIL: Should have detected corrupted envelope\n";
} catch (Exception $e) {
    echo "OK: Detected corrupted envelope\n";
}

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: Insufficient shares ===
OK: Insufficient shares for recovery (need more shares to meet threshold)

=== Test 2: Invalid base64 ===
OK: Caught exception for invalid base64

=== Test 3: Non-string share ===
OK: Caught exception for non-string share

=== Test 4: Single bit flip - TAMPER DETECTION ===
OK: Detected tampering: Share authentication failed: MAC mismatch (tampered or mixed shares)

=== Test 5: Mixed shares from different secrets ===
OK: Detected mixed shares: Share authentication failed: MAC mismatch (tampered or mixed shares)

=== Test 6: Empty array ===
OK: Caught exception for empty array

=== Test 7: Single share ===
OK: Caught exception for single share

=== Test 8: Corrupted envelope header ===
OK: Detected corrupted envelope

PASS
