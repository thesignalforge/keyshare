--TEST--
Signalforge\KeyShare\share() basic functionality with authenticated envelopes
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;

echo "=== Test 1: Basic share and recover ===\n";
$secret = "Hello, World!";
$shares = share($secret, 3, 5);

// Verify we got 5 shares
echo "Share count: " . count($shares) . "\n";

// Verify share indices are 1-5
echo "Share indices: " . implode(",", array_keys($shares)) . "\n";

// Verify all shares are non-empty strings
$all_valid = true;
foreach ($shares as $s) {
    if (!is_string($s) || strlen($s) === 0) {
        $all_valid = false;
        break;
    }
}
echo "All shares valid: " . ($all_valid ? "YES" : "NO") . "\n";

// Recover with exactly threshold shares (3)
$recovered = recover([
    1 => $shares[1],
    3 => $shares[3],
    5 => $shares[5],
]);
echo "Recovered matches (threshold): " . ($recovered === $secret ? "YES" : "NO") . "\n";

// Recover with more than threshold shares (4)
$recovered2 = recover([
    1 => $shares[1],
    2 => $shares[2],
    3 => $shares[3],
    4 => $shares[4],
]);
echo "Recovered matches (4 shares): " . ($recovered2 === $secret ? "YES" : "NO") . "\n";

// Recover with all shares (5)
$recovered3 = recover($shares);
echo "Recovered matches (all shares): " . ($recovered3 === $secret ? "YES" : "NO") . "\n";

echo "\n=== Test 2: Determinism ===\n";
$shares2 = share($secret, 3, 5);
echo "Same input produces same shares: " . ($shares === $shares2 ? "YES" : "NO") . "\n";

echo "\n=== Test 3: Binary data ===\n";
$binary_secret = "Binary \x00\x01\x02\xFF\xFE data";
$binary_shares = share($binary_secret, 2, 3);
$binary_recovered = recover([
    1 => $binary_shares[1],
    2 => $binary_shares[2],
]);
echo "Binary secret recovered: " . ($binary_recovered === $binary_secret ? "YES" : "NO") . "\n";

echo "\n=== Test 4: Large secret ===\n";
$large_secret = str_repeat("X", 1024);
$large_shares = share($large_secret, 5, 10);
$large_recovered = recover([
    2 => $large_shares[2],
    4 => $large_shares[4],
    6 => $large_shares[6],
    8 => $large_shares[8],
    10 => $large_shares[10],
]);
echo "Large secret recovered: " . ($large_recovered === $large_secret ? "YES" : "NO") . "\n";

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: Basic share and recover ===
Share count: 5
Share indices: 1,2,3,4,5
All shares valid: YES
Recovered matches (threshold): YES
Recovered matches (4 shares): YES
Recovered matches (all shares): YES

=== Test 2: Determinism ===
Same input produces same shares: YES

=== Test 3: Binary data ===
Binary secret recovered: YES

=== Test 4: Large secret ===
Large secret recovered: YES

PASS
