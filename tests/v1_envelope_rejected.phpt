--TEST--
Signalforge\KeyShare: v1 (legacy 1.x) envelopes are rejected with a clear migration message
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\Exception;

/*
 * Craft a v1 envelope by hand. The 1.x format was:
 *   [version=0x01][share_index][threshold][payload_len_be16][payload][HMAC-SHA256 tag]
 *
 * We don't need the MAC to be valid — the version gate must reject it
 * before any MAC check is attempted, so arbitrary tag bytes will do.
 */
function craft_v1_envelope(int $index, int $threshold, string $payload): string
{
    $header = chr(0x01)                     // legacy version
            . chr($index)
            . chr($threshold)
            . pack("n", strlen($payload));  // big-endian payload length
    $tag = str_repeat("\x00", 32);          // 32-byte HMAC-SHA256 tag (any bytes)
    return base64_encode($header . $payload . $tag);
}

echo "=== Test 1: v1 envelope rejected on recover() ===\n";
$v1_a = craft_v1_envelope(1, 2, str_repeat("A", 32));
$v1_b = craft_v1_envelope(2, 2, str_repeat("B", 32));

try {
    recover([1 => $v1_a, 2 => $v1_b]);
    echo "FAIL: v1 envelope should have been rejected\n";
} catch (Exception $e) {
    $msg = $e->getMessage();
    // Must mention legacy/1.x/2.x so the operator knows what to do.
    $hasLegacy = stripos($msg, "legacy") !== false
              || stripos($msg, "1.x") !== false
              || stripos($msg, "2.x") !== false;
    echo "OK: rejected with migration message: " . ($hasLegacy ? "YES" : "NO") . "\n";
}

echo "\n=== Test 2: Mixed v1 + v2 still rejected ===\n";
// Genuine v2 shares for comparison.
$good = share("real secret", 2, 3);
try {
    recover([
        1 => $v1_a,       // legacy
        2 => $good[2],    // v2
    ]);
    echo "FAIL: mixed v1+v2 should have been rejected\n";
} catch (Exception $e) {
    $msg = $e->getMessage();
    $hasLegacy = stripos($msg, "legacy") !== false
              || stripos($msg, "1.x") !== false
              || stripos($msg, "2.x") !== false;
    echo "OK: mixed case rejected with migration message: " . ($hasLegacy ? "YES" : "NO") . "\n";
}

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: v1 envelope rejected on recover() ===
OK: rejected with migration message: YES

=== Test 2: Mixed v1 + v2 still rejected ===
OK: mixed case rejected with migration message: YES

PASS
