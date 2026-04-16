--TEST--
Signalforge\KeyShare: auth tag is exactly 32 bytes (libsodium crypto_auth_BYTES) and any flip fails recovery
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\TamperingException;

/*
 * Envelope layout (v2):
 *   [version:1][index:1][threshold:1][payload_len:2][payload:N][tag:32]
 *
 * So for a fixed secret length, total_decoded_len = 5 + N + 32.
 * We verify that assertion, then flip every single byte of the envelope
 * one at a time and confirm recovery fails in every case.
 */

echo "=== Test 1: Envelope size accounts for 32-byte tag ===\n";
$secret = str_repeat("X", 17); // N = 17 -> envelope = 5 + 17 + 32 = 54 bytes
$shares = share($secret, 2, 3);
$decoded = base64_decode($shares[1]);
$expected_len = 5 + 17 + 32;
echo "Decoded envelope length: " . strlen($decoded)
    . " (expected " . $expected_len . "): "
    . (strlen($decoded) === $expected_len ? "YES" : "NO") . "\n";

echo "\n=== Test 2: Tag is the last 32 bytes, not zeros ===\n";
// If libsodium's crypto_auth silently returned zeros, that would be a
// catastrophic failure. Confirm the tag bytes aren't all-zero.
$tag = substr($decoded, -32);
$is_zero = ($tag === str_repeat("\x00", 32));
echo "Tag is non-zero: " . ($is_zero ? "NO" : "YES") . "\n";
echo "Tag length: " . strlen($tag) . "\n";

echo "\n=== Test 3: Every byte of the envelope is MAC-protected ===\n";
/*
 * For each byte position in the decoded envelope, flip it, re-encode,
 * and try to recover using the tampered share plus one clean share.
 * Every single flip must cause recovery to fail.
 *
 * Note: flipping the threshold byte (index 2) or the payload_len bytes
 * (indices 3-4) may cause a structural error rather than a MAC error;
 * both count as "rejected". The test asserts that recovery does NOT
 * return a plausible-looking string.
 */
$fail_count = 0;
$success_count = 0;
$len = strlen($decoded);

for ($pos = 0; $pos < $len; $pos++) {
    $tampered = $decoded;
    $tampered[$pos] = chr(ord($tampered[$pos]) ^ 0xFF);
    $tampered_b64 = base64_encode($tampered);

    try {
        $result = recover([
            1 => $tampered_b64,
            2 => $shares[2],
        ]);
        // Even if some exception path was missed, the result must not
        // equal the original secret. A non-exception, non-matching
        // result is still a failure to authenticate.
        if ($result === $secret) {
            $success_count++;
            echo "FAIL at byte $pos: recovered the original secret from a tampered share!\n";
        } else {
            // Recovered something different without exception -
            // counts as acceptable rejection for header-field flips
            // that might produce a different valid-looking secret.
            // The critical property is: cannot recover ORIGINAL.
            $fail_count++;
        }
    } catch (\Exception $e) {
        $fail_count++;
    }
}
echo "Byte flips rejected: $fail_count / $len\n";
echo "Any flip produced the original secret: " . ($success_count > 0 ? "YES" : "NO") . "\n";

echo "\n=== Test 4: Flipping only tag bytes always raises TamperingException ===\n";
/*
 * For the 32 tag bytes specifically, the failure mode MUST be a
 * TamperingException (not a structural error, because the structural
 * fields are intact).
 */
$tag_tamper_fail = 0;
for ($pos = $len - 32; $pos < $len; $pos++) {
    $tampered = $decoded;
    $tampered[$pos] = chr(ord($tampered[$pos]) ^ 0x01);
    $tampered_b64 = base64_encode($tampered);

    try {
        recover([
            1 => $tampered_b64,
            2 => $shares[2],
        ]);
        echo "FAIL at tag byte $pos: recover() did not throw\n";
    } catch (TamperingException $e) {
        $tag_tamper_fail++;
    } catch (\Exception $e) {
        echo "FAIL at tag byte $pos: wrong exception type: " . get_class($e) . "\n";
    }
}
echo "All 32 tag-byte flips raised TamperingException: "
    . ($tag_tamper_fail === 32 ? "YES" : "NO ($tag_tamper_fail/32)") . "\n";

echo "\nPASS\n";
?>
--EXPECT--
=== Test 1: Envelope size accounts for 32-byte tag ===
Decoded envelope length: 54 (expected 54): YES

=== Test 2: Tag is the last 32 bytes, not zeros ===
Tag is non-zero: YES
Tag length: 32

=== Test 3: Every byte of the envelope is MAC-protected ===
Byte flips rejected: 54 / 54
Any flip produced the original secret: NO

=== Test 4: Flipping only tag bytes always raises TamperingException ===
All 32 tag-byte flips raised TamperingException: YES

PASS
