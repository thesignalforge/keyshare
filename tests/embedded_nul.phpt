--TEST--
Signalforge\KeyShare: embedded NUL bytes in shares are rejected (not truncated)
--EXTENSIONS--
keyshare
--FILE--
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\Exception;

// Generate legitimate shares
$secret = "secret data";
$shares = share($secret, 2, 3);

// Inject a NUL byte into a share. The previous strlen-based decode would
// silently truncate at the NUL, potentially yielding a different recovery
// path. The fix uses explicit length, so the share is now base64-invalid
// (since the NUL isn't a valid base64 character) and recovery rejects it.
$tampered = "AAAA\0" . $shares[1];

try {
    recover([
        1 => $tampered,
        2 => $shares[2],
    ]);
    echo "FAIL: NUL-prefixed share should be rejected\n";
} catch (Exception $e) {
    echo "OK: NUL-prefixed share rejected\n";
}

// Same test with NUL in middle
$middle_nul = substr($shares[1], 0, 5) . "\0" . substr($shares[1], 5);
try {
    recover([
        1 => $middle_nul,
        2 => $shares[2],
    ]);
    echo "FAIL: mid-NUL share should be rejected\n";
} catch (Exception $e) {
    echo "OK: mid-NUL share rejected\n";
}

echo "PASS\n";
?>
--EXPECT--
OK: NUL-prefixed share rejected
OK: mid-NUL share rejected
PASS
