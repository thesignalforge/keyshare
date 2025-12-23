# Signalforge KeyShare

A high performance PHP extension implementing Shamir's Secret Sharing with authenticated envelopes and SIMD optimization.

Split secrets into multiple shares where any threshold number of shares can reconstruct the original, while fewer shares reveal nothing. Each share is cryptographically authenticated to detect tampering and prevent mixing shares from different secrets.

## Features

- **Threshold Secret Sharing**: Split secrets into N shares where any K shares reconstruct the original
- **Authenticated Envelopes**: HMAC SHA256 integrity protection on every share
- **SIMD Acceleration**: Automatic runtime detection with AVX2, SSE2, and scalar fallbacks
- **Passphrase Support**: Derive cryptographic keys from passphrases using PBKDF2 SHA256
- **Tamper Detection**: Corrupted or mixed shares are detected and rejected
- **Zero Dependencies**: No OpenSSL, libsodium, or external crypto libraries required
- **Deterministic**: Same inputs always produce identical outputs

## Requirements

- PHP 8.3 or later
- Linux or macOS (x86_64 for SIMD benefits)
- C compiler with C11 support

## Installation

### From Source

```bash
git clone https://github.com/signalforge/keyshare.git
cd keyshare
phpize
./configure --enable-keyshare
make
make test
sudo make install
```

Add to your `php.ini`:

```ini
extension=keyshare
```

### Verify Installation

```bash
php -m | grep keyshare
php --ri keyshare
```

## API Reference

All functions are in the `Signalforge\KeyShare` namespace.

### share

```php
Signalforge\KeyShare\share(
    string $secret,
    int $threshold,
    int $shares
): array
```

Split a binary or UTF8 secret into shares.

**Parameters:**
- `$secret` — The secret to split (1 to 65535 bytes)
- `$threshold` — Minimum shares needed to reconstruct (2 to 255)
- `$shares` — Total number of shares to generate (threshold to 255)

**Returns:** Associative array indexed by share number (1 to N) containing base64 encoded authenticated shares.

**Throws:** `Signalforge\KeyShare\Exception` on invalid parameters.

### recover

```php
Signalforge\KeyShare\recover(
    array $shares
): string
```

Reconstruct a secret from shares.

**Parameters:**
- `$shares` — Associative array of base64 encoded shares (minimum threshold count)

**Returns:** The original secret as a binary string.

**Throws:** `Signalforge\KeyShare\Exception` on:
- Insufficient shares for threshold
- MAC verification failure (tampering detected)
- Mixed shares from different secrets
- Malformed envelope structure

### passphrase

```php
Signalforge\KeyShare\passphrase(
    string $passphrase,
    int $threshold,
    int $shares
): array
```

Derive a cryptographic key from a passphrase and split it into shares.

Uses PBKDF2 SHA256 with 100,000 iterations to derive a 32 byte key, then splits that key using Shamir's scheme.

**Parameters:**
- `$passphrase` — The passphrase to derive a key from
- `$threshold` — Minimum shares needed to reconstruct (2 to 255)
- `$shares` — Total number of shares to generate (threshold to 255)

**Returns:** Associative array indexed by share number containing base64 encoded authenticated shares.

**Throws:** `Signalforge\KeyShare\Exception` on invalid parameters.

## Usage Examples

### Basic Secret Sharing

```php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;

// Split a secret into 5 shares, requiring any 3 to reconstruct
$secret = "my sensitive data";
$shares = share($secret, 3, 5);

// Distribute shares to different parties
// $shares[1] -> Alice
// $shares[2] -> Bob
// $shares[3] -> Charlie
// $shares[4] -> Dave
// $shares[5] -> Eve

// Later: reconstruct with any 3 shares
$recovered = recover([
    1 => $shares[1],  // Alice
    3 => $shares[3],  // Charlie
    5 => $shares[5],  // Eve
]);

assert($recovered === $secret);
```

### Passphrase Based Key Sharing

```php
use function Signalforge\KeyShare\passphrase;
use function Signalforge\KeyShare\recover;

// Split a passphrase derived key among trustees
$shares = passphrase("correct horse battery staple", 3, 5);

// Recover the derived key (32 bytes)
$derivedKey = recover([
    2 => $shares[2],
    4 => $shares[4],
    5 => $shares[5],
]);

// Use the derived key for encryption, etc.
$ciphertext = openssl_encrypt($data, 'aes-256-gcm', $derivedKey, ...);
```

### Tamper Detection

```php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\Exception;

$shares = share("secret", 2, 3);

// Tamper with a share
$tampered = $shares[1];
$decoded = base64_decode($tampered);
$decoded[10] = chr(ord($decoded[10]) ^ 0xFF);
$tampered = base64_encode($decoded);

try {
    recover([
        1 => $tampered,
        2 => $shares[2],
    ]);
} catch (Exception $e) {
    echo "Tampering detected: " . $e->getMessage();
    // Output: Share authentication failed: MAC mismatch (tampered or mixed shares)
}
```

### Binary Data

```php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;

// Works with any binary data
$binarySecret = random_bytes(256);
$shares = share($binarySecret, 5, 10);

$recovered = recover([
    1 => $shares[1],
    3 => $shares[3],
    5 => $shares[5],
    7 => $shares[7],
    9 => $shares[9],
]);

assert($recovered === $binarySecret);
```

## Share Format

Each share is a base64 encoded authenticated envelope:

```
+─────────+─────────────+───────────+─────────────+─────────+──────────+
│ Version │ Share Index │ Threshold │ Payload Len │ Payload │ Auth Tag │
│ 1 byte  │   1 byte    │  1 byte   │   2 bytes   │ N bytes │ 32 bytes │
+─────────+─────────────+───────────+─────────────+─────────+──────────+
```

- **Version**: Envelope format version (currently 1)
- **Share Index**: Share number (1 to 255)
- **Threshold**: Minimum shares required for reconstruction
- **Payload Length**: Big endian uint16 length of payload
- **Payload**: Raw Shamir share data
- **Auth Tag**: HMAC SHA256 over all preceding fields

The authentication key is derived from the secret using HKDF style expansion, ensuring shares from different secrets cannot be mixed.

## Security Considerations

### What This Provides

- **Information theoretic security**: Fewer than threshold shares reveal zero information about the secret
- **Tamper detection**: Any modification to shares is detected via MAC verification
- **Mix prevention**: Shares from different secrets cannot be combined

### What This Does Not Provide

- **Share confidentiality**: Share contents are not encrypted; the share itself is sensitive
- **Forward secrecy**: Compromising the secret compromises all shares
- **Availability**: Losing too many shares makes recovery impossible

### Recommendations

1. Distribute shares through secure channels
2. Store shares in separate physical/logical locations
3. Use passphrase mode for human memorable secrets
4. Consider threshold carefully: too low risks compromise, too high risks loss
5. Test recovery procedures before relying on them

## Performance

Benchmarks on AMD Ryzen 9 9950X3D (AVX2 enabled):

| Secret Size | Split (5 of 10) | Recover (5 shares) |
|-------------|-----------------|---------------------|
| 32 bytes    | 0.01 ms         | 0.00 ms             |
| 1 KB        | 0.07 ms         | 0.02 ms             |
| 4 KB        | 0.24 ms         | 0.08 ms             |
| 64 KB       | 3.77 ms         | 1.30 ms             |

SIMD acceleration provides approximately 4x speedup over scalar implementation for large secrets.

## Technical Details

### Cryptographic Primitives

- **Secret Sharing**: Shamir's scheme over GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
- **Field Arithmetic**: Multiplication via log/exp tables with SIMD parallel nibble lookups
- **Authentication**: HMAC SHA256 with key derived from secret
- **Key Derivation**: PBKDF2 SHA256 with 100,000 iterations (passphrase mode)

### SIMD Implementation

The extension automatically detects CPU capabilities at module initialization:

- **AVX2**: Processes 32 bytes per iteration using 256 bit registers
- **SSE2/SSSE3**: Processes 16 bytes per iteration using 128 bit registers
- **Scalar**: Fallback for non x86 platforms or older CPUs

All paths produce identical output; SIMD only affects performance.

## Building for Development

```bash
# Debug build
phpize
./configure --enable-keyshare CFLAGS="-g -O0"
make

# Run tests
make test

# Run specific test
php run-tests.php tests/share.phpt

# Check for memory leaks (requires valgrind)
USE_ZEND_ALLOC=0 valgrind --leak-check=full php -d extension=modules/keyshare.so -r '...'
```

## Project Structure

```
keyshare/
├── config.m4              # Autoconf build configuration
├── php_keyshare.h         # PHP extension header
├── src/
│   ├── keyshare.c         # PHP function bindings
│   ├── gf256_simd.c/h     # SIMD optimized GF(256) arithmetic
│   ├── shamir.c/h         # Shamir secret sharing core
│   ├── envelope.c/h       # Authenticated envelope format
│   ├── kdf.c/h            # SHA256, HMAC, PBKDF2
│   └── base64.c/h         # Base64 encoding/decoding
└── tests/
    ├── share.phpt         # Share function tests
    ├── recover.phpt       # Recovery and tamper detection tests
    └── passphrase.phpt    # Passphrase function tests
```

## License

MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome. Please ensure:

1. All tests pass (`make test`)
2. New features include tests
3. Code follows existing style
4. No new external dependencies

## Acknowledgments

- Adi Shamir for the original secret sharing scheme (1979)
- The PHP internals community for extension development documentation
