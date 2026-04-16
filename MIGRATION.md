# Migrating from keyshare 1.x to 2.x

The 2.x series is a **clean-break** security upgrade of the keyshare
extension. The PHP API is unchanged, but the wire format and cryptographic
primitives have all been replaced. **Shares produced by 1.x cannot be
recovered by 2.x.**

## TL;DR

- If you have 1.x shares sitting in storage: recover them with 1.x, then
  re-split the recovered secrets with 2.x. 2.x will refuse 1.x shares
  with a clear error message telling you to do exactly this.
- Plan this migration as a maintenance window. `recover(1.x) -> share(2.x)`
  round-trips each secret and needs access to the original threshold
  shares.

## What changed

| Concern             | 1.x                            | 2.x                                      |
| ------------------- | ------------------------------ | ---------------------------------------- |
| GF(256) math        | Hand-rolled (+SIMD)            | **libgfshare**                           |
| Envelope MAC        | Hand-rolled HMAC-SHA256        | **libsodium crypto_auth** (HMAC-SHA512/256) |
| MAC key derivation  | Hand-rolled HKDF-ish over SHA-256 | **libsodium crypto_generichash** (BLAKE2b, personalized) |
| Passphrase KDF      | Hand-rolled PBKDF2-SHA256, 100k iters | **libsodium crypto_pwhash** (Argon2id, MODERATE) |
| CSPRNG              | libsodium randombytes_buf      | libsodium randombytes_buf (unchanged)    |
| Secure erase        | sodium_memzero (via helper)    | sodium_memzero (unchanged)               |
| Envelope version    | `0x01`                         | `0x02`                                   |

## Why the clean break

Every primitive in 1.x was hand-rolled against the spec and passed its
own tests. That is not the same as being reviewed. The 2.x stack
delegates all cryptographic responsibilities to libsodium (NIST-aligned,
audited, constant-time) and libgfshare (purpose-built for this exact
problem). The reduction in locally-owned cryptographic code is substantial
(see the commit diff: ~1200 lines of hand-rolled crypto removed, ~500
lines of glue added).

Maintaining a legacy-compat path would have required keeping the entire
1.x SHA-256/HMAC/PBKDF2 implementation in the binary, defeating the
reason to switch in the first place. A clean break is the correct answer.

## Migration procedure

```php
use function Signalforge\KeyShare\recover;
use function Signalforge\KeyShare\share;

// Step 1: Running the 1.x extension on a separate process/container,
//         recover the original secret.
$secret = recover($old_1x_shares);  // <- inside a 1.x-loaded PHP

// Step 2: Running the 2.x extension, split it again.
$new_shares = share($secret, $threshold, $num_shares);  // <- inside a 2.x-loaded PHP

// Step 3: Distribute $new_shares to the holders, destroy the 1.x shares.
sodium_memzero($secret);
```

If you try to pass a 1.x share to 2.x's `recover()`, you'll get:

```
Signalforge\KeyShare\Exception: This share was created by keyshare 1.x
using legacy crypto. Re-issue shares with keyshare 2.x.
```

## Performance notes

### `share()` and `recover()` (raw secrets)

No meaningful change. libgfshare is a well-optimized C implementation;
throughput on typical secrets (32 bytes to a few kilobytes) is
dominated by memory allocation, not by GF math.

The removal of the AVX2/SSE2 GF(256) code does theoretically reduce
peak throughput for *very* large secrets (>> 1 MiB). Given the
`KEYSHARE_MAX_SECRET_LEN = 65535` bytes cap, this is not observable
in practice.

### `passphrase()` — intentionally slow

`passphrase()` now invokes Argon2id at the libsodium `MODERATE` cost
tier:

- Ops limit: 3
- Memory limit: 256 MiB

On typical modern server hardware this is roughly **0.5 to 1.0 seconds**
per call. That is not a bug; that is the primary defence against
offline brute-force of a stolen share. Argon2id's memory-hardness means
an attacker with a GPU farm cannot cheaply parallelize the search.

If your deployment genuinely cannot afford 256 MiB RAM per `passphrase()`
call (e.g. a very constrained container), the options are:

1. Accept the cost. It's paid once per key-issuance, not per request.
2. Fork this extension and change the `crypto_pwhash_OPSLIMIT_MODERATE`
   / `crypto_pwhash_MEMLIMIT_MODERATE` pair to `INTERACTIVE` (64 MiB,
   ~0.1s). Document the reduced security margin.

We deliberately do **not** expose the cost tier as a runtime parameter.
Doing so would let an attacker coerce weak parameters, and would create
a "bit-compatibility" obligation between calls with different tiers.
If you need configurability, fork and set it at compile time.

## Verifying migration

After upgrading, a quick sanity check:

```php
// Fresh roundtrip.
$shares = \Signalforge\KeyShare\share("test-secret", 2, 3);
$back   = \Signalforge\KeyShare\recover($shares);
assert($back === "test-secret");

// Legacy rejection.
try {
    \Signalforge\KeyShare\recover($old_1x_shares);
    assert(false, "legacy share was silently accepted!");
} catch (\Signalforge\KeyShare\Exception $e) {
    assert(str_contains($e->getMessage(), "1.x"));
}
```

## Version identification

The envelope's first byte (after base64 decode) identifies the version:

- `0x01` => 1.x legacy format
- `0x02` => 2.x current format

Operators auditing stored shares can check the version byte directly:

```php
function share_version(string $encoded_share): int
{
    $raw = base64_decode($encoded_share, true);
    if ($raw === false || strlen($raw) === 0) {
        throw new \InvalidArgumentException("not a valid share");
    }
    return ord($raw[0]);
}
```
