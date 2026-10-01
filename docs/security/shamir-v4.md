# SecretHub share format v4

Each byte is an element of GF(2^8), represented as the polynomial whose
coefficients are its bits. Addition and subtraction are XOR. Multiplication is
carryless polynomial multiplication reduced by the irreducible AES polynomial
`x^8 + x^4 + x^3 + x + 1` (`0x11b`). Each byte `s` has a separate polynomial
`f(x) = s + a1*x + ... + a(k-1)*x^(k-1)`. Coefficients are independent uniform
bytes from `:crypto.strong_rand_bytes(k - 1)`, without modulo reduction or
excluding zero. The highest coefficient may be zero: forcing it nonzero would
bias the distribution and invalidate the usual perfect-secrecy argument.

Coordinates are distinct integers `1..n`, with `1 <= k <= n <= 251`. The
existing maximum is retained. In this field, coordinate 251 is nonzero, unlike
the previous arithmetic modulo 251. Coordinates 0 and 252..255 are rejected.
Each value contains exactly one field element for every original secret byte;
there is no adjustment mask or secret-dependent normalization metadata.

Reconstruction uses Lagrange interpolation at zero. A basis factor for `xi`
is the product of `xj / (xi XOR xj)` for every other coordinate `xj`.
Nonzero elements have inverse `a^254`. Envelopes and uniqueness are checked
before this operation, so an inverse of zero is never needed.

For any fewer than `k` distinct nonzero coordinates, fixing the secret imposes
independent linear constraints on the `k-1` uniform coefficients. Each possible
observation has the same number of coefficient preimages for every secret.
This is the standard Shamir perfect-secrecy argument; round trips or statistical
tests alone cannot prove it. The Elixir implementation does not promise
constant-time arithmetic or explicit erasure of immutable VM binaries.

## Envelope

A share map contains `version: 4`, `share_set_id`, `id`, `threshold`,
`total_shares`, `secret_length`, and `value`. The generation is 16 raw bytes,
not a UUID string. `split/3` generates a fresh random generation; `split/4`
accepts the durable Vault generation from the caller. Secret length must be
1 through 4096 bytes. `valid_share?/1` checks all required fields and bounds.

The text representation is `secrethub-share-` followed by unpadded URL-safe
base64 of these exact bytes:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 1 | Version, exactly 4 |
| 1 | 1 | Coordinate, 1 through total |
| 2 | 1 | Threshold, 1 through total |
| 3 | 1 | Total, 1 through 251 |
| 4 | 2 | Secret length, unsigned big endian, 1 through 4096 |
| 6 | 16 | Share-set generation |
| 22 | Secret length | Value |

The decoder limits the base64 payload to 5491 bytes before decoding. After
decoding, it requires that unpadded URL-safe base64 re-encoding exactly equals
the supplied payload. This rejects padding and noncanonical discarded pad bits.
It also rejects trailing bytes, missing bytes, unsupported versions, and invalid bounds. It
returns an error for arbitrary malformed input; error strings never contain
share values or reconstructed secrets. The encoder also returns an error for an
invalid map. Combination requires matching version, generation, threshold,
total, and length, and rejects duplicate coordinates even with equal values.

Metadata is not authentication. The Vault state machine must compare the
version and generation with its durable expected values before collecting
shares, then authenticate the reconstructed wrapping key before accepting it.
An attacker can rewrite metadata and values. This module alone cannot identify
such a forgery.

## Legacy recovery boundary

Formats 1 through 3 fail closed with `Legacy share version unsupported;
verified Vault recovery required`. Legacy maps are invalid. These formats used
arithmetic modulo 251, biased coefficients, and (for v3) secret-derived
adjustment metadata. They must not enter ordinary unseal or be reinterpreted as
v4 shares. No existing Vault is automatically reset or migrated here.

Existing data requires an explicit recovery procedure that validates the
recovered old key against existing authenticated ciphertext or independently
verifiable key material before transactionally creating new durable key
validation material. Until that procedure exists and succeeds, legacy Vaults
are recovery-blocked. Creating a verifier from an arbitrary legacy
reconstruction is insufficient.

## Independent vectors and reference

The checked-in test contains a reference using polynomial convolution and
long division, independently structured from production shift-and-add
multiplication. It checks all 251 split coordinates against the reference and
reconstructs every three-share subset of the following fixed vectors. This
standalone Python reference generates the vectors without SecretHub code:

```python
def multiply(a, b):
    product = 0
    for i in range(8):
        for j in range(8):
            if ((a >> i) & 1) and ((b >> j) & 1):
                product ^= 1 << (i + j)
    for i in range(14, 7, -1):
        if (product >> i) & 1:
            product ^= 0x11b << (i - 8)
    return product

assert multiply(0x57, 0x13) == 0xfe  # AES multiplication example
secret = bytes([0, 1, 250, 251, 252, 253, 254, 255])
a1 = bytes([0x53, 0xca, 0, 1, 2, 3, 254, 255])
a2 = bytes([0xca, 0x53, 255, 254, 253, 252, 1, 0])
for x in [1, 2, 3, 17, 250, 251]:
    value = bytes(s ^ multiply(a, x) ^ multiply(b, multiply(x, x))
                  for s, a, b in zip(secret, a1, a2))
    print(x, value.hex())
```

| Coordinate | Value hex |
| --- | --- |
| 1 | 9998050403020100 |
| 2 | a3d92b2c21261d1a |
| 3 | 3a40d4d3ded9e2e5 |
| 17 | 8590cfc5dfd56369 |
| 250 | 47ee1fe6f20b3bc2 |
| 251 | de77e0190df4c43d |

The coefficient regression samples 32768 linear coefficients by splitting zero
bytes at coordinate 1, where the share value equals the coefficient. It requires
all 256 values, including zero and 251..255, with broad frequency bounds
48..224 (expected count 128). This detects the old modulo-251 reduction; source
inspection establishes exact uniform sampling. Additional tests exercise every
secret byte, random 32-byte keys, all threshold subsets, exact wire bytes,
metadata mismatch, truncation, oversize, malformed input, and legacy rejection.
