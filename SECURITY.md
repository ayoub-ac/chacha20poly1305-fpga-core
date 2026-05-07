# Security model

This document describes what `chacha20_poly1305_aead` (and the underlying
`chacha20_core` and `poly1305_core`) is designed to defend against, what
it is NOT designed to defend against, and how to evaluate the claims.

If you need a side-channel-resistant AEAD core for a real product, read
this whole document and decide whether the threat model matches your
deployment. Don't trust marketing copy; trust the threat model and your
own evaluation.

## What is protected

### 1. Constant-time execution

ChaCha20 (RFC 8439 §2.4) and Poly1305 (RFC 8439 §2.5) are designed to
have no data-dependent branches. The cycle count of every FSM in this
core depends only on the message length and not on the message bytes,
the key, or the nonce.

Per-block cycle counts:
* `chacha20_block`: 83 cycles per 64-byte keystream block (1 setup + 80
  quarter-rounds + 1 final add + 1 done), regardless of key/nonce.
* `poly1305_core`: 5 cycles per 16-byte chunk (add + multiply + 3 fold
  steps), regardless of message bytes.
* `chacha20_poly1305_aead` top-level: deterministic per (aad_len,
  pt_len) tuple.

**What this protects**: timing attacks that observe completion latency
to infer key or message bits. There is no path through the design that
takes a different number of cycles depending on data values.

### 2. Constant-time tag compare

The `tag_match_o` output is computed combinationally as
`(poly_tag ^ expected_tag_i) == 0`. There is no early-exit; the full
128-bit XOR-OR-zero is always evaluated. A naive byte-by-byte memcmp
performed in software risks leaking how many leading bytes match, but
this hardware compare does not.

### 3. Bounded round and step counters

The internal `step_q` (ChaCha20 quarter-round counter, 0..79) and the
Poly1305 FSM round counter are bounded by SVA assertions that fail the
test gate if a counter ever runs past its expected range.

### 4. Strong AEAD properties from RFC 8439

The construction itself provides:
* **Confidentiality**: ChaCha20 is a strong stream cipher when used with
  a unique (key, nonce) pair. Reusing a nonce under the same key breaks
  confidentiality catastrophically.
* **Integrity / authenticity**: Poly1305 binds the AAD, the ciphertext,
  and their lengths into a 128-bit tag. Modifying any byte of AAD,
  ciphertext, or the (aad_len, ct_len) tuple invalidates the tag.

## What is NOT covered (be honest)

This list is deliberately exhaustive so purchasers can evaluate fit:

- **Differential power analysis (DPA)** on the ChaCha20 round update or
  the Poly1305 multiplier: the working state and the multiplier inputs
  are unmasked. A power attacker measuring leakage at the FF-update
  boundary can mount standard CPA / DPA against intermediate values.
  Mitigation requires arithmetic masking of the additions and shares /
  randomization of the multiplier — not implemented.
- **Electromagnetic (EM) analysis** and **template attacks**: not
  specifically countered. There is no power balancing, no differential
  routing, no constant-Hamming-weight encoding.
- **Fault injection** on the round counter, working variables, the
  Poly1305 accumulator, or the message-feed FSM: a flipped bit can
  corrupt the output. No duplicated-counter / parity-protected register
  variant is shipped; that is on the Premium roadmap (matching the AES
  sibling product, which does ship a hardened variant).
- **Cache / micro-architectural side channels**: not applicable (this
  is RTL, not software). However, if you place this core into a system
  with a shared bus or shared memory, those channels can leak.
- **Nonce-reuse misuse**: this core does NOT detect or prevent nonce
  reuse. Re-using a (key, nonce) pair under ChaCha20-Poly1305 leaks the
  XOR of plaintexts and allows tag forgery. The integrator must
  guarantee uniqueness of every (key, nonce). For systems where
  nonce-uniqueness is not trivially provable, consider
  XChaCha20-Poly1305 (extended-nonce variant, 192-bit nonce) — not
  implemented in this core; available in the Premium tier on request.
- **Invasive attacks** (decap, microprobing) are entirely out of scope.

If your deployment threat model includes any of the above and the rest
of your system relies on AEAD integrity, this core is not enough on its
own.

## Compliance claims

- **RFC 8439 conformance**: yes. The RTL implements ChaCha20,
  Poly1305, and the AEAD_CHACHA20_POLY1305 construction exactly as
  specified, and is verified against:
  * RFC 8439 §2.3.2 ChaCha20 block-function vector.
  * RFC 8439 §2.4.2 ChaCha20 sunscreen vector.
  * RFC 8439 §2.5.2 Poly1305 vector.
  * RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 worked example.
  * 100 random vectors cross-checked against
    `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
- **NIST CAVP test certificate**: NOT obtained. NIST does not yet have
  a CAVP suite for ChaCha20-Poly1305; informal validation is via the
  RFC vectors and the Python `cryptography` reference.
- **FIPS-140-3 certification**: NOT claimed. ChaCha20-Poly1305 is not
  on the FIPS 140-3 approved-algorithm list as of the writing of this
  document. If your deployment requires FIPS, use the AES-256-GCM
  sibling product instead.
- **Common Criteria**: not evaluated.
- **TLS 1.3 / WireGuard / SSH suitability**: this core implements the
  cryptographic primitive used by all three, but the protocol-level
  framing, key schedule, rekeying, and replay protection are out of
  scope and must be implemented by the integrator.

## Test methodology used to validate the security claims

The Verilator testbenches run:

1. **Functional correctness on RFC 8439 vectors**: `make test`. The
   testbench includes every published vector from RFC 8439 sections
   2.3.2, 2.4.2, 2.5.2, and 2.8.2. The full vector set passes on
   Verilator 5.020 in the shipped configuration.
2. **Cross-validation against Python `cryptography`**: the testbench
   includes 100 randomly-generated (key, nonce, AAD, plaintext) tuples,
   each encrypted by the Python reference and replayed through the
   DUT; the ciphertext + tag must match exactly. Lengths cover edge
   cases (0..7 bytes, 56..63 bytes, 64..71 bytes, and random up to
   256).
3. **SVA-enforced protocol invariants on every cycle**: see
   `tb/aead_assertions.sv`. Properties include:
   - `data_ready_o` only rises after `init_i` has been seen.
   - `result_o` is stable while `result_valid_o`.
   - `tag_o` is stable while `tag_valid_o`.
   - `tag_valid_o` only rises after an effective finalization.
   - Tag latency bound after finalization.
4. **Functional coverage**: 10 bins (encrypt / decrypt / aad-only modes,
   AAD seen, short / long data, partial / full last block, finalize and
   tag emission). Coverage report printed at end of `make test`.

We do NOT run experimental DPA / CPA against a real bitstream. The
constant-time claim is **design intent**, derived from the structure of
the algorithm. If you need an experimentally-verified claim, that is a
separate engagement that requires an FPGA, an oscilloscope, and a
trace-collection campaign measured in days or weeks.

## How to use the core safely

1. **Never reuse a (key, nonce) pair.** This is the cardinal rule of
   ChaCha20-Poly1305. A 96-bit nonce gives you 2^96 nonces per key —
   more than enough for any random-nonce or counter-nonce strategy in a
   normal lifetime, but only if you actually maintain uniqueness.
2. Hold `rst_ni` low for at least 4 cycles after power-on and before
   the first command.
3. Wipe the message and key from memory after use; the wrapper does not
   do this automatically (the working-state registers retain post-op
   state until the next `init_i`).
4. For tag verification, use `tag_match_o` (constant-time) instead of
   reading `tag_o` and comparing in software.
5. The core is not a substitute for protocol-level measures like
   replay protection, rekeying, or padding-oracle hardening. Wrap it
   in a real protocol (TLS, WireGuard, IPsec ESP).

## Reporting issues

Found a bug, a side channel we missed, or a discrepancy with RFC 8439?
Open an issue or contact the email in the README. Coordinated disclosure
welcome. We do not currently offer a bug bounty.
