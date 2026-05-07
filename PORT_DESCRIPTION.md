# Port description

Detailed handshake protocol and timing for `chacha20_poly1305_aead`.

## Reset

`rst_ni` is **synchronous active-low**. Hold it low for at least 4
clock cycles before the first command. After de-assertion, the core is
in `T_IDLE` with `init_ready_o = 1`.

```
clk_i      __|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
rst_ni     ‾‾‾‾‾‾‾|_______________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾
init_ready_o      X X X X X X X X X X X X X 1 1 1 1 1 1
```

## Session start

A new AEAD session is initiated by pulsing `init_i` for one cycle
together with the key, nonce, and mode. The core internally derives the
Poly1305 (r, s) key by running ChaCha20 with `counter = 0`, then begins
accepting AAD or data.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
init_ready_o        ‾‾‾|___________________________________
init_i              ___|‾‾|_____________________________________
key_i / nonce_i     ___|valid|___________________________________
mode_i              ___|valid|___________________________________
                    (key derive ~83 cycles)
aad_ready_o         _________________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
```

`init_ready_o` is high when the core can accept a new `init_i`, which
includes both `T_IDLE` (post-reset / post-clean) and `T_DONE` (after a
prior session has finalised). Driving `init_i` while `init_ready_o = 0`
is ignored.

## AAD streaming

Each AAD chunk is 1..16 bytes. The caller sends 16-byte chunks until
the last one, which can be partial. Per RFC 8439 §2.8, partial chunks
are zero-padded internally to 16 bytes before being fed to Poly1305 —
the caller does NOT need to zero-pad explicitly.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
aad_ready_o         ‾‾‾‾‾‾|___________|‾‾‾‾‾‾|___________|‾‾
aad_valid_i         ___|‾‾|‾‾‾‾‾‾‾‾‾‾‾|‾‾|‾‾‾‾‾‾‾‾‾‾‾|___
aad_chunk_i         ___|c0 |‾‾‾‾‾‾‾‾‾‾‾|c1 |‾‾‾‾‾‾‾‾‾‾‾|___
aad_byte_count_i    ___|16 |             |12 |             ___
aad_last_i          ___|0  |             |1  |             ___
```

`aad_byte_count_i = 16` for full chunks; `1..15` for the last partial.
After accepting an AAD chunk, the core takes ~5 cycles to absorb it
through Poly1305 (one multiply); during that window `aad_ready_o` is
low.

If the message has no AAD, simply skip the AAD phase: send `data_valid_i`
directly, and the FSM transitions automatically.

## Plaintext / ciphertext streaming

Each data block is 1..64 bytes. The result block (encrypted ciphertext
or decrypted plaintext) is emitted in lock-step with the input.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|
data_ready_o        ‾‾|_______________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
data_valid_i        |‾‾|_____________________________________
data_i              |b0 |_____________________________________
data_byte_count_i   |64 |_____________________________________
                    (chacha20 block ~83 cycles + poly1305 absorb)
result_valid_o      _____________________________|‾‾|________
result_o            _____________________________|r0 |________
result_ready_i      _________________________________|‾‾|____
```

`data_byte_count_i = 64` for full blocks; `1..63` for the last partial.
`data_last_i = 1` together with `data_valid_i = 1` triggers automatic
finalisation: the core emits the length block to Poly1305 and arrives
at `T_DONE` without an explicit `finalize_i` pulse.

`result_byte_count_o` mirrors the input byte count; the upper unused
bytes of `result_o` for a partial last block are don't-care from the
caller's perspective.

## Finalisation

There are two ways to finalise:

1. **Implicit (recommended)**: pulse `data_last_i = 1` with the final
   `data_valid_i` beat. The core handles everything else.
2. **Explicit**: after all `data_valid_i` beats have been consumed,
   pulse `finalize_i = 1` for one cycle. Useful in streaming flows
   where the caller does not know in advance which beat is last.

Either way, the core then:
1. Feeds the (`len_aad` || `len_ct`) 16-byte length block to Poly1305.
2. Runs the Poly1305 freeze + add-s step.
3. Asserts `tag_valid_o = 1` with `tag_o` stable.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|
data_last_i         |‾‾|_____________________________________
                    (LEN block + finalise ~10 cycles)
tag_valid_o         _____________________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾
tag_o               _____________________________|tag |‾‾‾‾‾‾‾‾‾‾‾‾
```

`tag_valid_o` stays high until the next `init_i`. `tag_o` is stable
across this entire window.

## Constant-time tag compare

For the decrypt path, the caller drives `expected_tag_i` with the tag
received over the wire. The core combinationally computes
`tag_match_o = tag_valid_o && (tag_o ^ expected_tag_i == 0)`. There is
no early-exit; the full 128-bit XOR-OR-zero is always evaluated, so
`tag_match_o` does not leak partial-match information.

For the encrypt path, leave `expected_tag_i = 0` (or any value); the
caller will use `tag_o` directly.

## Mode select (`mode_i`)

`mode_i` is a status bit recorded for the integrator's benefit. The
hardware operations are identical for all three modes (ChaCha20 stream
XOR, Poly1305 absorb), but the value is exposed via debug ports and
the coverage collector.

| Encoding | Mode      | Use                                    |
|----------|-----------|----------------------------------------|
| `2'b00`  | ENCRYPT   | Caller feeds plaintext, gets ciphertext + tag |
| `2'b01`  | DECRYPT   | Caller feeds ciphertext, gets plaintext + tag, then verifies via `expected_tag_i` |
| `2'b10`  | AAD_ONLY  | Caller feeds AAD only, no ct/pt; tag authenticates AAD alone (rare) |
| `2'b11`  | reserved  | Reserved for future modes (e.g., XChaCha20-Poly1305 in Premium tier). Treated as ENCRYPT for now. |

## Endianness

All wide buses use little-endian byte ordering, matching the on-the-wire
RFC 8439 convention:
- `key_i[7:0]` is byte 0 of the key.
- `nonce_i[7:0]` is byte 0 of the nonce.
- `aad_chunk_i[7:0]` is byte 0 of the chunk.
- `data_i[7:0]` is byte 0 of the block.
- `result_o[7:0]` is byte 0 of the result block.
- `tag_o[7:0]` is byte 0 of the tag.

This matches the convention used by Python's `cryptography` library and
by reference implementations in libsodium / OpenSSL / WireGuard.

## Latency summary

For a message with `A` bytes of AAD and `P` bytes of plaintext:

| Phase                         | Cycles                              |
|-------------------------------|-------------------------------------|
| Init capture                  | 1                                   |
| Poly1305 key derive (cha20)   | ~85                                 |
| AAD absorb                    | `ceil(A / 16) * 5`                  |
| Per-data-block (cha20 + poly) | `~85 + 4 * 5 = ~105`                |
| Number of data blocks         | `ceil(P / 64)`                      |
| LEN block absorb              | 5                                   |
| Poly1305 finalize             | 2                                   |
| Total (rough)                 | `~95 + ceil(A/16)*5 + ceil(P/64)*105` |

For a typical TLS 1.3 record with ~16 bytes AAD and ~16 KB plaintext,
this is about 27 000 cycles, i.e. ~270 µs at 100 MHz.
