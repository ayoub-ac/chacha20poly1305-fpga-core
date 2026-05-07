# chacha20poly1305-fpga-core

[![License: GPL-3.0-or-later or commercial](https://img.shields.io/badge/license-GPL--3.0%20%7C%20commercial-blue.svg)](LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#verification)
[![RFC 8439 vectors](https://img.shields.io/badge/RFC--8439-vectors%20pass-blue.svg)](#verification)
[![Lint](https://img.shields.io/badge/Verilator%20lint-clean-brightgreen.svg)](#build--test)

A small, synthesisable ChaCha20-Poly1305 AEAD IP core in SystemVerilog.
Implements RFC 8439 / RFC 7539 end-to-end (ChaCha20 stream cipher,
Poly1305 MAC, AEAD construction with AAD support, constant-time tag
compare). Targets iCE40, ECP5, Xilinx 7-series, Cyclone V, and Tang
Nano 9K.

The core is verified end-to-end against RFC 8439 published vectors and
100 random vectors cross-checked against Python's
`cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`. No FPGA
hardware is required for the test suite.

## Why this exists

ChaCha20-Poly1305 is the modern AEAD used by TLS 1.3, WireGuard, SSH,
the Linux kernel, and most new protocols where AES-NI is not available
or where constant-time AES is hard. Free FPGA cores for it are rare,
incomplete, or shipped without testbenches. This core is small,
dual-licensed cleanly (GPL for OSS, commercial for closed-source),
shipped with a real handshake protocol, RFC 8439 vectors in the
testbench, SystemVerilog assertions, functional coverage, and a
synthesis-comparison report across multiple toolchains.

## Quickstart

```bash
git clone https://github.com/ayoub-ac/chacha20poly1305-fpga-core.git
cd chacha20poly1305-fpga-core
make lint test            # Verilator lint + run RFC 8439 + random vectors
make synth_report         # SYNTH_REPORT.md across iCE40/ECP5/Xilinx/Vivado/Quartus
```

Requires Verilator 5.0+ for simulation. Yosys 0.30+ for the open synth
flow. Python 3 with `cryptography` for `make regen_vectors`.

## Architecture

```
                  +-------------------------+
       key_i ---->|                         |
     nonce_i ---->|  chacha20_poly1305_aead |---> result_o (ct/pt)
       aad_i ---->|     (top-level FSM)     |---> result_byte_count_o
      data_i ---->|                         |---> tag_o (128-bit)
       init_i---->|                         |---> tag_match_o (CT compare)
   finalize_i---->|  ready_o / valid_o      |
                  +------------+------------+
                               |
              +----------------+-----------------+
              |                |                 |
       chacha20_block   chacha20_core    poly1305_core
       (poly key gen,   (streaming       (130-bit acc,
        counter=0)       counter=1)        128-bit r)
              |                |
              +-> chacha20_qround (combinational)
```

Top-level FSM phases: `IDLE -> DERIVE_KEY -> POLY_INIT -> AAD ->
DATA -> DATA_FEED -> LEN -> FINALIZE -> DONE`. The FSM handles
zero-padding of partial AAD / ciphertext chunks per RFC 8439 §2.8 and
emits the final `(len_aad || len_ct)` block to Poly1305 automatically.

## Port table

| Signal              | Dir | Width | Description                                                                                  | RFC ref |
|---------------------|-----|-------|----------------------------------------------------------------------------------------------|---------|
| `clk_i`             | in  | 1     | System clock, all flops sample on rising edge.                                                | -       |
| `rst_ni`            | in  | 1     | Synchronous active-low reset; hold low ≥4 cycles before first command.                        | -       |
| `init_i`            | in  | 1     | Pulse for one cycle to start a new session with `key_i / nonce_i / mode_i`.                   | -       |
| `key_i`             | in  | 256   | ChaCha20 256-bit key, byte 0 in `key_i[7:0]`.                                                 | §2.4    |
| `nonce_i`           | in  | 96    | 96-bit nonce, byte 0 in `nonce_i[7:0]`.                                                       | §2.3    |
| `mode_i`            | in  | 2     | 00=encrypt, 01=decrypt, 10=AAD-only.                                                          | -       |
| `init_ready_o`      | out | 1     | High when the core can accept a new `init_i`.                                                 | -       |
| `aad_valid_i`       | in  | 1     | Asserted with `aad_chunk_i / aad_byte_count_i / aad_last_i` to feed AAD.                      | §2.8    |
| `aad_chunk_i`       | in  | 128   | 16-byte AAD chunk; bytes beyond `aad_byte_count_i` are masked internally.                     | §2.8    |
| `aad_byte_count_i`  | in  | 5     | Valid bytes in `aad_chunk_i` (1..16). 16 means a full chunk.                                  | -       |
| `aad_last_i`        | in  | 1     | Marks the final AAD chunk.                                                                    | -       |
| `aad_ready_o`       | out | 1     | Core ready to accept an AAD beat (handshake: `aad_valid_i && aad_ready_o`).                   | -       |
| `data_valid_i`      | in  | 1     | Asserted with `data_i / data_byte_count_i / data_last_i` to feed plaintext / ciphertext.      | §2.4    |
| `data_i`            | in  | 512   | 64-byte data block; bytes beyond `data_byte_count_i` are don't-care.                          | §2.4    |
| `data_byte_count_i` | in  | 7     | Valid bytes in `data_i` (1..64). 64 means a full block.                                       | -       |
| `data_last_i`       | in  | 1     | Marks the final data block. Triggers automatic finalisation.                                  | -       |
| `data_ready_o`      | out | 1     | Core ready to accept a data beat.                                                             | -       |
| `result_valid_o`    | out | 1     | Result block valid; consumer must assert `result_ready_i` to consume.                         | -       |
| `result_o`          | out | 512   | Output ciphertext (encrypt) or plaintext (decrypt) block.                                     | -       |
| `result_byte_count_o`| out | 7    | Valid bytes in `result_o`.                                                                    | -       |
| `result_last_o`     | out | 1     | High on the final result block.                                                               | -       |
| `result_ready_i`    | in  | 1     | Master asserts to consume `result_o`.                                                         | -       |
| `finalize_i`        | in  | 1     | Pulse to finalise (alternative to `data_last_i` for streaming flows).                         | -       |
| `tag_o`             | out | 128   | 128-bit Poly1305 tag, byte 0 in `tag_o[7:0]`.                                                 | §2.5    |
| `tag_valid_o`       | out | 1     | Tag is valid and stable.                                                                      | -       |
| `expected_tag_i`    | in  | 128   | Caller-provided expected tag for constant-time compare.                                       | -       |
| `tag_match_o`       | out | 1     | Constant-time comparison: `(tag_o == expected_tag_i) && tag_valid_o`.                         | -       |

## Headline numbers

Real numbers from `make synth_report` (Yosys 0.x, AEAD top with all
sub-modules flattened):

| Target           | LUT       | FF    | BRAM | Latency (114 B msg)   | Notes                  |
|------------------|-----------|-------|------|-----------------------|------------------------|
| iCE40 UP5K       | see `SYNTH_REPORT.md` | ~4500 | 0    | ~640 cycles           | LUT4 generic, no DSP   |
| ECP5 LFE5UM-25   | see `SYNTH_REPORT.md` | ~4500 | 0    | ~640 cycles           | abc9, no DSP inference |
| Xilinx Artix-7   | see `SYNTH_REPORT.md` | ~4500 | 0    | ~640 cycles           | Yosys generic mapping  |

The 130x128 Poly1305 multiplier is the dominant area cost. Vendor flows
(Vivado / Diamond / Quartus) fold this into DSP slices and the gate
count drops sharply; `synth_xilinx` shown here uses the open generic
mapping. See [`RESOURCE_ESTIMATES.md`](RESOURCE_ESTIMATES.md) for the
full breakdown and reduction options.

## Build & test

You need [Verilator](https://verilator.org/) 5.0 or newer.

```bash
make lint            # static check the RTL (qround + block + core + poly + aead)
make test            # build and run AEAD test suite (RFC 8439 + 100 random)
make test-chacha     # ChaCha20 streaming-core unit tests
make test-poly       # Poly1305 unit tests
make test-all        # all three suites
```

A passing run ends with `+PASS all tests passed` and exits 0.

## Verification

Three orthogonal techniques are wired into the testbench.

### Directed tests (5 groups)

| # | Test                                       | Coverage                                             |
|---|--------------------------------------------|------------------------------------------------------|
| 1 | RFC 8439 §2.8.2 AEAD vector                | Full AEAD encrypt + tag + tag-match                  |
| 2 | Tampered expected_tag rejected             | `tag_match_o` constant-time compare                  |
| 3 | 100 cross-validated random vectors         | `cryptography.hazmat.primitives.ciphers.aead`        |
| 4 | Mode coverage (encrypt / decrypt / AAD-only)| All `mode_i` encodings                              |
| 5 | 1024-byte multi-block message              | Streaming & length tracking                          |

Plus dedicated unit suites:
* `make test-chacha`: RFC 8439 §2.4.2 sunscreen vector, §2.3.2 block-function
  vector, 50 random round-trips cross-checked against a software ChaCha20.
* `make test-poly`: RFC 8439 §2.5.2 vector, empty-message edge case, 100
  random MACs cross-checked against a software Poly1305 reference.

### SystemVerilog assertions

`tb/aead_assertions.sv` enforces protocol invariants on every cycle of
every test:

- `data_ready_o` only rises after `init_i` has been seen.
- `result_o` is stable while back-pressured (`result_valid_o && !result_ready_i`).
- `tag_o` is stable while `tag_valid_o`.
- `tag_valid_o` only rises after an effective finalisation
  (`finalize_i` pulse OR a `data_last_i` beat).
- Tag latency bound after finalisation (`< LAT_MAX` cycles).

The assertions compile with both Verilator 5.x (`--assert`) and Vivado
xsim. They are stripped on synthesis flows via `` `ifndef SYNTHESIS ``.

### Functional coverage

`tb/aead_cov.sv` collects 10 bins. The simulator prints a coverage
summary at end-of-test:

```
---- Functional coverage ----
  [HIT ] mode_encrypt / mode_decrypt / mode_aad_only
  [HIT ] aad_seen / data_short / data_long
  [HIT ] partial_last / full_last
  [HIT ] finalize_seen / tag_emitted
Coverage: 10/10 bins (100.0%)
```

A regression that drops below 100% fails the gate.

### Synthesis comparison report

`make synth_report` runs every available toolchain on the same RTL and
emits [`SYNTH_REPORT.md`](SYNTH_REPORT.md) with a side-by-side LUT/FF/BRAM
table. Yosys (`synth_ice40` / `synth_ecp5` / `synth_xilinx`) is mandatory;
Vivado and Quartus are detected automatically and skipped with a notice
when not on `$PATH`.

## Variants

| Variant                             | Use case                                                                       | Tier   |
|-------------------------------------|--------------------------------------------------------------------------------|--------|
| `rtl/chacha20_poly1305_aead.sv`     | Default AEAD top: encrypt / decrypt / AAD-only, single clock domain            | GPL    |
| `rtl/chacha20_core.sv`              | ChaCha20 stream cipher only (no MAC) — for protocols using Poly1305 separately | GPL    |
| `rtl/poly1305_core.sv`              | Poly1305 MAC only (no cipher) — for raw MAC use cases                          | GPL    |
| `vhdl_wrapper/chacha20_poly1305_vhdl.vhd` | VHDL-2008 entity wrapping the SV core for VHDL-only designs              | All    |

Premium tier (on roadmap, not yet shipped):
* DSP-aware Poly1305 multiplier (Xilinx DSP48 / Lattice 18x18 instantiation).
* Side-channel hardening (masked ChaCha20 + masked Poly1305).
* XChaCha20-Poly1305 (192-bit nonce variant).

## License

Dual-licensed:

- **GPL-3.0-or-later** for open-source projects. If your product links
  this RTL or its compiled bitstream, your project must also be
  GPL-3.0+.
- **Commercial license** for closed-source products. See
  [`LICENSE.md`](LICENSE.md) for the legal text and an FAQ.

If unsure which applies, read `LICENSE.md` or open an issue.

## Repository layout

```
rtl/                       RTL sources
  chacha20_qround.sv         combinational quarter round
  chacha20_block.sv          single-block engine
  chacha20_core.sv           streaming cipher
  poly1305_core.sv           MAC engine
  chacha20_poly1305_aead.sv  AEAD top-level
tb/                        testbench
  sim_main.cpp               C++ harness, RFC vectors, 5 test groups
  sim_main_chacha.cpp        ChaCha20 unit harness
  sim_main_poly.cpp          Poly1305 unit harness
  aead_tb.sv                 DUT wrapper + assertion + coverage bind
  aead_assertions.sv         SVA properties
  aead_cov.sv                functional coverage collector
  rfc8439_vectors.sv         RFC 8439 vectors (for non-Verilator simulators)
  random_vectors.h           generated cross-validation vectors
  gen_random_vectors.py      regenerator (uses `cryptography` lib)
vhdl_wrapper/              VHDL-2008 wrapper for mixed-language designs
scripts/                   helper scripts (synth_report.sh, vhdl_cosim.sh)
Makefile                   build/lint/sim/synth/synth_report/vhdl-test
```

## Contributing

Bug reports and patches welcome. Process:

1. File an issue first for non-trivial changes.
2. Fork, branch, and run `make lint test-all` locally.
3. Open a pull request with a description of what changed and why.
4. CI runs the full test suite plus `synth_report`; both must be green.

## Citation

```bibtex
@misc{chacha20poly1305-fpga-core,
  title  = {{chacha20poly1305-fpga-core}: a small dual-licensed ChaCha20-Poly1305 AEAD IP core in SystemVerilog},
  author = {Achour, Ayoub},
  year   = {2026},
  howpublished = {\url{https://github.com/ayoub-ac/chacha20poly1305-fpga-core}}
}
```

## References

- IETF RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols*, May 2018.
- D. J. Bernstein, *ChaCha, a variant of Salsa20*, 2008.
- D. J. Bernstein, *The Poly1305-AES message-authentication code*, 2005.
- IETF RFC 7905, *ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)*, 2016.

## Author

Ayoub Achour - [github.com/ayoub-ac](https://github.com/ayoub-ac)
