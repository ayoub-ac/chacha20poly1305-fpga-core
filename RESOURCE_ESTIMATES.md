# Resource estimates

Numbers below are from Yosys 0.x generic synthesis (`make synth_report`).
They are pre-place-and-route, with the design **flattened** before the
final stat pass. See `SYNTH_REPORT.md` for the most recent run; this
document explains what dominates the area and how to shrink it.

## Summary (post-Yosys, post-flatten, pre-PnR)

| Target                         | Comment |
|--------------------------------|---------|
| Lattice iCE40 UP5K             | LUT-heavy: the 130x128 Poly1305 multiplier maps to a tree of LUT4/CARRY cells. The UP5K has 5280 logic tiles, so this design fits comfortably but uses a meaningful fraction. |
| Lattice ECP5 LFE5UM-25         | LUT4 dominates. ECP5 generic synthesis in Yosys 0.x does not infer 18x18 multipliers; nextpnr-ecp5 packs tighter; vendor (Diamond) tighter still. |
| Xilinx Artix-7 XC7A35T         | Yosys-generic synthesis here counts LUT6 + CARRY4. Vivado synth_design will pack the multiplier into 4-5 DSP48E1 slices and the LUT count drops by ~50%. |
| Cyclone V 5CSEMA5F31C6         | Quartus folds the multiplier into 18x18 DSP cells; ALM count is much lower than the Yosys soft estimate. |
| Gowin GW1NR-9 (Tang Nano 9K)   | Not characterised here. Uses the 18-input multipliers in the GW1NR fabric; size comparable to ECP5 with DSP enabled. |

For exact LUT/FF/BRAM numbers run `make synth_report` and read
`SYNTH_REPORT.md`. The synthesis-comparison report is regenerated on
every CI build.

## What dominates the area

- **Poly1305 130x128 multiplier**: the single largest contributor.
  Implemented as a flat combinational `*` operator in `poly1305_core.sv`,
  which Yosys lowers into a tree of CARRY cells. This is intentionally
  written as `*` rather than as a hand-pipelined multiply so vendor
  flows (Vivado, Diamond, Quartus) can map it onto DSP slices /
  18x18 multipliers automatically. On the open Yosys flow, the soft
  multiplier is large but functional.
- **264-bit product register** plus the 130-bit accumulator and the
  128-bit r/s registers: ~520 FFs of state for Poly1305.
- **ChaCha20 state**: 16 x 32 = 512 FFs for the working state, plus
  another 512 for the original-state copy needed by the final add at
  the end of the block function.
- **Quarter-round**: 4 32-bit additions + a 32-bit XOR + a 32-bit
  rotate per QR. Combinational; about 200 LUT4 cells per `qround`
  instance on iCE40.
- **ChaCha20 step counter**: 7 bits (0..79). Negligible.
- **AEAD top-level FSM**: ~8 states + slice index counter + 64-bit
  aad_len_q + 64-bit ct_len_q + 512-bit emit_buf_q. ~700 FFs total.

## What you can do to shrink it

- **Enable DSP inference**: with `synth_xilinx -dsp` or by running
  Vivado natively, the Poly1305 multiplier folds into DSP48 slices
  and the LUT count drops sharply. Premium tier ships hand-instantiated
  DSP wrappers for Xilinx 7-series and UltraScale.
- **Externalise the ChaCha20 working state to a 32-deep BRAM**: with
  `(* ram_style = "block" *)` (Vivado) or `(* ram_style = "distributed"
  *)` (Yosys / Lattice), the 32-deep x 32-bit state can drop into a
  small block RAM, reclaiming ~512 FFs at a cost of ~1 BRAM. Available
  in the Premium tier.
- **Share one chacha20_block instance** between the Poly1305-key-derive
  (counter=0) path and the bulk-data (counter≥1) path. Saves about a
  third of the ChaCha20 area at the cost of a slightly more complex
  FSM. Premium tier.
- **Multi-cycle Poly1305 multiplier**: split the 130x128 multiply
  across 5 cycles using a 32x32 schoolbook accumulator. Cuts the
  multiplier LUT count by ~3-4x on the open-source flow at a cost of
  4x latency for the MAC step. Premium tier.

## What you can do to push throughput

- **Pipelined ChaCha20 block engine** (Premium): unroll the 80
  quarter-round loop into a 5-stage pipeline. Steady-state throughput
  becomes 1 keystream block every 16 cycles instead of every 83.
- **Cache one keystream block ahead**: prefetch the next ChaCha20
  block while the current one is being XORed and consumed. Hides the
  84-cycle keystream generation latency behind the data flow on long
  messages.

## Frequency

- iCE40 UP5K, default toolchain (Yosys + nextpnr), no constraints: limited
  by the carry-chain depth in the Poly1305 multiplier (~30-40 MHz on
  generic synth).
- ECP5: ~80-100 MHz on generic synth without DSP; faster with vendor
  flow.
- Artix-7 -1 speed grade: ~100 MHz typical with Yosys, easily 200 MHz
  with Vivado + DSP. The combinational path through the 130x128
  multiplier is the critical path.
- Cyclone V: similar to Artix-7 with DSP enabled.

The throughput is gated by both the cipher (1 keystream block / 83
cycles) and the MAC (1 chunk / 5 cycles). For a 1-KB message, the AEAD
finishes in roughly: 83 (poly key) + 16 * (83 + 4 * 5) = ~1750 cycles,
i.e. ~9 cycles per byte ignoring the AAD path. At 100 MHz this gives
about 90 Mbps; the pipelined Premium variant pushes this to ~500 Mbps
on Artix-7.

## Power

Ballpark: 15-30 mW dynamic on iCE40 UP5K at 30 MHz, depending on data
activity. Static power is dominated by the FPGA itself.

## How to reproduce

```bash
make synth_report
```

This runs Yosys with `synth_ice40`, `synth_ecp5` (with `-abc9`), and
`synth_xilinx`, then `flatten`, then `stat`, and writes the result to
`SYNTH_REPORT.md`. Vendor flows (Vivado, Quartus) are detected
automatically when on PATH.

For end-to-end place-and-route numbers (post-PnR LUT counts and timing),
run the vendor flow:
- iCE40 / ECP5: `nextpnr-ice40` / `nextpnr-ecp5` with Yosys output.
- Xilinx: Vivado with a project pointing at the `rtl/` files.
- Lattice Diamond / Radiant: project with `rtl/` added.
- Quartus: project with `rtl/` added.
