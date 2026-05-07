# VHDL wrapper

`chacha20_poly1305_vhdl.vhd` is a thin VHDL-2008 entity that re-exposes
the SystemVerilog `chacha20_poly1305_aead` module under a VHDL-friendly
interface. Use it from a VHDL design that does not want to touch
SystemVerilog directly.

## Status

**Wrapper only.** The AEAD datapath (ChaCha20 quarter rounds, Poly1305
multiply, the AEAD FSM) lives in `rtl/*.sv` and is instantiated as a
SystemVerilog black-box. Mixed-language elaboration is supported by every
commercial simulator and synthesiser the core has been tested against.

A pure VHDL re-implementation of the core is on the roadmap (Premium
tier). Until then, treat this directory as a binding layer, not as a
second implementation.

## Usage

### Vivado / Quartus / Diamond

Add both the SystemVerilog files and `chacha20_poly1305_vhdl.vhd` to the
same project library (`work` is fine). The toolchain resolves the SV
component automatically:

```tcl
# Vivado
read_verilog -sv {rtl/chacha20_qround.sv rtl/chacha20_block.sv \
                  rtl/chacha20_core.sv rtl/poly1305_core.sv \
                  rtl/chacha20_poly1305_aead.sv}
read_vhdl -vhdl2008 vhdl_wrapper/chacha20_poly1305_vhdl.vhd
```

### ModelSim / Questa / Aldec

```
vlog -sv rtl/chacha20_qround.sv rtl/chacha20_block.sv \
        rtl/chacha20_core.sv rtl/poly1305_core.sv \
        rtl/chacha20_poly1305_aead.sv
vcom -2008 vhdl_wrapper/chacha20_poly1305_vhdl.vhd
```

### GHDL + Verilator (open-source co-sim)

The provided `make vhdl-test` target wraps a build-only smoke test of
both halves; run it from the repository root:

```
make vhdl-test
```

The target is a no-op (with a notice) if `ghdl` is not on `$PATH`.

## Instantiation example

```vhdl
library ieee;
  use ieee.std_logic_1164.all;

entity my_design is end entity;
architecture rtl of my_design is
  signal clk, rstn : std_logic;
  signal init_i, aad_valid_i, aad_last_i, aad_ready_o : std_logic;
  signal data_valid_i, data_last_i, data_ready_o      : std_logic;
  signal result_valid_o, result_last_o, result_ready_i : std_logic;
  signal finalize_i, tag_valid_o, tag_match_o          : std_logic;
  signal init_ready_o                                  : std_logic;
  signal key_i, expected_tag_i                         : std_logic_vector(255 downto 0);
  signal nonce_i      : std_logic_vector( 95 downto 0);
  signal mode_i       : std_logic_vector(  1 downto 0);
  signal aad_chunk_i  : std_logic_vector(127 downto 0);
  signal data_i, result_o : std_logic_vector(511 downto 0);
  signal tag_o, expected_tag_i_short : std_logic_vector(127 downto 0);
  signal aad_bcb      : std_logic_vector(  4 downto 0);
  signal data_bcb, result_bcb : std_logic_vector(  6 downto 0);
begin
  u_aead : entity work.chacha20_poly1305_vhdl
    port map (
      clk_i => clk,             rst_ni => rstn,
      init_i => init_i,         key_i => key_i(255 downto 0),
      nonce_i => nonce_i,       mode_i => mode_i,
      init_ready_o => init_ready_o,
      aad_valid_i => aad_valid_i,
      aad_chunk_i => aad_chunk_i,
      aad_byte_count_i => aad_bcb,
      aad_last_i => aad_last_i, aad_ready_o => aad_ready_o,
      data_valid_i => data_valid_i, data_i => data_i,
      data_byte_count_i => data_bcb, data_last_i => data_last_i,
      data_ready_o => data_ready_o,
      result_valid_o => result_valid_o, result_o => result_o,
      result_byte_count_o => result_bcb,
      result_last_o => result_last_o, result_ready_i => result_ready_i,
      finalize_i => finalize_i, tag_o => tag_o, tag_valid_o => tag_valid_o,
      expected_tag_i => expected_tag_i_short, tag_match_o => tag_match_o
    );
end architecture;
```

## What this wrapper does NOT change

* Latency, throughput, area: identical to `chacha20_poly1305_aead.sv`.
  There is no additional pipeline stage.
* Endianness: byte 0 of every wide bus is the LSB of the corresponding
  word, matching the on-the-wire RFC 8439 byte order.
* Reset polarity: still active-low synchronous (`rst_ni`).
