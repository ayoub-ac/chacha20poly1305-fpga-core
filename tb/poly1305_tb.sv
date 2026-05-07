// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Top-level testbench wrapper for poly1305_core. Stimulus is driven from the
// C++ harness (tb/sim_main_poly.cpp); this module re-exports the DUT ports.

module poly1305_tb (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic         init_i,
  input  logic [255:0] key_i,
  output logic         init_ready_o,
  input  logic         data_valid_i,
  input  logic [127:0] chunk_i,
  input  logic [4:0]   chunk_byte_count_i,
  output logic         data_ready_o,
  input  logic         finalize_i,
  output logic [127:0] tag_o,
  output logic         tag_valid_o
);

  poly1305_core u_dut (
    .clk_i              (clk_i),
    .rst_ni             (rst_ni),
    .init_i             (init_i),
    .key_i              (key_i),
    .init_ready_o       (init_ready_o),
    .data_valid_i       (data_valid_i),
    .chunk_i            (chunk_i),
    .chunk_byte_count_i (chunk_byte_count_i),
    .data_ready_o       (data_ready_o),
    .finalize_i         (finalize_i),
    .tag_o              (tag_o),
    .tag_valid_o        (tag_valid_o)
  );

endmodule
