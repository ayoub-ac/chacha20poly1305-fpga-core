// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Top-level testbench wrapper for chacha20_core (streaming).
// Stimulus is driven from tb/sim_main_chacha.cpp.

module chacha20_tb (
  input  logic         clk_i,
  input  logic         rst_ni,

  input  logic         init_i,
  input  logic [255:0] key_i,
  input  logic [95:0]  nonce_i,
  input  logic [31:0]  start_counter_i,

  input  logic         data_valid_i,
  input  logic [511:0] data_i,
  input  logic         last_i,
  input  logic [6:0]   byte_count_i,
  output logic         data_ready_o,

  output logic         result_valid_o,
  output logic [511:0] result_o,
  output logic         result_last_o,
  output logic [6:0]   result_byte_count_o,
  input  logic         result_ready_i
);

  chacha20_core u_dut (
    .clk_i              (clk_i),
    .rst_ni             (rst_ni),
    .init_i             (init_i),
    .key_i              (key_i),
    .nonce_i            (nonce_i),
    .start_counter_i    (start_counter_i),
    .data_valid_i       (data_valid_i),
    .data_i             (data_i),
    .last_i             (last_i),
    .byte_count_i       (byte_count_i),
    .data_ready_o       (data_ready_o),
    .result_valid_o     (result_valid_o),
    .result_o           (result_o),
    .result_last_o      (result_last_o),
    .result_byte_count_o(result_byte_count_o),
    .result_ready_i     (result_ready_i)
  );

endmodule
