// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// ChaCha20 quarter round, combinational.
//
// Reference: RFC 8439 (May 2018), Section 2.1.
//
//   QUARTERROUND(a, b, c, d):
//     a += b; d ^= a; d <<<= 16;
//     c += d; b ^= c; b <<<= 12;
//     a += b; d ^= a; d <<<=  8;
//     c += d; b ^= c; b <<<=  7;
//
// All operations are 32-bit unsigned, additions are mod 2^32, "<<<" is a
// rotate-left on a 32-bit word.
//
// This block is purely combinational — the consumer (chacha20_block.sv)
// instantiates it inside a sequential FSM that drives one quarter round per
// cycle.

module chacha20_qround (
  input  logic [31:0] a_i,
  input  logic [31:0] b_i,
  input  logic [31:0] c_i,
  input  logic [31:0] d_i,
  output logic [31:0] a_o,
  output logic [31:0] b_o,
  output logic [31:0] c_o,
  output logic [31:0] d_o
);

  function automatic logic [31:0] rotl(input logic [31:0] x, input int n);
    rotl = (x << n) | (x >> (32 - n));
  endfunction

  logic [31:0] a1, b1, c1, d1;
  logic [31:0] a2, b2, c2, d2;
  logic [31:0] a3, b3, c3, d3;

  // a += b; d ^= a; d <<<= 16
  assign a1 = a_i + b_i;
  assign d1 = rotl(d_i ^ a1, 16);
  assign b1 = b_i;
  assign c1 = c_i;

  // c += d; b ^= c; b <<<= 12
  assign c2 = c1 + d1;
  assign b2 = rotl(b1 ^ c2, 12);
  assign a2 = a1;
  assign d2 = d1;

  // a += b; d ^= a; d <<<= 8
  assign a3 = a2 + b2;
  assign d3 = rotl(d2 ^ a3, 8);
  assign b3 = b2;
  assign c3 = c2;

  // c += d; b ^= c; b <<<= 7
  assign c_o = c3 + d3;
  assign b_o = rotl(b3 ^ c_o, 7);
  assign a_o = a3;
  assign d_o = d3;

endmodule
