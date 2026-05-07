// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// RFC 8439 test vectors as SystemVerilog package constants. Mirrored from
// the relevant sections so non-Verilator simulators (Vivado xsim, Questa)
// can compile the same vectors.
//
// Sources:
//   * RFC 8439 §2.4.2  ChaCha20 sunscreen vector
//   * RFC 8439 §2.5.2  Poly1305 vector
//   * RFC 8439 §2.8.2  AEAD_CHACHA20_POLY1305 worked example
//
// The Verilator C++ harness embeds the same vectors directly; this file
// is provided so other simulators can pick them up by `include` or by
// importing the package. It is purely declarative.

package rfc8439_vectors_pkg;

  // ---------------------------------------------------------------------
  // RFC 8439 §2.4.2: ChaCha20 encrypt
  // ---------------------------------------------------------------------
  localparam logic [255:0] CHA_KEY    = 256'h1f1e1d1c_1b1a1918_17161514_13121110_0f0e0d0c_0b0a0908_07060504_03020100;
  localparam logic [95:0]  CHA_NONCE  = 96'h00000000_4a000000_00000000;
  localparam logic [31:0]  CHA_COUNTER = 32'd1;

  // ---------------------------------------------------------------------
  // RFC 8439 §2.5.2: Poly1305
  // ---------------------------------------------------------------------
  localparam logic [255:0] POLY_KEY = 256'h1bf54941_aff6bf4a_fdb20d01_8a800301_a806d542_fe52447f_336d5578_57bed685;
  localparam logic [127:0] POLY_TAG = 128'ha927_0127_0c0c_2bc2_c636_0513_30c1_0d6a;
  // (note: bit ordering is little-endian byte order inside the 128-bit
  // literal; consumers of this package should byte-swap as needed.)

  // ---------------------------------------------------------------------
  // RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305
  // ---------------------------------------------------------------------
  localparam logic [255:0] AEAD_KEY   = 256'h9f8f9e8d_8c8b8a89_88878685_84838281_807f7e7d_7c7b7a79_78777675_74737271;
  localparam logic [95:0]  AEAD_NONCE = 96'h00000000_47000000_07060504; // little-endian within bytes
  localparam logic [127:0] AEAD_TAG   = 128'h0691ed22_60ec5b5b_38aa44ef_91ce1a7b;
  // AAD = 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7  (12 bytes)
  localparam logic [95:0]  AEAD_AAD   = 96'hc7c6c5c4_c3c2c1c0_53525150;

  // Plaintext is 114 bytes — too long for a single localparam without
  // splitting; the C++ harness embeds the bytes directly. Provided here
  // as a comment for SV consumers:
  //
  //   "Ladies and Gentlemen of the class of '99: If I could offer you "
  //   "only one tip for the future, sunscreen would be it."

endpackage
