// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Poly1305 MAC core. Streaming, one 16-byte chunk per multiply.
//
// Reference: RFC 8439 (May 2018), Section 2.5.1.
//
// Algorithm (RFC 8439 §2.5.1):
//
//   key = (r, s)         // 256 bits, r=lower 128, s=upper 128
//   clamp(r):            // mask 0x0ffffffc0ffffffc0ffffffc0fffffff
//   acc = 0
//   for each 16-byte chunk c with `n` valid bytes (1..16):
//       n_i = read_le_n_bytes(c, n) | (1 << (8*n))     // append 0x01 byte
//       acc = ((acc + n_i) * r) mod (2^130 - 5)
//   tag = (acc + s) mod 2^128
//
// Implementation strategy:
//   * acc is held in a 131-bit register (one extra bit of headroom).
//   * r (after clamping) is held in 128 bits (top nibble of every 32-bit
//     limb is zeroed by the clamp; the result is < 2^124).
//   * Multiplication acc * r is computed combinationally as a flat
//     (131x128) product => 259 bits.
//   * Modular reduction by p = 2^130 - 5 uses the identity 2^130 ≡ 5 (mod p):
//     X = X_hi * 2^130 + X_lo  =>  X mod p == X_lo + 5*X_hi (mod p).
//     Three fold cycles always suffice given the input bounds. The result
//     of the third fold fits in <= 131 bits (and is < 2^130 + 5 in
//     practice, which is canonicalised at finalize-time).
//
// FSM cycles per absorb:  ADD (1) + MUL (1) + FOLD1 (1) + FOLD2 (1) + FOLD3 (1) = 5
// FSM cycles for finalize: FINAL (1) + DONE (output pulse)
//
// Handshake:
//   * init_i pulses with key_i held valid; clamps r, captures s, zeroes acc.
//   * For each chunk: pulse data_valid_i with chunk_i (16 bytes, byte 0 in
//     LSB) and chunk_byte_count_i (1..16). data_ready_o falls during the
//     5-cycle absorb, then re-asserts.
//   * finalize_i pulses to compute tag = (acc mod p) + s mod 2^128;
//     tag_valid_o asserts and stays high until init_i is taken again.

module poly1305_core (
  input  logic         clk_i,
  input  logic         rst_ni,

  input  logic         init_i,
  input  logic [255:0] key_i,         // r = key_i[127:0], s = key_i[255:128]
  output logic         init_ready_o,

  input  logic         data_valid_i,
  input  logic [127:0] chunk_i,
  input  logic [4:0]   chunk_byte_count_i,
  output logic         data_ready_o,

  input  logic         finalize_i,
  output logic [127:0] tag_o,
  output logic         tag_valid_o
);

  // ------------------------------------------------------------------
  // Constants
  // ------------------------------------------------------------------
  // Clamp mask for r (RFC 8439 §2.5):
  //   bytes 3,7,11,15 are masked with 0x0F
  //   bytes 4,8,12     are masked with 0xFC
  // In little-endian limb form: top nibble of each 32-bit word is zero,
  // and the low 2 bits of three of them are zero.
  localparam logic [127:0] R_CLAMP_MASK =
    128'h0ffffffc_0ffffffc_0ffffffc_0fffffff;

  // ------------------------------------------------------------------
  // Session registers
  // ------------------------------------------------------------------
  logic [127:0] r_q;
  logic [127:0] s_q;
  logic [130:0] acc_q;     // 131 bits of headroom
  logic         have_key_q;

  // Wide product register (used through the fold steps)
  logic [263:0] prod_q;

  // Pending n_i value (130 bits to hold "+1 byte" up to position 128)
  logic [129:0] n_pending_q;

  // ------------------------------------------------------------------
  // FSM
  // ------------------------------------------------------------------
  typedef enum logic [3:0] {
    PS_IDLE  = 4'd0,
    PS_ADD   = 4'd1,
    PS_MUL   = 4'd2,
    PS_FOLD1 = 4'd3,
    PS_FOLD2 = 4'd4,
    PS_FOLD3 = 4'd5,
    PS_FINAL = 4'd6,
    PS_DONE  = 4'd7
  } pstate_e;

  pstate_e pstate_q, pstate_d;

  // ------------------------------------------------------------------
  // Combinational helpers
  // ------------------------------------------------------------------
  function automatic logic [129:0] build_n(input logic [127:0] chunk,
                                           input logic [4:0]   bcb);
    logic [127:0] mask;
    logic [129:0] hi_bit;
    if (bcb >= 5'd16) begin
      mask   = {128{1'b1}};
      hi_bit = 130'd1 << 128;
    end else begin
      mask   = (128'h1 << (bcb * 8)) - 128'h1;
      hi_bit = 130'd1 << (bcb * 8);
    end
    build_n = ({2'b0, chunk & mask}) | hi_bit;
  endfunction

  // fold step:
  //   x is a 264-bit value. Split as x = x_hi * 2^130 + x_lo with x_lo
  //   the low 130 bits and x_hi the rest. Result: x_lo + 5*x_hi
  //   (still 264 bits to absorb the ~3-bit growth on x_hi*5).
  function automatic logic [263:0] fold_step(input logic [263:0] x);
    logic [129:0] lo;
    logic [133:0] hi;
    logic [263:0] lo_ext;
    logic [263:0] hi5;
    lo     = x[129:0];
    hi     = x[263:130];
    lo_ext = {134'd0, lo};
    hi5    = {130'd0, hi} + ({130'd0, hi} << 2);  // hi * 5 = hi + 4*hi
    fold_step = lo_ext + hi5;
  endfunction

  // ------------------------------------------------------------------
  // FSM next-state
  // ------------------------------------------------------------------
  logic [130:0] acc_d;
  logic [263:0] prod_d;
  logic [129:0] n_pending_d;
  logic [127:0] r_d, s_d;
  logic         have_key_d;

  always_comb begin
    pstate_d    = pstate_q;
    acc_d       = acc_q;
    prod_d      = prod_q;
    n_pending_d = n_pending_q;
    r_d         = r_q;
    s_d         = s_q;
    have_key_d  = have_key_q;

    case (pstate_q)
      // ----------------------------------------------------------------
      PS_IDLE: begin
        if (init_i) begin
          r_d        = key_i[127:0] & R_CLAMP_MASK;
          s_d        = key_i[255:128];
          acc_d      = 131'd0;
          have_key_d = 1'b1;
        end else if (data_valid_i && have_key_q) begin
          n_pending_d = build_n(chunk_i, chunk_byte_count_i);
          pstate_d    = PS_ADD;
        end else if (finalize_i && have_key_q) begin
          pstate_d = PS_FINAL;
        end
      end

      // ----------------------------------------------------------------
      PS_ADD: begin
        // acc <- acc + n_pending, register
        acc_d    = acc_q + {1'b0, n_pending_q};
        pstate_d = PS_MUL;
      end

      // ----------------------------------------------------------------
      PS_MUL: begin
        // prod <- acc * r  (131 * 128 = 259 bits, store in 264)
        prod_d   = {133'd0, acc_q} * {136'd0, r_q};
        pstate_d = PS_FOLD1;
      end

      // ----------------------------------------------------------------
      PS_FOLD1: begin
        prod_d   = fold_step(prod_q);
        pstate_d = PS_FOLD2;
      end

      // ----------------------------------------------------------------
      PS_FOLD2: begin
        prod_d   = fold_step(prod_q);
        pstate_d = PS_FOLD3;
      end

      // ----------------------------------------------------------------
      PS_FOLD3: begin
        // After 3 folds prod is bounded by 2^130 + small slack. Place into
        // the 131-bit accumulator (the small extra above 2^130 will be
        // absorbed at finalize).
        acc_d    = prod_q[130:0];
        pstate_d = PS_IDLE;
      end

      // ----------------------------------------------------------------
      PS_FINAL: begin
        // Freeze: canonicalise acc to be < p = 2^130 - 5.
        // acc + 5: if it overflows 2^130 then canonical = (acc+5) mod 2^130;
        //          else canonical = acc.
        prod_d   = {133'd0, acc_q} + 264'd5;
        pstate_d = PS_DONE;
      end

      // ----------------------------------------------------------------
      PS_DONE: begin
        if (init_i) begin
          r_d        = key_i[127:0] & R_CLAMP_MASK;
          s_d        = key_i[255:128];
          acc_d      = 131'd0;
          have_key_d = 1'b1;
          pstate_d   = PS_IDLE;
        end
      end

      default: pstate_d = PS_IDLE;
    endcase
  end

  // ------------------------------------------------------------------
  // Registers
  // ------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      pstate_q    <= PS_IDLE;
      r_q         <= 128'd0;
      s_q         <= 128'd0;
      acc_q       <= 131'd0;
      prod_q      <= 264'd0;
      n_pending_q <= 130'd0;
      have_key_q  <= 1'b0;
    end else begin
      pstate_q    <= pstate_d;
      r_q         <= r_d;
      s_q         <= s_d;
      acc_q       <= acc_d;
      prod_q      <= prod_d;
      n_pending_q <= n_pending_d;
      have_key_q  <= have_key_d;
    end
  end

  // ------------------------------------------------------------------
  // Outputs
  // ------------------------------------------------------------------
  assign init_ready_o = (pstate_q == PS_IDLE) || (pstate_q == PS_DONE);
  assign data_ready_o = (pstate_q == PS_IDLE) && have_key_q;
  assign tag_valid_o  = (pstate_q == PS_DONE);

  // Tag computation: combinational, valid when pstate_q == PS_DONE.
  //   acc_canonical = (acc + 5 >= 2^130) ? (acc + 5) mod 2^130 : acc
  // The "acc + 5" was registered into prod_q during PS_FINAL.
  logic [130:0] canonical;
  assign canonical = (prod_q[130]) ? prod_q[130:0]      // freeze fired
                                   : acc_q;
  // tag = (canonical mod 2^128) + s mod 2^128
  assign tag_o = canonical[127:0] + s_q;

endmodule
