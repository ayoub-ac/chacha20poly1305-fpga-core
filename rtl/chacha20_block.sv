// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// ChaCha20 block function. Produces one 512-bit keystream block from
// (key, nonce, counter).
//
// Reference: RFC 8439 (May 2018), Section 2.3 / 2.3.1.
//
// Algorithm (RFC 8439 §2.3.1):
//
//   state = constants(4) || key(8) || counter(1) || nonce(3)   // 16 x 32-bit
//   working = state
//   for i in 0..9:                                             // 20 rounds
//       column round  : QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
//       diagonal round: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
//   keystream_word[i] = working[i] + state[i]                  // mod 2^32
//
// Constants ("expand 32-byte k"):
//   state[0..3] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
//
// Architecture:
//   * One quarter-round per cycle. 8 QRs per double-round, 10 double-rounds
//     = 80 quarter-round cycles + 1 setup + 1 add + 1 done = 83 cycles per
//     block.
//   * The state vector is held in a 16x32 register file. The qround
//     instance is fed by a 4:1 mux selecting which 4 lanes participate this
//     cycle.
//   * Endianness: words are stored little-endian as on-the-wire bytes
//     (RFC 8439 §2.3 "the 4-byte input block is treated as a 4-byte little
//     endian integer"). Byte/word packing happens in chacha20_core.sv.
//
// Handshake:
//   * Pulse start_i with key_i / nonce_i / counter_i held valid for one
//     cycle. Core drops ready_o until the keystream block is ready.
//   * keystream_o is held with valid_o = 1 until the consumer pulses
//     ack_i, after which valid_o drops on the next cycle.

module chacha20_block (
  input  logic         clk_i,
  input  logic         rst_ni,

  input  logic         start_i,
  input  logic [255:0] key_i,         // 8 x 32-bit, little-endian word order
  input  logic [95:0]  nonce_i,       // 3 x 32-bit
  input  logic [31:0]  counter_i,
  output logic         ready_o,

  output logic [511:0] keystream_o,   // 16 x 32-bit, word i in [511 - 32*i -: 32]
  output logic         valid_o,
  input  logic         ack_i
);

  // ChaCha20 sigma constants ("expand 32-byte k" interpreted as four 32-bit
  // little-endian words). RFC 8439 §2.3.
  localparam logic [31:0] C0 = 32'h61707865;
  localparam logic [31:0] C1 = 32'h3320646e;
  localparam logic [31:0] C2 = 32'h79622d32;
  localparam logic [31:0] C3 = 32'h6b206574;

  typedef enum logic [2:0] {
    S_IDLE   = 3'd0,
    S_LOAD   = 3'd1,
    S_RUN    = 3'd2,  // 80 quarter rounds (10 double-rounds, 8 QR each)
    S_ADD    = 3'd3,  // working += state
    S_DONE   = 3'd4   // valid_o asserted, waiting for ack_i
  } state_e;

  state_e state_q, state_d;

  // Step counter: 0..79 over the 80 quarter rounds.
  logic [6:0] step_q, step_d;

  // 16 x 32-bit state (the original "state") and working register. We need
  // both because the final add is working + original_state.
  logic [31:0] state_q_arr   [0:15];
  logic [31:0] state_d_arr   [0:15];
  logic [31:0] working_q_arr [0:15];
  logic [31:0] working_d_arr [0:15];

  // ------------------------------------------------------------------
  // Quarter-round lane selection (RFC 8439 §2.3.1). Each step picks 4
  // working lanes (a, b, c, d) and feeds them to the qround block. The
  // 4 results overwrite those lanes.
  //
  // Step layout: each double-round = 8 QRs. Within a double-round:
  //   QR 0..3 = column rounds:
  //     0 -> (0, 4,  8, 12)
  //     1 -> (1, 5,  9, 13)
  //     2 -> (2, 6, 10, 14)
  //     3 -> (3, 7, 11, 15)
  //   QR 4..7 = diagonal rounds:
  //     4 -> (0, 5, 10, 15)
  //     5 -> (1, 6, 11, 12)
  //     6 -> (2, 7,  8, 13)
  //     7 -> (3, 4,  9, 14)
  // ------------------------------------------------------------------

  logic [3:0] sel_a, sel_b, sel_c, sel_d;

  always_comb begin
    // qr_in_double = step_q[2:0] (step % 8)
    unique case (step_q[2:0])
      3'd0: begin sel_a = 4'd0;  sel_b = 4'd4;  sel_c = 4'd8;  sel_d = 4'd12; end
      3'd1: begin sel_a = 4'd1;  sel_b = 4'd5;  sel_c = 4'd9;  sel_d = 4'd13; end
      3'd2: begin sel_a = 4'd2;  sel_b = 4'd6;  sel_c = 4'd10; sel_d = 4'd14; end
      3'd3: begin sel_a = 4'd3;  sel_b = 4'd7;  sel_c = 4'd11; sel_d = 4'd15; end
      3'd4: begin sel_a = 4'd0;  sel_b = 4'd5;  sel_c = 4'd10; sel_d = 4'd15; end
      3'd5: begin sel_a = 4'd1;  sel_b = 4'd6;  sel_c = 4'd11; sel_d = 4'd12; end
      3'd6: begin sel_a = 4'd2;  sel_b = 4'd7;  sel_c = 4'd8;  sel_d = 4'd13; end
      3'd7: begin sel_a = 4'd3;  sel_b = 4'd4;  sel_c = 4'd9;  sel_d = 4'd14; end
      default: begin sel_a = 4'd0; sel_b = 4'd0; sel_c = 4'd0; sel_d = 4'd0; end
    endcase
  end

  logic [31:0] qa_in, qb_in, qc_in, qd_in;
  logic [31:0] qa_out, qb_out, qc_out, qd_out;

  assign qa_in = working_q_arr[sel_a];
  assign qb_in = working_q_arr[sel_b];
  assign qc_in = working_q_arr[sel_c];
  assign qd_in = working_q_arr[sel_d];

  chacha20_qround u_qr (
    .a_i (qa_in), .b_i (qb_in), .c_i (qc_in), .d_i (qd_in),
    .a_o (qa_out), .b_o (qb_out), .c_o (qc_out), .d_o (qd_out)
  );

  // ------------------------------------------------------------------
  // FSM
  // ------------------------------------------------------------------
  always_comb begin
    state_d = state_q;
    step_d  = step_q;
    for (int i = 0; i < 16; i++) begin
      state_d_arr[i]   = state_q_arr[i];
      working_d_arr[i] = working_q_arr[i];
    end

    case (state_q)
      // ----------------------------------------------------------------
      S_IDLE: begin
        if (start_i) begin
          // RFC 8439 §2.3: state layout
          //   state[0..3]   = constants
          //   state[4..11]  = key[0..7]
          //   state[12]     = block counter
          //   state[13..15] = nonce[0..2]
          state_d_arr[0]  = C0;
          state_d_arr[1]  = C1;
          state_d_arr[2]  = C2;
          state_d_arr[3]  = C3;
          for (int i = 0; i < 8; i++) begin
            state_d_arr[4 + i] = key_i[32*i +: 32];
          end
          state_d_arr[12] = counter_i;
          for (int i = 0; i < 3; i++) begin
            state_d_arr[13 + i] = nonce_i[32*i +: 32];
          end
          // working <- state
          working_d_arr[0]  = C0;
          working_d_arr[1]  = C1;
          working_d_arr[2]  = C2;
          working_d_arr[3]  = C3;
          for (int i = 0; i < 8; i++) begin
            working_d_arr[4 + i] = key_i[32*i +: 32];
          end
          working_d_arr[12] = counter_i;
          for (int i = 0; i < 3; i++) begin
            working_d_arr[13 + i] = nonce_i[32*i +: 32];
          end
          step_d  = 7'd0;
          state_d = S_RUN;
        end
      end

      // ----------------------------------------------------------------
      S_RUN: begin
        // Apply this quarter round
        working_d_arr[sel_a] = qa_out;
        working_d_arr[sel_b] = qb_out;
        working_d_arr[sel_c] = qc_out;
        working_d_arr[sel_d] = qd_out;

        if (step_q == 7'd79) begin
          state_d = S_ADD;
        end else begin
          step_d = step_q + 7'd1;
        end
      end

      // ----------------------------------------------------------------
      S_ADD: begin
        // RFC 8439 §2.3.1: keystream[i] = working[i] + original_state[i]
        for (int i = 0; i < 16; i++) begin
          working_d_arr[i] = working_q_arr[i] + state_q_arr[i];
        end
        state_d = S_DONE;
      end

      // ----------------------------------------------------------------
      S_DONE: begin
        if (ack_i) state_d = S_IDLE;
      end

      // S_LOAD reserved for future split; currently unused
      default: state_d = S_IDLE;
    endcase
  end

  // ------------------------------------------------------------------
  // Registers
  // ------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      state_q <= S_IDLE;
      step_q  <= 7'd0;
      for (int i = 0; i < 16; i++) begin
        state_q_arr[i]   <= 32'd0;
        working_q_arr[i] <= 32'd0;
      end
    end else begin
      state_q <= state_d;
      step_q  <= step_d;
      for (int i = 0; i < 16; i++) begin
        state_q_arr[i]   <= state_d_arr[i];
        working_q_arr[i] <= working_d_arr[i];
      end
    end
  end

  // ------------------------------------------------------------------
  // Outputs
  // ------------------------------------------------------------------
  assign ready_o = (state_q == S_IDLE);
  assign valid_o = (state_q == S_DONE);

  // keystream_o packs 16 little-endian 32-bit words. Word index i lives in
  // bits [32*i + 31 : 32*i] when interpreted as little-endian byte stream,
  // which matches RFC 8439 §2.3 "serializing the state".
  // For the on-the-wire byte order (byte 0 = state[0] LSB), we want:
  //   keystream_o[7:0]   = state[0][7:0]
  //   keystream_o[15:8]  = state[0][15:8]
  //   ...
  // i.e. word i occupies bits [32*i + 31 : 32*i].
  generate
    for (genvar gi = 0; gi < 16; gi++) begin : g_pack
      assign keystream_o[32*gi +: 32] = working_q_arr[gi];
    end
  endgenerate

endmodule
