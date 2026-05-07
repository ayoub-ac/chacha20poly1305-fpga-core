// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// ChaCha20 streaming core. Wraps chacha20_block to encrypt / decrypt a
// stream of 64-byte blocks. Encryption and decryption are identical (XOR
// of plaintext with keystream), so the same datapath services both.
//
// Reference: RFC 8439 (May 2018), Section 2.4 "The ChaCha20 Encryption
// Algorithm".
//
// Streaming model:
//   * Caller asserts init_i with key_i / nonce_i / start_counter_i for one
//     cycle to start a new message. The keystream is produced lazily: the
//     first chacha20_block is launched the first cycle data_valid_i is
//     accepted.
//   * For each input data block:
//       - Caller presents data_i (64 bytes = 512 bits, byte 0 in LSB) and
//         data_valid_i.
//       - Core XORs against the current keystream and emits result_o.
//       - For the LAST block of a message, last_i must be high together
//         with data_valid_i.  byte_count_i (1..64) tells the core how many
//         valid bytes the last block has.
//
// Counter: starts at start_counter_i (typically 1 for AEAD where block 0 is
// the Poly1305 key derivation), increments by one per 64-byte block.
//
// This module exposes a streaming AXI-stream-style data interface but does
// NOT implement Poly1305: see chacha20_poly1305_aead.sv for the AEAD top.

module chacha20_core (
  input  logic         clk_i,
  input  logic         rst_ni,

  // Session setup
  input  logic         init_i,
  input  logic [255:0] key_i,
  input  logic [95:0]  nonce_i,
  input  logic [31:0]  start_counter_i,

  // Streaming data in
  input  logic         data_valid_i,
  input  logic [511:0] data_i,         // 64-byte block, byte 0 in [7:0]
  input  logic         last_i,         // last block of message
  input  logic [6:0]   byte_count_i,   // valid bytes in last block (1..64)
  output logic         data_ready_o,

  // Streaming data out
  output logic         result_valid_o,
  output logic [511:0] result_o,
  output logic         result_last_o,
  output logic [6:0]   result_byte_count_o,
  input  logic         result_ready_i
);

  // ------------------------------------------------------------------
  // Session registers
  // ------------------------------------------------------------------
  logic [255:0] sess_key_q;
  logic [95:0]  sess_nonce_q;
  logic [31:0]  counter_q;
  logic         have_session_q;

  // ------------------------------------------------------------------
  // Block engine
  // ------------------------------------------------------------------
  logic         blk_start;
  logic         blk_ready;
  logic [511:0] blk_keystream;
  logic         blk_valid;
  logic         blk_ack;

  chacha20_block u_block (
    .clk_i      (clk_i),
    .rst_ni     (rst_ni),
    .start_i    (blk_start),
    .key_i      (sess_key_q),
    .nonce_i    (sess_nonce_q),
    .counter_i  (counter_q),
    .ready_o    (blk_ready),
    .keystream_o(blk_keystream),
    .valid_o    (blk_valid),
    .ack_i      (blk_ack)
  );

  // ------------------------------------------------------------------
  // Streaming FSM:
  //   IDLE  -> wait for init_i, then transition to LAUNCH
  //   LAUNCH-> pulse blk_start when blk_ready and a data beat is pending
  //   WAIT  -> wait for blk_valid
  //   EMIT  -> wait for downstream result_ready_i, then ack the block,
  //           bump counter, return to IDLE_RUN to launch the next block
  // ------------------------------------------------------------------
  typedef enum logic [2:0] {
    SS_IDLE   = 3'd0,
    SS_LAUNCH = 3'd1,
    SS_WAIT   = 3'd2,
    SS_EMIT   = 3'd3
  } sstate_e;

  sstate_e sstate_q, sstate_d;

  // Latched data for the current block.
  logic [511:0] data_buf_q;
  logic         last_buf_q;
  logic [6:0]   bc_buf_q;

  always_comb begin
    sstate_d   = sstate_q;
    blk_start  = 1'b0;
    blk_ack    = 1'b0;

    case (sstate_q)
      SS_IDLE: begin
        // Accept a new data beat when we have a session.
        if (have_session_q && data_valid_i) begin
          sstate_d = SS_LAUNCH;
        end
      end

      SS_LAUNCH: begin
        if (blk_ready) begin
          blk_start = 1'b1;
          sstate_d  = SS_WAIT;
        end
      end

      SS_WAIT: begin
        if (blk_valid) begin
          sstate_d = SS_EMIT;
        end
      end

      SS_EMIT: begin
        // Hold result until consumer asserts ready.
        if (result_ready_i) begin
          blk_ack  = 1'b1;
          sstate_d = SS_IDLE;
        end
      end

      default: sstate_d = SS_IDLE;
    endcase
  end

  // ------------------------------------------------------------------
  // Registers
  // ------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      sstate_q       <= SS_IDLE;
      sess_key_q     <= 256'd0;
      sess_nonce_q   <= 96'd0;
      counter_q      <= 32'd0;
      have_session_q <= 1'b0;
      data_buf_q     <= 512'd0;
      last_buf_q     <= 1'b0;
      bc_buf_q       <= 7'd0;
    end else begin
      sstate_q <= sstate_d;

      // Session loading on init_i
      if (init_i) begin
        sess_key_q     <= key_i;
        sess_nonce_q   <= nonce_i;
        counter_q      <= start_counter_i;
        have_session_q <= 1'b1;
      end

      // Latch incoming data on the IDLE -> LAUNCH transition.
      if (sstate_q == SS_IDLE && have_session_q && data_valid_i) begin
        data_buf_q <= data_i;
        last_buf_q <= last_i;
        bc_buf_q   <= last_i ? byte_count_i : 7'd64;
      end

      // Bump counter on EMIT completion.
      if (sstate_q == SS_EMIT && result_ready_i) begin
        counter_q <= counter_q + 32'd1;
      end
    end
  end

  // ------------------------------------------------------------------
  // Outputs
  // ------------------------------------------------------------------
  // We only accept a new beat in SS_IDLE. result_ready_i in SS_EMIT also
  // gates "available again" at the same cycle so we don't hold ready high
  // forever.
  assign data_ready_o = (sstate_q == SS_IDLE) && have_session_q;

  // XOR plaintext with keystream. For partial last block we still XOR all
  // 512 bits; the consumer is responsible for using only result_byte_count_o
  // bytes. The unused bytes still XOR a deterministic value (keystream
  // bytes) but we treat them as don't-care above byte_count_i.
  assign result_o            = data_buf_q ^ blk_keystream;
  assign result_valid_o      = (sstate_q == SS_EMIT);
  assign result_last_o       = last_buf_q;
  assign result_byte_count_o = bc_buf_q;

endmodule
