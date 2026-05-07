// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// ChaCha20-Poly1305 AEAD top-level (RFC 8439 §2.8).
//
// AEAD construction:
//
//   poly_key   = chacha20_block(key, nonce, counter=0)[0..31]    // first 32 bytes of block 0
//   ciphertext = chacha20(key, nonce, counter=1, plaintext)
//   mac_data   = aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
//                len64(aad) || len64(ciphertext)
//   tag        = poly1305(poly_key, mac_data)
//
//   pad16(x) = "\x00" * (16 - (len(x) mod 16))   if len(x) mod 16 != 0 else ""
//   len64(x) = little-endian 8-byte length in bytes
//
// In the verify-with-decrypt path the caller checks tag against the
// expected tag in constant time (NOT done in this module — provided as a
// reference function in tb/sim_main.cpp).
//
// Mode select:
//   mode_i = 2'b00  ENCRYPT      ciphertext + tag
//   mode_i = 2'b01  DECRYPT      plaintext  + tag (caller checks)
//   mode_i = 2'b10  AAD_ONLY     no ct/pt, only authenticates AAD (rare)
//
// The caller streams AAD first (one or more 16-byte chunks; last chunk's
// byte_count may be 1..16), then plaintext / ciphertext (similarly), then
// pulses finalize. The core handles pad16 by computing chunk_byte_count
// per chunk and feeding the Poly1305 block with the actual byte count;
// when byte_count < 16, the extra bytes the Poly1305 block sees are zero
// (the caller is responsible for zero-padding the chunk top bytes), and
// internally the n_i build only reads chunk_byte_count bytes — this
// matches the "skip zero pad" optimisation that is functionally equivalent
// to feeding a zero-padded full chunk.
//
// However, the RFC's len64-of-aad / len64-of-ciphertext block must always
// be appended as a final 16-byte poly chunk regardless. This module
// records aad_len_q and ct_len_q during the streaming and emits the
// final 16-byte length block automatically when finalize_i pulses.
//
// For the partial-chunk case the AEAD spec requires that the chunk be
// padded to 16 bytes BEFORE being fed to Poly1305 (RFC 8439 §2.8.1). We
// implement this by feeding Poly1305 with chunk_byte_count = 16 and the
// caller's chunk top bytes already zeroed; the n_i build then sets the
// "+1 byte" bit at offset 16, exactly as the RFC requires for a full
// 16-byte block. This means callers MUST present zero-padded chunks.

module chacha20_poly1305_aead (
  input  logic         clk_i,
  input  logic         rst_ni,

  // Session setup
  input  logic         init_i,
  input  logic [255:0] key_i,
  input  logic [95:0]  nonce_i,
  input  logic [1:0]   mode_i,
  output logic         init_ready_o,

  // AAD streaming (optional)
  input  logic         aad_valid_i,
  input  logic [127:0] aad_chunk_i,
  input  logic [4:0]   aad_byte_count_i,   // 1..16 (16 for full)
  input  logic         aad_last_i,
  output logic         aad_ready_o,

  // Plaintext / ciphertext streaming
  input  logic         data_valid_i,
  input  logic [511:0] data_i,             // 64-byte block
  input  logic [6:0]   data_byte_count_i,  // 1..64
  input  logic         data_last_i,
  output logic         data_ready_o,

  // Result streaming (encrypt: ct, decrypt: pt)
  output logic         result_valid_o,
  output logic [511:0] result_o,
  output logic [6:0]   result_byte_count_o,
  output logic         result_last_o,
  input  logic         result_ready_i,

  // Final tag
  input  logic         finalize_i,
  output logic [127:0] tag_o,
  output logic         tag_valid_o,

  // Decrypt-only convenience: caller sets expected_tag_i and we OR the
  // constant-time difference into tag_match_o.
  input  logic [127:0] expected_tag_i,
  output logic         tag_match_o
);

  localparam logic [1:0] M_ENCRYPT  = 2'b00;
  localparam logic [1:0] M_DECRYPT  = 2'b01;
  localparam logic [1:0] M_AAD_ONLY = 2'b10;

  // ------------------------------------------------------------------
  // Sub-blocks: a single chacha20_block to derive poly_key from counter=0,
  // then a chacha20_core (which has its own internal block engine) to
  // process plaintext/ciphertext from counter=1.
  //
  // To keep area sane, we wire ONE chacha20_block to derive the Poly1305
  // key (counter=0), then we instantiate chacha20_core for the bulk
  // stream. The bulk core internally creates its own chacha20_block; the
  // resulting two chacha20_blocks share the same RTL but are physically
  // separate cells. Premium tier could share one engine via muxing.
  // ------------------------------------------------------------------

  // Poly1305 key derivation block
  logic         pk_start;
  logic         pk_ready;
  logic [511:0] pk_keystream;
  logic         pk_valid;
  logic         pk_ack;

  chacha20_block u_pk_block (
    .clk_i      (clk_i),
    .rst_ni     (rst_ni),
    .start_i    (pk_start),
    .key_i      (sess_key_q),
    .nonce_i    (sess_nonce_q),
    .counter_i  (32'd0),
    .ready_o    (pk_ready),
    .keystream_o(pk_keystream),
    .valid_o    (pk_valid),
    .ack_i      (pk_ack)
  );

  // Streaming ChaCha20 core for bulk data (counter starts at 1)
  logic         cc_init;
  logic         cc_data_valid;
  logic [511:0] cc_data;
  logic         cc_data_last;
  logic [6:0]   cc_data_bc;
  logic         cc_data_ready;
  logic         cc_result_valid;
  logic [511:0] cc_result;
  logic         cc_result_last;
  logic [6:0]   cc_result_bc;
  logic         cc_result_ready;

  chacha20_core u_cc (
    .clk_i              (clk_i),
    .rst_ni             (rst_ni),
    .init_i             (cc_init),
    .key_i              (sess_key_q),
    .nonce_i            (sess_nonce_q),
    .start_counter_i    (32'd1),
    .data_valid_i       (cc_data_valid),
    .data_i             (cc_data),
    .last_i             (cc_data_last),
    .byte_count_i       (cc_data_bc),
    .data_ready_o       (cc_data_ready),
    .result_valid_o     (cc_result_valid),
    .result_o           (cc_result),
    .result_last_o      (cc_result_last),
    .result_byte_count_o(cc_result_bc),
    .result_ready_i     (cc_result_ready)
  );

  // Poly1305
  logic         poly_init;
  logic         poly_data_valid;
  logic [127:0] poly_chunk;
  logic [4:0]   poly_chunk_bc;
  logic         poly_data_ready;
  logic         poly_finalize;
  logic [127:0] poly_tag;
  logic         poly_tag_valid;
  logic [255:0] poly_key_w;

  poly1305_core u_poly (
    .clk_i             (clk_i),
    .rst_ni            (rst_ni),
    .init_i            (poly_init),
    .key_i             (poly_key_w),
    /* verilator lint_off PINCONNECTEMPTY */
    .init_ready_o      (),
    /* verilator lint_on PINCONNECTEMPTY */
    .data_valid_i      (poly_data_valid),
    .chunk_i           (poly_chunk),
    .chunk_byte_count_i(poly_chunk_bc),
    .data_ready_o      (poly_data_ready),
    .finalize_i        (poly_finalize),
    .tag_o             (poly_tag),
    .tag_valid_o       (poly_tag_valid)
  );

  // ------------------------------------------------------------------
  // Session registers
  // ------------------------------------------------------------------
  logic [255:0] sess_key_q;
  logic [95:0]  sess_nonce_q;
  logic [1:0]   sess_mode_q;

  // First 256 bits (32 bytes) of pk_keystream are the Poly1305 (r,s) key.
  // chacha20_block emits keystream little-endian byte-packed in
  // keystream_o[31:0]=word0, etc. The Poly1305 key is the first 32 bytes,
  // i.e. keystream_o[255:0].
  assign poly_key_w = pk_keystream[255:0];

  // Length tracking (in bytes)
  logic [63:0] aad_len_q;
  logic [63:0] ct_len_q;

  // ------------------------------------------------------------------
  // Top-level FSM. Phases:
  //   T_IDLE        : waiting for init
  //   T_DERIVE_KEY  : start pk_block, wait for poly_key
  //   T_POLY_INIT   : pulse poly_init for one cycle, wait
  //   T_AAD         : stream AAD chunks into Poly1305
  //   T_AAD_PAD     : (handled implicitly via the caller using bcb=16 with
  //                    pre-zeroed chunks; actually we just transition)
  //   T_DATA        : stream data through chacha20_core; for each emitted
  //                    block, slice into 4x16-byte chunks and feed Poly1305
  //                    (post-cipher == ciphertext for both enc/dec)
  //   T_LEN         : feed the final 16-byte (len_aad || len_ct) to Poly
  //   T_FINALIZE    : pulse poly_finalize, wait for tag_valid
  //   T_DONE        : tag_valid_o asserted
  // ------------------------------------------------------------------

  typedef enum logic [3:0] {
    T_IDLE       = 4'd0,
    T_DERIVE_KEY = 4'd1,
    T_POLY_INIT  = 4'd2,
    T_AAD        = 4'd3,
    T_DATA       = 4'd4,
    T_DATA_FEED  = 4'd5,  // emit cipher block to result + slice into Poly
    T_LEN        = 4'd6,
    T_FINALIZE   = 4'd7,
    T_DONE       = 4'd8
  } tstate_e;

  tstate_e tstate_q, tstate_d;

  // For each emitted bulk block, we need to feed up to 4 16-byte chunks
  // (or fewer on the last partial block) into Poly1305. slice_idx_q
  // counts which chunk within the block we're on.
  logic [2:0] slice_idx_q, slice_idx_d;

  // Captured emitted block (we can't hold cc_result_ready high while we
  // shuffle slices because cc would advance counter; we register
  // cc_result on emit and let the streaming core advance).
  logic [511:0] emit_buf_q;
  logic [6:0]   emit_bc_q;
  logic         emit_last_q;
  logic         emit_held_q;       // we have a registered emission to drain

  // For the LEN block:
  logic         len_done_q;

  // Constant-time tag compare: XOR-OR-zero
  logic [127:0] tag_xor;
  assign tag_xor     = poly_tag ^ expected_tag_i;
  assign tag_match_o = tag_valid_o && (tag_xor == 128'd0);

  // ------------------------------------------------------------------
  // Slice helper. For slice index k in [0..3]:
  //   chunk = data[127+128*k : 128*k]
  //   bcb   = 16 normally, possibly less for the last slice of the last
  //           block when data_byte_count < 64.
  // ------------------------------------------------------------------
  function automatic logic [4:0] slice_bcb(
      input logic [6:0] total_bytes,
      input logic [2:0] k);
    logic [6:0] s_start;
    logic [6:0] rem;
    s_start = {k, 4'b0};   // k * 16
    if (total_bytes <= s_start) begin
      slice_bcb = 5'd0;
    end else begin
      rem = total_bytes - s_start;
      if (rem >= 7'd16) slice_bcb = 5'd16;
      else              slice_bcb = rem[4:0];
    end
  endfunction

  // ------------------------------------------------------------------
  // Combinational defaults / FSM
  // ------------------------------------------------------------------
  logic [4:0]   cur_slice_bcb;
  logic [127:0] cur_slice_chunk;
  logic [127:0] aad_mask;
  logic [127:0] slice_mask;

  // Mask helper: bytes [0..bcb-1] are 1s, bytes [bcb..15] are 0s.
  function automatic logic [127:0] byte_mask(input logic [4:0] bcb);
    if (bcb >= 5'd16) byte_mask = {128{1'b1}};
    else if (bcb == 5'd0) byte_mask = 128'd0;
    else byte_mask = (128'h1 << (bcb * 8)) - 128'h1;
  endfunction

  always_comb begin
    tstate_d        = tstate_q;
    slice_idx_d     = slice_idx_q;

    pk_start        = 1'b0;
    pk_ack          = 1'b0;

    cc_init         = 1'b0;
    cc_data_valid   = 1'b0;
    cc_data         = data_i;
    cc_data_last    = data_last_i;
    cc_data_bc      = data_byte_count_i;
    cc_result_ready = 1'b0;

    poly_init       = 1'b0;
    poly_data_valid = 1'b0;
    poly_chunk      = aad_chunk_i;
    poly_chunk_bc   = aad_byte_count_i;
    poly_finalize   = 1'b0;

    cur_slice_bcb   = slice_bcb(emit_bc_q, slice_idx_q);
    cur_slice_chunk = emit_buf_q[128*slice_idx_q +: 128];
    aad_mask        = byte_mask(aad_byte_count_i);
    slice_mask      = byte_mask(cur_slice_bcb);

    case (tstate_q)
      // ----------------------------------------------------------------
      T_IDLE: begin
        // init_i transition handled in always_ff (latches session)
        if (init_i) tstate_d = T_DERIVE_KEY;
      end

      // ----------------------------------------------------------------
      T_DERIVE_KEY: begin
        if (pk_ready) begin
          pk_start = 1'b1;
        end
        if (pk_valid) begin
          tstate_d = T_POLY_INIT;
        end
      end

      // ----------------------------------------------------------------
      T_POLY_INIT: begin
        // Poly key bits are now stable at pk_keystream[255:0].
        poly_init = 1'b1;
        // Initialize bulk ChaCha20 core too.
        cc_init   = 1'b1;
        // Ack the poly-key block so the engine returns to idle.
        pk_ack    = 1'b1;
        tstate_d  = T_AAD;
      end

      // ----------------------------------------------------------------
      T_AAD: begin
        if (aad_valid_i && poly_data_ready) begin
          // Feed AAD chunk to Poly. Per RFC 8439 §2.8, each AAD chunk is
          // pad16'd and treated as a full 16-byte block by Poly1305. We
          // zero-mask bytes >= aad_byte_count_i and force bcb=16 so the
          // build_n in poly1305_core appends 0x01 at byte 16.
          poly_data_valid = 1'b1;
          poly_chunk      = aad_chunk_i & aad_mask;
          poly_chunk_bc   = 5'd16;
          if (aad_last_i) tstate_d = T_DATA;
        end else if (data_valid_i && !aad_valid_i) begin
          tstate_d = T_DATA;
        end else if (finalize_i && !aad_valid_i) begin
          tstate_d = T_LEN;
        end
      end

      // ----------------------------------------------------------------
      T_DATA: begin
        // Push data into chacha20_core, drain results, slice into Poly.
        // Two paths: feed input + drain output.
        if (!emit_held_q) begin
          if (data_valid_i && cc_data_ready) begin
            cc_data_valid = 1'b1;
          end
          if (cc_result_valid) begin
            cc_result_ready = 1'b1;  // capture this cycle
            // After capture we'll process in T_DATA_FEED
            tstate_d = T_DATA_FEED;
          end else if (finalize_i && !data_valid_i) begin
            tstate_d = T_LEN;
          end
        end
      end

      // ----------------------------------------------------------------
      T_DATA_FEED: begin
        // We have emit_buf_q valid. Feed slice slice_idx_q into Poly.
        // Per RFC 8439 §2.8: each ciphertext block goes into Poly as a
        // pad16'd 16-byte block (bcb=16), with bytes beyond the actual
        // ct length set to zero. We mask the slice here.
        if (cur_slice_bcb == 5'd0) begin
          if (emit_last_q) begin
            tstate_d = T_LEN;
          end else begin
            tstate_d = T_DATA;
          end
        end else if (poly_data_ready) begin
          poly_data_valid = 1'b1;
          poly_chunk      = cur_slice_chunk & slice_mask;
          poly_chunk_bc   = 5'd16;
          slice_idx_d     = slice_idx_q + 3'd1;
        end
      end

      // ----------------------------------------------------------------
      T_LEN: begin
        // Build the 16-byte length block: (aad_len_le_8 || ct_len_le_8)
        if (poly_data_ready && !len_done_q) begin
          poly_data_valid = 1'b1;
          poly_chunk      = {ct_len_q, aad_len_q};
          poly_chunk_bc   = 5'd16;
        end
        if (len_done_q) begin
          tstate_d = T_FINALIZE;
        end
      end

      // ----------------------------------------------------------------
      T_FINALIZE: begin
        if (poly_data_ready) begin
          poly_finalize = 1'b1;
        end
        if (poly_tag_valid) begin
          tstate_d = T_DONE;
        end
      end

      // ----------------------------------------------------------------
      T_DONE: begin
        if (init_i) tstate_d = T_DERIVE_KEY;
      end

      default: tstate_d = T_IDLE;
    endcase
  end

  // ------------------------------------------------------------------
  // Sequential
  // ------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      tstate_q     <= T_IDLE;
      sess_key_q   <= 256'd0;
      sess_nonce_q <= 96'd0;
      sess_mode_q  <= 2'b00;
      aad_len_q    <= 64'd0;
      ct_len_q     <= 64'd0;
      slice_idx_q  <= 3'd0;
      emit_buf_q   <= 512'd0;
      emit_bc_q    <= 7'd0;
      emit_last_q  <= 1'b0;
      emit_held_q  <= 1'b0;
      len_done_q   <= 1'b0;
    end else begin
      tstate_q <= tstate_d;

      // Latch session
      if (init_i) begin
        sess_key_q   <= key_i;
        sess_nonce_q <= nonce_i;
        sess_mode_q  <= mode_i;
        aad_len_q    <= 64'd0;
        ct_len_q     <= 64'd0;
        slice_idx_q  <= 3'd0;
        emit_held_q  <= 1'b0;
        len_done_q   <= 1'b0;
      end

      // Track AAD bytes
      if (tstate_q == T_AAD && aad_valid_i && poly_data_ready) begin
        aad_len_q <= aad_len_q + {59'd0, aad_byte_count_i};
      end

      // Capture an emitted cipher block in T_DATA
      if (tstate_q == T_DATA && cc_result_valid) begin
        emit_buf_q  <= cc_result;
        emit_bc_q   <= cc_result_bc;
        emit_last_q <= cc_result_last;
        emit_held_q <= 1'b1;
        slice_idx_q <= 3'd0;
        ct_len_q    <= ct_len_q + {57'd0, cc_result_bc};
      end

      // Reset emit_held when we exit T_DATA_FEED with no more slices
      if (tstate_q == T_DATA_FEED && cur_slice_bcb == 5'd0) begin
        emit_held_q <= 1'b0;
        slice_idx_q <= 3'd0;
      end

      if (tstate_q == T_DATA_FEED && poly_data_ready &&
          slice_bcb(emit_bc_q, slice_idx_q) != 5'd0) begin
        slice_idx_q <= slice_idx_q + 3'd1;
      end

      // LEN done flag
      if (tstate_q == T_LEN && poly_data_ready && !len_done_q) begin
        len_done_q <= 1'b1;
      end
    end
  end

  // ------------------------------------------------------------------
  // External handshake outputs
  // ------------------------------------------------------------------
  assign init_ready_o        = (tstate_q == T_IDLE) || (tstate_q == T_DONE);
  assign aad_ready_o         = (tstate_q == T_AAD)  && poly_data_ready;
  assign data_ready_o        = (tstate_q == T_DATA) && cc_data_ready && !emit_held_q;

  // The result stream the user sees is the chacha20_core output passed
  // through. Because we capture it for slicing, expose the emit_buf as
  // the result during T_DATA_FEED.
  assign result_valid_o       = (tstate_q == T_DATA_FEED) && (slice_idx_q == 3'd0);
  assign result_o             = emit_buf_q;
  assign result_byte_count_o  = emit_bc_q;
  assign result_last_o        = emit_last_q;

  // Tag
  assign tag_o       = poly_tag;
  assign tag_valid_o = (tstate_q == T_DONE);

endmodule
