// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// SVA assertions for chacha20_poly1305_aead. The properties cover protocol
// invariants enforced on every cycle of every test.
//
//   p_data_after_init    :  data_valid_i is only consumed (data_ready_o
//                           high) after init_i has been seen at least once.
//   p_result_stable      :  result_o is stable while result_valid_o is high.
//   p_tag_stable_done    :  tag_o is stable while tag_valid_o is high.
//   p_tag_after_finalize :  tag_valid_o never rises before finalize_i has
//                           been observed at least once.
//   p_tag_latency_bound  :  tag_valid_o rises at most LAT_MAX cycles after
//                           finalize_i. LAT_MAX is generous (1k) — the
//                           bound exists to catch a stuck FSM, not to pin a
//                           tight number.
//
// Properties are wrapped in `ifndef SYNTHESIS so they are stripped on
// synthesis flows.

module aead_assertions #(
  parameter int LAT_MAX = 1024
) (
  input logic         clk_i,
  input logic         rst_ni,
  input logic         init_i,
  input logic         data_valid_i,
  input logic         data_ready_o,
  input logic         data_last_i,
  input logic         result_valid_o,
  input logic [511:0] result_o,
  input logic         tag_valid_o,
  input logic [127:0] tag_o,
  input logic         finalize_i
);
`ifndef SYNTHESIS

  // Track init / finalize / last-data seen. The AEAD top can be finalised
  // either explicitly (finalize_i pulse) or implicitly (data_last_i with
  // a valid data beat).
  logic init_seen_q   = 1'b0;
  logic finalize_seen_q = 1'b0;
  int   cycles_since_finalize_q = 0;

  wire effective_finalize = finalize_i || (data_valid_i && data_ready_o && data_last_i);

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      init_seen_q             <= 1'b0;
      finalize_seen_q         <= 1'b0;
      cycles_since_finalize_q <= 0;
    end else begin
      if (init_i) init_seen_q <= 1'b1;
      if (init_i) finalize_seen_q <= 1'b0;
      if (effective_finalize) begin
        finalize_seen_q         <= 1'b1;
        cycles_since_finalize_q <= 0;
      end else if (finalize_seen_q && !tag_valid_o) begin
        cycles_since_finalize_q <= cycles_since_finalize_q + 1;
      end
    end
  end

  // 1. data_ready_o cannot rise without an init having been seen.
  property p_data_after_init;
    @(posedge clk_i) disable iff (!rst_ni)
      data_ready_o |-> init_seen_q;
  endproperty
  a_data_after_init: assert property (p_data_after_init)
    else $error("aead: data_ready_o asserted before init_i ever seen");

  // 2. result_o stable while valid.
  property p_result_stable;
    @(posedge clk_i) disable iff (!rst_ni)
      result_valid_o |=> (!result_valid_o || $stable(result_o));
  endproperty
  a_result_stable: assert property (p_result_stable)
    else $error("aead: result_o changed while result_valid_o asserted");

  // 3. tag stable while valid.
  property p_tag_stable_done;
    @(posedge clk_i) disable iff (!rst_ni)
      tag_valid_o |=> (!tag_valid_o || $stable(tag_o));
  endproperty
  a_tag_stable_done: assert property (p_tag_stable_done)
    else $error("aead: tag_o changed while tag_valid_o asserted");

  // 4. tag_valid_o stays low across cycles where finalize hasn't yet
  // been observed in this session. Sampled-property form, gated on
  // init_seen_q to skip the pre-init phase.
  logic [3:0] post_finalize_grace_q = 4'd0;
  always_ff @(posedge clk_i) begin
    if (!rst_ni) post_finalize_grace_q <= 4'd0;
    else if (finalize_i) post_finalize_grace_q <= 4'hf;
    else if (post_finalize_grace_q != 4'd0)
      post_finalize_grace_q <= post_finalize_grace_q - 4'd1;
  end
  property p_tag_after_finalize;
    @(posedge clk_i) disable iff (!rst_ni || !init_seen_q)
      tag_valid_o |-> finalize_seen_q;
  endproperty
  a_tag_after_finalize: assert property (p_tag_after_finalize)
    else $error("aead: tag_valid_o asserted without finalize_i seen this session");

  // 5. tag latency bound after finalize.
  property p_tag_latency_bound;
    @(posedge clk_i) disable iff (!rst_ni)
      finalize_seen_q |-> (cycles_since_finalize_q < LAT_MAX);
  endproperty
  a_tag_latency_bound: assert property (p_tag_latency_bound)
    else $error("aead: tag did not arrive within %0d cycles of finalize_i", LAT_MAX);

`endif // SYNTHESIS
endmodule
