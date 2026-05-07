# ChaCha20-Poly1305 AEAD FPGA core - build / lint / sim / synth
#
# Targets:
#   make lint             verilator --lint-only on RTL (block + core + poly + aead)
#   make sim              build the AEAD top-level simulator
#   make test             build + run AEAD sim, check for "+PASS"
#   make sim-chacha       build the ChaCha20 streaming-core simulator
#   make test-chacha      build + run ChaCha20 sim
#   make sim-poly         build the Poly1305 simulator
#   make test-poly        build + run Poly1305 sim
#   make test-aead        alias for `test`
#   make test-all         run every test suite
#   make synth            Yosys: ice40 + ecp5 + xilinx generic for the AEAD top
#   make synth_report     run all available toolchains and emit SYNTH_REPORT.md
#   make vhdl-test        GHDL+Verilator co-sim of the VHDL wrapper (if installed)
#   make clean            remove build artifacts
#   make regen_vectors    regenerate tb/random_vectors.h from cryptography

VERILATOR ?= verilator
YOSYS     ?= yosys
GHDL      ?= ghdl
VIVADO    ?= vivado
QUARTUS   ?= quartus_sh

RTL_CHACHA := \
    rtl/chacha20_qround.sv \
    rtl/chacha20_block.sv \
    rtl/chacha20_core.sv

RTL_POLY := \
    rtl/poly1305_core.sv

RTL_AEAD := \
    $(RTL_CHACHA) \
    $(RTL_POLY) \
    rtl/chacha20_poly1305_aead.sv

TB_AEAD_TOP := tb/aead_tb.sv
TB_AEAD_AUX := tb/aead_assertions.sv tb/aead_cov.sv
TB_AEAD_CPP := tb/sim_main.cpp

TB_CHACHA_TOP := tb/chacha20_tb.sv
TB_CHACHA_CPP := tb/sim_main_chacha.cpp

TB_POLY_TOP   := tb/poly1305_tb.sv
TB_POLY_CPP   := tb/sim_main_poly.cpp

VFLAGS := -Wall -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL

.PHONY: lint sim test sim-chacha test-chacha sim-poly test-poly \
        test-aead test-all synth synth_report vhdl-test clean regen_vectors

lint:
	$(VERILATOR) --lint-only $(VFLAGS) --top-module aead_tb \
	    $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX)
	$(VERILATOR) --lint-only $(VFLAGS) --top-module chacha20_tb \
	    $(RTL_CHACHA) $(TB_CHACHA_TOP)
	$(VERILATOR) --lint-only $(VFLAGS) --top-module poly1305_tb \
	    $(RTL_POLY) $(TB_POLY_TOP)

sim: obj_dir/Vaead_tb

obj_dir/Vaead_tb: $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX) $(TB_AEAD_CPP) \
                  tb/random_vectors.h
	$(VERILATOR) --cc --exe --build $(VFLAGS) --assert --public-flat-rw \
	    --top-module aead_tb \
	    $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX) $(TB_AEAD_CPP) \
	    -o Vaead_tb

test: sim
	./obj_dir/Vaead_tb | tee test.log
	@grep -q "+PASS" test.log && echo "TESTS PASSED" || (echo "TESTS FAILED" && exit 1)

test-aead: test

sim-chacha: obj_dir_chacha/Vchacha20_tb

obj_dir_chacha/Vchacha20_tb: $(RTL_CHACHA) $(TB_CHACHA_TOP) $(TB_CHACHA_CPP)
	$(VERILATOR) --cc --exe --build $(VFLAGS) --top-module chacha20_tb \
	    --Mdir obj_dir_chacha \
	    $(RTL_CHACHA) $(TB_CHACHA_TOP) $(TB_CHACHA_CPP) \
	    -o Vchacha20_tb

test-chacha: sim-chacha
	./obj_dir_chacha/Vchacha20_tb | tee test_chacha.log
	@grep -q "+PASS" test_chacha.log && echo "CHACHA TESTS PASSED" || (echo "CHACHA TESTS FAILED" && exit 1)

sim-poly: obj_dir_poly/Vpoly1305_tb

obj_dir_poly/Vpoly1305_tb: $(RTL_POLY) $(TB_POLY_TOP) $(TB_POLY_CPP)
	$(VERILATOR) --cc --exe --build $(VFLAGS) --top-module poly1305_tb \
	    --Mdir obj_dir_poly \
	    $(RTL_POLY) $(TB_POLY_TOP) $(TB_POLY_CPP) \
	    -o Vpoly1305_tb

test-poly: sim-poly
	./obj_dir_poly/Vpoly1305_tb | tee test_poly.log
	@grep -q "+PASS" test_poly.log && echo "POLY TESTS PASSED" || (echo "POLY TESTS FAILED" && exit 1)

test-all: test-poly test-chacha test

# ---------- Open synthesis (Yosys) ------------------------------------------
synth:
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top chacha20_poly1305_aead; synth_ice40 -top chacha20_poly1305_aead; stat" \
	    | tee synth_ice40.log
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top chacha20_poly1305_aead; synth_ecp5 -top chacha20_poly1305_aead -abc9; stat" \
	    | tee synth_ecp5.log
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top chacha20_poly1305_aead; synth_xilinx -top chacha20_poly1305_aead; stat" \
	    | tee synth_xilinx.log

# ---------- Cross-toolchain synthesis report --------------------------------
synth_report:
	@bash scripts/synth_report.sh

# ---------- VHDL co-sim (optional) ------------------------------------------
vhdl-test:
	@which $(GHDL) >/dev/null 2>&1 || { echo "ghdl not installed - skipping vhdl-test"; exit 0; }
	@which $(VERILATOR) >/dev/null 2>&1 || { echo "verilator not installed"; exit 1; }
	@bash scripts/vhdl_cosim.sh

clean:
	rm -rf obj_dir obj_dir_chacha obj_dir_poly \
	    test.log test_chacha.log test_poly.log \
	    synth_ice40.log synth_ecp5.log synth_xilinx.log \
	    synth_report/ SYNTH_REPORT.md

regen_vectors:
	python3 tb/gen_random_vectors.py > tb/random_vectors.h
