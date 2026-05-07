// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Verilator C++ harness for chacha20_core (streaming).
//
// Tests:
//   1. RFC 8439 §2.4.2 sunscreen vector — 114-byte plaintext (encrypt then
//      decrypt round-trip).
//   2. RFC 8439 §2.3.2 ChaCha20 block function vector — single-block
//      keystream check against published expected output.
//   3. Random round-trip on varying lengths cross-validated against the
//      software ChaCha20 reference.
//
// Output: prints "+PASS" or "+FAIL <reason>".

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <array>

#include "verilated.h"
#include "Vchacha20_tb.h"

// ---------------------------------------------------------------------------
// Software ChaCha20 reference (used as the SECOND source of truth alongside
// the RFC vectors).
// ---------------------------------------------------------------------------
static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}
static void chacha20_block_sw(const uint8_t key[32], const uint8_t nonce[12],
                              uint32_t counter, uint8_t out[64]) {
    static const uint32_t C[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t s[16];
    s[0]=C[0]; s[1]=C[1]; s[2]=C[2]; s[3]=C[3];
    for (int i = 0; i < 8; i++) {
        s[4+i] = (uint32_t)key[4*i] | ((uint32_t)key[4*i+1] << 8) |
                 ((uint32_t)key[4*i+2] << 16) | ((uint32_t)key[4*i+3] << 24);
    }
    s[12] = counter;
    for (int i = 0; i < 3; i++) {
        s[13+i] = (uint32_t)nonce[4*i] | ((uint32_t)nonce[4*i+1] << 8) |
                  ((uint32_t)nonce[4*i+2] << 16) | ((uint32_t)nonce[4*i+3] << 24);
    }
    uint32_t w[16]; std::memcpy(w, s, sizeof(s));
    auto QR = [](uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    };
    for (int r = 0; r < 10; r++) {
        QR(w[0], w[4], w[8], w[12]);
        QR(w[1], w[5], w[9], w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[8],  w[13]);
        QR(w[3], w[4], w[9],  w[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t x = w[i] + s[i];
        out[4*i]   = (uint8_t)(x);
        out[4*i+1] = (uint8_t)(x >> 8);
        out[4*i+2] = (uint8_t)(x >> 16);
        out[4*i+3] = (uint8_t)(x >> 24);
    }
}
static void chacha20_sw(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t start_counter,
                        const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t ctr = start_counter;
    for (size_t off = 0; off < len; off += 64, ctr++) {
        uint8_t ks[64];
        chacha20_block_sw(key, nonce, ctr, ks);
        size_t take = (len - off >= 64) ? 64 : (len - off);
        for (size_t i = 0; i < take; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}

// ---------------------------------------------------------------------------
// Sim helpers
// ---------------------------------------------------------------------------
static int g_failures = 0;
static vluint64_t g_time = 0;

static void tick(Vchacha20_tb* dut) {
    dut->clk_i = 0; dut->eval(); g_time++;
    dut->clk_i = 1; dut->eval(); g_time++;
}
static void reset(Vchacha20_tb* dut) {
    dut->rst_ni = 0;
    dut->init_i = 0;
    dut->data_valid_i = 0;
    dut->result_ready_i = 0;
    dut->last_i = 0;
    dut->byte_count_i = 0;
    for (int i = 0; i < 8; i++) dut->key_i[i] = 0;
    for (int i = 0; i < 3; i++) dut->nonce_i[i] = 0;
    dut->start_counter_i = 0;
    for (int i = 0; i < 16; i++) dut->data_i[i] = 0;
    for (int i = 0; i < 4; i++) tick(dut);
    dut->rst_ni = 1;
    tick(dut);
}

static void put_key(Vchacha20_tb* dut, const uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        uint32_t w = 0;
        for (int b = 0; b < 4; b++) w |= (uint32_t)key[4*i + b] << (8*b);
        dut->key_i[i] = w;
    }
}
static void put_nonce(Vchacha20_tb* dut, const uint8_t n[12]) {
    for (int i = 0; i < 3; i++) {
        uint32_t w = 0;
        for (int b = 0; b < 4; b++) w |= (uint32_t)n[4*i + b] << (8*b);
        dut->nonce_i[i] = w;
    }
}
static void put_block(Vchacha20_tb* dut, const uint8_t blk[64]) {
    for (int i = 0; i < 16; i++) {
        uint32_t w = 0;
        for (int b = 0; b < 4; b++) w |= (uint32_t)blk[4*i + b] << (8*b);
        dut->data_i[i] = w;
    }
}
static void read_result(Vchacha20_tb* dut, uint8_t out[64]) {
    for (int i = 0; i < 16; i++) {
        uint32_t w = dut->result_o[i];
        for (int b = 0; b < 4; b++) out[4*i + b] = (w >> (8*b)) & 0xff;
    }
}

// Run a streaming ChaCha20 transform through the DUT.
static void dut_chacha20(Vchacha20_tb* dut,
                         const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t start_counter,
                         const uint8_t* in, uint8_t* out, size_t len) {
    // init
    while (!dut->result_valid_o && false) {} // unused
    put_key(dut, key);
    put_nonce(dut, nonce);
    dut->start_counter_i = start_counter;
    dut->init_i = 1;
    tick(dut);
    dut->init_i = 0;

    // stream
    size_t off = 0;
    while (off < len || len == 0) {
        size_t take = (len - off >= 64) ? 64 : (len - off);
        bool last = (off + take >= len);

        uint8_t blk[64] = {0};
        if (take > 0) std::memcpy(blk, in + off, take);

        // Wait for data_ready
        int waited = 0;
        while (!dut->data_ready_o) {
            tick(dut);
            if (++waited > 200) { g_failures++; return; }
        }
        put_block(dut, blk);
        dut->data_valid_i = 1;
        dut->last_i       = last && (take > 0);
        dut->byte_count_i = (uint8_t)(take == 0 ? 0 : take);
        tick(dut);
        dut->data_valid_i = 0;
        dut->last_i       = 0;

        // Wait for result, consume
        waited = 0;
        while (!dut->result_valid_o) {
            tick(dut);
            if (++waited > 200) { g_failures++; return; }
        }
        uint8_t res[64];
        read_result(dut, res);
        if (take > 0) std::memcpy(out + off, res, take);

        // Ack
        dut->result_ready_i = 1;
        tick(dut);
        dut->result_ready_i = 0;

        off += take;
        if (take == 0) break;
        if (last) break;
    }
}

static std::vector<uint8_t> hex2bytes(const char* h) {
    std::vector<uint8_t> v;
    for (; *h && *(h+1); h += 2) {
        if (*h == ' ' || *h == ':') { h--; continue; }
        unsigned x; std::sscanf(h, "%2x", &x);
        v.push_back((uint8_t)x);
    }
    return v;
}
static std::string bytes2hex(const uint8_t* b, size_t n) {
    std::string s; s.reserve(n*2);
    for (size_t i = 0; i < n; i++) {
        char tmp[3]; std::snprintf(tmp, 3, "%02x", b[i]);
        s += tmp;
    }
    return s;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// RFC 8439 §2.4.2 "Sunscreen" test vector
static void test_rfc_sunscreen(Vchacha20_tb* dut) {
    std::printf("---- Test 1: RFC 8439 sec 2.4.2 sunscreen vector ----\n");
    // key, nonce, counter from RFC
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t counter = 1;

    const char* plaintext = "Ladies and Gentlemen of the class of '99: "
                           "If I could offer you only one tip for the future, "
                           "sunscreen would be it.";
    const std::vector<uint8_t> pt(plaintext,
                                  plaintext + std::strlen(plaintext));

    // Expected ciphertext (RFC 8439 §2.4.2):
    const char* expected_hex =
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d";
    auto exp = hex2bytes(expected_hex);

    std::vector<uint8_t> ct(pt.size());
    dut_chacha20(dut, key, nonce, counter, pt.data(), ct.data(), pt.size());

    if (ct == exp) {
        std::printf("  [PASS] RFC sunscreen encrypt matches\n");
    } else {
        std::printf("  [FAIL] RFC sunscreen encrypt\n");
        std::printf("         expected %s\n", bytes2hex(exp.data(), exp.size()).c_str());
        std::printf("         got      %s\n", bytes2hex(ct.data(), ct.size()).c_str());
        g_failures++;
    }

    // Round-trip: decrypt the ciphertext and confirm we get the plaintext.
    // ChaCha20 enc/dec are symmetric.
    std::vector<uint8_t> roundtrip(ct.size());
    dut_chacha20(dut, key, nonce, counter, ct.data(), roundtrip.data(), ct.size());
    if (roundtrip == pt) {
        std::printf("  [PASS] RFC sunscreen decrypt round-trips\n");
    } else {
        std::printf("  [FAIL] RFC sunscreen decrypt round-trip\n");
        g_failures++;
    }
}

static void test_rfc_block_vector(Vchacha20_tb* dut) {
    std::printf("---- Test 2: RFC 8439 sec 2.3.2 block-function vector ----\n");
    // key bytes 0..31, nonce 0,0,0,9,0,0,0,0x4a,0,0,0,0; counter=1
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    uint8_t nonce[12] = {0,0,0,9, 0,0,0,0x4a, 0,0,0,0};
    uint32_t counter = 1;

    // Encrypt 64 zero bytes => keystream
    std::vector<uint8_t> in(64, 0);
    std::vector<uint8_t> ks(64);
    dut_chacha20(dut, key, nonce, counter, in.data(), ks.data(), 64);

    const char* expected_hex =
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e";
    auto exp = hex2bytes(expected_hex);
    if (ks == exp) {
        std::printf("  [PASS] RFC block-function keystream\n");
    } else {
        std::printf("  [FAIL] RFC block-function keystream\n");
        std::printf("         expected %s\n", bytes2hex(exp.data(), 64).c_str());
        std::printf("         got      %s\n", bytes2hex(ks.data(), 64).c_str());
        g_failures++;
    }
}

static void test_random_lengths(Vchacha20_tb* dut, int n) {
    std::printf("---- Test 3: %d random messages cross-validated ----\n", n);
    std::srand(0xdecafbad);
    int passes = 0, fails = 0;
    for (int i = 0; i < n; i++) {
        uint8_t key[32]; for (int j = 0; j < 32; j++) key[j] = std::rand() & 0xff;
        uint8_t nonce[12]; for (int j = 0; j < 12; j++) nonce[j] = std::rand() & 0xff;
        uint32_t ctr = std::rand();
        size_t len = std::rand() % 300 + 1;     // 1..300 bytes
        std::vector<uint8_t> pt(len);
        for (size_t j = 0; j < len; j++) pt[j] = std::rand() & 0xff;

        std::vector<uint8_t> expected(len);
        chacha20_sw(key, nonce, ctr, pt.data(), expected.data(), len);

        std::vector<uint8_t> got(len);
        dut_chacha20(dut, key, nonce, ctr, pt.data(), got.data(), len);

        if (got == expected) {
            passes++;
        } else {
            if (fails < 3) {
                std::printf("  [FAIL] random #%d len=%zu\n", i, len);
                std::printf("         expected %s\n", bytes2hex(expected.data(), std::min(len, (size_t)32)).c_str());
                std::printf("         got      %s\n", bytes2hex(got.data(), std::min(len, (size_t)32)).c_str());
            }
            fails++;
        }
    }
    std::printf("  random: %d / %d pass\n", passes, n);
    if (fails > 0) g_failures += fails;
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    setvbuf(stdout, nullptr, _IOLBF, 0);
    Vchacha20_tb* dut = new Vchacha20_tb();
    reset(dut);

    test_rfc_sunscreen(dut);
    test_rfc_block_vector(dut);
    test_random_lengths(dut, 50);

    if (g_failures == 0) {
        std::printf("+PASS all tests passed\n");
        delete dut;
        return 0;
    } else {
        std::printf("+FAIL %d failures\n", g_failures);
        delete dut;
        return 1;
    }
}
