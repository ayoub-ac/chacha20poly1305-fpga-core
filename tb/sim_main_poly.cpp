// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Verilator C++ harness for poly1305_core.
//
// Tests:
//   1. RFC 8439 §2.5.2 vector ("Cryptographic Forum Research Group" message)
//   2. Empty message (tag should be just s)
//   3. Single-chunk and multi-chunk messages
//   4. Cross-validation against a software Poly1305 reference
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
#include "Vpoly1305_tb.h"

// ---------------------------------------------------------------------------
// Software Poly1305 reference (used for cross-validation).
// 128-bit math via four uint64_t limbs. RFC 8439 §2.5.1.
// ---------------------------------------------------------------------------
static void poly1305_sw(const uint8_t key[32],
                        const uint8_t* msg, size_t msg_len,
                        uint8_t tag[16]) {
    // Use a clean 130-bit accumulator via 5 26-bit limbs (Bernstein's
    // recommended layout). For test purposes we use a __int128-style
    // implementation with portable arithmetic.
    // We use the simpler radix-2^64 approach with a 256-bit accumulator
    // and modular reduction by the prime p = 2^130 - 5.
    // For portability without 128-bit ints, we use a small bignum.

    // Big integer helpers (fixed 17-byte = 136-bit big endian)
    auto from_bytes_le = [](uint64_t out[3], const uint8_t* in, size_t n) {
        out[0] = out[1] = out[2] = 0;
        uint64_t lo = 0, hi = 0;
        for (size_t i = 0; i < n && i < 8; i++) lo |= (uint64_t)in[i] << (8*i);
        for (size_t i = 8; i < n && i < 16; i++) hi |= (uint64_t)in[i] << (8*(i-8));
        out[0] = lo;
        out[1] = hi;
        out[2] = (n < 16) ? ((uint64_t)1 << (8 * n) >> 64) : 1;
        // Actually high bit goes at position 8*n for partial; for full chunk it's bit 128.
        if (n < 16) {
            uint64_t bit = (uint64_t)1 << (8*n);
            if (8*n < 64) out[0] |= bit;
            else if (8*n < 128) out[1] |= ((uint64_t)1 << (8*n - 64));
            else out[2] = 1;
        } else {
            out[2] = 1;
        }
    };

    // Clamp r
    uint8_t r_bytes[16];
    std::memcpy(r_bytes, key, 16);
    r_bytes[3]  &= 15;
    r_bytes[7]  &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4]  &= 252;
    r_bytes[8]  &= 252;
    r_bytes[12] &= 252;

    uint64_t r0=0, r1=0;
    for (int i = 0; i < 8; i++) r0 |= (uint64_t)r_bytes[i]   << (8*i);
    for (int i = 0; i < 8; i++) r1 |= (uint64_t)r_bytes[i+8] << (8*i);

    uint64_t s0=0, s1=0;
    for (int i = 0; i < 8; i++) s0 |= (uint64_t)key[16+i] << (8*i);
    for (int i = 0; i < 8; i++) s1 |= (uint64_t)key[24+i] << (8*i);

    // Accumulator: 5 26-bit limbs. r in same form.
    auto split26 = [](uint64_t lo, uint64_t hi, uint32_t out[5]) {
        // bits 0..25, 26..51, 52..77, 78..103, 104..129
        uint64_t b[2] = {lo, hi};
        // b is 128 bits + we may have bit 128 from the appended 1
        out[0] = (uint32_t)(b[0] & 0x3ffffff);
        out[1] = (uint32_t)((b[0] >> 26) & 0x3ffffff);
        out[2] = (uint32_t)(((b[0] >> 52) | (b[1] << 12)) & 0x3ffffff);
        out[3] = (uint32_t)((b[1] >> 14) & 0x3ffffff);
        out[4] = (uint32_t)((b[1] >> 40) & 0x3ffffff);
    };

    uint32_t r[5];
    split26(r0, r1, r);

    uint32_t h[5] = {0,0,0,0,0};
    uint32_t s[4] = {(uint32_t)s0, (uint32_t)(s0>>32), (uint32_t)s1, (uint32_t)(s1>>32)};

    // pre-multiply r by 5 for the reduction
    uint32_t r5[5] = {r[0]*5, r[1]*5, r[2]*5, r[3]*5, r[4]*5};

    auto block = [&](uint64_t lo, uint64_t hi, uint32_t hibit) {
        uint32_t m[5];
        m[0] = (uint32_t)(lo & 0x3ffffff);
        m[1] = (uint32_t)((lo >> 26) & 0x3ffffff);
        m[2] = (uint32_t)(((lo >> 52) | (hi << 12)) & 0x3ffffff);
        m[3] = (uint32_t)((hi >> 14) & 0x3ffffff);
        m[4] = (uint32_t)((hi >> 40) | (hibit << 24));

        // h += m
        for (int i = 0; i < 5; i++) h[i] += m[i];

        // h *= r mod p
        uint64_t d[5];
        d[0] = (uint64_t)h[0]*r[0] + (uint64_t)h[1]*r5[4] + (uint64_t)h[2]*r5[3] +
               (uint64_t)h[3]*r5[2] + (uint64_t)h[4]*r5[1];
        d[1] = (uint64_t)h[0]*r[1] + (uint64_t)h[1]*r[0]  + (uint64_t)h[2]*r5[4] +
               (uint64_t)h[3]*r5[3] + (uint64_t)h[4]*r5[2];
        d[2] = (uint64_t)h[0]*r[2] + (uint64_t)h[1]*r[1]  + (uint64_t)h[2]*r[0]  +
               (uint64_t)h[3]*r5[4] + (uint64_t)h[4]*r5[3];
        d[3] = (uint64_t)h[0]*r[3] + (uint64_t)h[1]*r[2]  + (uint64_t)h[2]*r[1]  +
               (uint64_t)h[3]*r[0]  + (uint64_t)h[4]*r5[4];
        d[4] = (uint64_t)h[0]*r[4] + (uint64_t)h[1]*r[3]  + (uint64_t)h[2]*r[2]  +
               (uint64_t)h[3]*r[1]  + (uint64_t)h[4]*r[0];

        // carry propagate
        uint64_t c;
        c = d[0] >> 26; h[0] = d[0] & 0x3ffffff;
        d[1] += c;
        c = d[1] >> 26; h[1] = d[1] & 0x3ffffff;
        d[2] += c;
        c = d[2] >> 26; h[2] = d[2] & 0x3ffffff;
        d[3] += c;
        c = d[3] >> 26; h[3] = d[3] & 0x3ffffff;
        d[4] += c;
        c = d[4] >> 26; h[4] = d[4] & 0x3ffffff;
        h[0] += (uint32_t)c * 5;
        c = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] += (uint32_t)c;
    };

    // Process full 16-byte chunks
    size_t i = 0;
    while (i + 16 <= msg_len) {
        uint64_t lo = 0, hi = 0;
        for (int k = 0; k < 8; k++) lo |= (uint64_t)msg[i+k]   << (8*k);
        for (int k = 0; k < 8; k++) hi |= (uint64_t)msg[i+k+8] << (8*k);
        block(lo, hi, 1);
        i += 16;
    }
    // Last partial
    if (i < msg_len) {
        uint8_t buf[16] = {0};
        size_t rem = msg_len - i;
        std::memcpy(buf, msg + i, rem);
        buf[rem] = 0x01;
        uint64_t lo = 0, hi = 0;
        for (int k = 0; k < 8; k++) lo |= (uint64_t)buf[k]   << (8*k);
        for (int k = 0; k < 8; k++) hi |= (uint64_t)buf[k+8] << (8*k);
        block(lo, hi, 0);
    }

    // freeze
    // fully reduce h
    uint32_t cc;
    cc = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += cc;
    cc = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += cc;
    cc = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += cc;
    cc = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += cc * 5;
    cc = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += cc;

    // h - p
    uint32_t g[5];
    g[0] = h[0] + 5;
    cc = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + cc;
    cc = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + cc;
    cc = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + cc;
    cc = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + cc - (1u << 26);

    uint32_t mask = (g[4] >> 31) - 1;
    g[0] &= mask; g[1] &= mask; g[2] &= mask; g[3] &= mask; g[4] &= mask;
    mask = ~mask;
    h[0] = (h[0] & mask) | g[0];
    h[1] = (h[1] & mask) | g[1];
    h[2] = (h[2] & mask) | g[2];
    h[3] = (h[3] & mask) | g[3];
    h[4] = (h[4] & mask) | g[4];

    // pack to 128-bit little endian
    uint64_t H0 = (uint64_t)h[0] | ((uint64_t)h[1] << 26) | ((uint64_t)h[2] << 52);
    uint64_t H1 = ((uint64_t)h[2] >> 12) | ((uint64_t)h[3] << 14) | ((uint64_t)h[4] << 40);

    // add s
    uint64_t T0 = H0 + s0;
    uint64_t carry = (T0 < H0) ? 1 : 0;
    uint64_t T1 = H1 + s1 + carry;

    for (int k = 0; k < 8; k++) tag[k]   = (T0 >> (8*k)) & 0xff;
    for (int k = 0; k < 8; k++) tag[k+8] = (T1 >> (8*k)) & 0xff;
}

// ---------------------------------------------------------------------------
// Sim helpers
// ---------------------------------------------------------------------------
static int g_failures = 0;
static vluint64_t g_time = 0;

static void tick(Vpoly1305_tb* dut) {
    dut->clk_i = 0; dut->eval(); g_time++;
    dut->clk_i = 1; dut->eval(); g_time++;
}
static void reset(Vpoly1305_tb* dut) {
    dut->rst_ni = 0;
    dut->init_i = 0;
    dut->data_valid_i = 0;
    dut->finalize_i = 0;
    for (int i = 0; i < 8; i++) dut->key_i[i] = 0;
    for (int i = 0; i < 4; i++) dut->chunk_i[i] = 0;
    dut->chunk_byte_count_i = 0;
    for (int i = 0; i < 4; i++) tick(dut);
    dut->rst_ni = 1;
    tick(dut);
}

static void put_key(Vpoly1305_tb* dut, const uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        uint32_t w = 0;
        for (int b = 0; b < 4; b++) w |= (uint32_t)key[i*4 + b] << (8*b);
        dut->key_i[i] = w;
    }
}
static void put_chunk(Vpoly1305_tb* dut, const uint8_t buf[16]) {
    for (int i = 0; i < 4; i++) {
        uint32_t w = 0;
        for (int b = 0; b < 4; b++) w |= (uint32_t)buf[i*4 + b] << (8*b);
        dut->chunk_i[i] = w;
    }
}
static void read_tag(Vpoly1305_tb* dut, uint8_t tag[16]) {
    for (int i = 0; i < 4; i++) {
        uint32_t w = dut->tag_o[i];
        for (int b = 0; b < 4; b++) tag[i*4 + b] = (w >> (8*b)) & 0xff;
    }
}

static std::string hexstr(const uint8_t* b, size_t n) {
    std::string s; s.reserve(n*2);
    for (size_t i = 0; i < n; i++) {
        char tmp[3];
        std::snprintf(tmp, 3, "%02x", b[i]);
        s += tmp;
    }
    return s;
}

static std::vector<uint8_t> hex2bytes(const char* h) {
    std::vector<uint8_t> v;
    while (*h && *(h+1)) {
        unsigned x; std::sscanf(h, "%2x", &x);
        v.push_back((uint8_t)x);
        h += 2;
    }
    return v;
}

// Run a Poly1305 MAC through the DUT. msg can have arbitrary length; the
// harness slices into 16-byte chunks (last may be partial).
static void dut_poly1305(Vpoly1305_tb* dut,
                        const uint8_t key[32],
                        const uint8_t* msg, size_t msg_len,
                        uint8_t tag_out[16]) {
    // init
    while (!dut->init_ready_o) tick(dut);
    put_key(dut, key);
    dut->init_i = 1;
    tick(dut);
    dut->init_i = 0;

    // feed chunks
    size_t i = 0;
    while (i < msg_len) {
        size_t take = (msg_len - i >= 16) ? 16 : (msg_len - i);
        uint8_t buf[16] = {0};
        std::memcpy(buf, msg + i, take);
        // wait for ready
        int waited = 0;
        while (!dut->data_ready_o) {
            tick(dut);
            if (++waited > 50) { g_failures++; return; }
        }
        put_chunk(dut, buf);
        dut->chunk_byte_count_i = (uint8_t)take;
        dut->data_valid_i = 1;
        tick(dut);
        dut->data_valid_i = 0;
        i += take;
    }

    // wait for ready, then finalize
    int waited = 0;
    while (!dut->data_ready_o) {
        tick(dut);
        if (++waited > 50) { g_failures++; return; }
    }
    dut->finalize_i = 1;
    tick(dut);
    dut->finalize_i = 0;

    // wait for tag_valid
    waited = 0;
    while (!dut->tag_valid_o) {
        tick(dut);
        if (++waited > 50) { g_failures++; return; }
    }
    read_tag(dut, tag_out);
    tick(dut);  // consume valid pulse
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
static void test_rfc_vector(Vpoly1305_tb* dut) {
    std::printf("---- Test 1: RFC 8439 sec 2.5.2 vector ----\n");

    // RFC 8439 §2.5.2: key
    const char* key_hex =
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b";
    const char* msg = "Cryptographic Forum Research Group";
    const char* expected_tag_hex = "a8061dc1305136c6c22b8baf0c0127a9";

    auto key = hex2bytes(key_hex);
    auto exp = hex2bytes(expected_tag_hex);
    uint8_t tag[16];
    dut_poly1305(dut, key.data(),
                 reinterpret_cast<const uint8_t*>(msg), std::strlen(msg),
                 tag);

    std::string got = hexstr(tag, 16);
    std::string expected = hexstr(exp.data(), 16);
    if (got == expected) {
        std::printf("  [PASS] RFC 8439 vector\n");
    } else {
        std::printf("  [FAIL] RFC 8439 vector\n");
        std::printf("         expected %s\n", expected.c_str());
        std::printf("         got      %s\n", got.c_str());
        g_failures++;
    }
}

static void test_empty(Vpoly1305_tb* dut) {
    std::printf("---- Test 2: Empty message (tag = s) ----\n");
    uint8_t key[32] = {0};
    // Set s to a known pattern
    for (int i = 0; i < 16; i++) key[16 + i] = 0xa0 + i;

    uint8_t tag[16];
    // For empty message, no chunks fed; finalize directly.
    while (!dut->init_ready_o) tick(dut);
    put_key(dut, key);
    dut->init_i = 1;
    tick(dut);
    dut->init_i = 0;

    int w = 0;
    while (!dut->data_ready_o) { tick(dut); if (++w > 50) break; }
    dut->finalize_i = 1; tick(dut); dut->finalize_i = 0;
    w = 0;
    while (!dut->tag_valid_o) { tick(dut); if (++w > 50) { g_failures++; return; } }
    uint8_t got[16];
    read_tag(dut, got);
    tick(dut);

    bool ok = std::memcmp(got, key + 16, 16) == 0;
    if (ok) std::printf("  [PASS] empty -> tag == s\n");
    else { std::printf("  [FAIL] empty\n"); g_failures++; }
}

static void test_random(Vpoly1305_tb* dut, int n) {
    std::printf("---- Test 3: %d random messages cross-validated ----\n", n);
    std::srand(0xc0ffee);
    int passes = 0, fails = 0;
    for (int i = 0; i < n; i++) {
        uint8_t key[32];
        for (int j = 0; j < 32; j++) key[j] = std::rand() & 0xff;
        size_t len = std::rand() % 256;  // 0..255 bytes
        std::vector<uint8_t> msg(len);
        for (size_t j = 0; j < len; j++) msg[j] = std::rand() & 0xff;

        uint8_t expected[16], got[16];
        poly1305_sw(key, msg.data(), len, expected);
        dut_poly1305(dut, key, msg.data(), len, got);

        if (std::memcmp(expected, got, 16) == 0) {
            passes++;
        } else {
            if (fails < 3) {
                std::printf("  [FAIL] random #%d len=%zu\n", i, len);
                std::printf("         expected %s\n", hexstr(expected, 16).c_str());
                std::printf("         got      %s\n", hexstr(got, 16).c_str());
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
    Vpoly1305_tb* dut = new Vpoly1305_tb();
    reset(dut);

    test_rfc_vector(dut);
    test_empty(dut);
    test_random(dut, 100);

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
