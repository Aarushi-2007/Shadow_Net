// ShadowNet Onion Ring — statistical security test suite
//
// The evaluation harness (eval_main.cpp) checks whether observable fields
// are EQUAL across activity patterns. That catches a blatant leak, but
// equality is a weak test: two things can be unequal in distribution while
// never being unequal in any single comparison you happen to make. This
// file asks the stronger question a real attacker would ask:
//
//     Given a large sample of intercepted traffic, does ANY statistical
//     test distinguish "F1 was active" from "F2 was active" from "nobody
//     was active"?
//
// That is the definition of the security property. If no test beats chance,
// the anonymity claim is supported by evidence rather than by assertion.
//
// Build:
//   g++ -std=c++17 -O2 core/crypto_openssl.cpp core/ring_node.cpp \
//       eval/security_tests.cpp -o eval/shadownet_sectest -lssl -lcrypto
//   ./eval/shadownet_sectest
//
// IMPORTANT — what a PASS here does and does not mean.
// These are NECESSARY conditions, not sufficient ones. Passing every test
// below does not prove the protocol is secure; it proves that this specific
// battery of tests found no leak at this sample size. A real weakness could
// still hide below the detection threshold, or in a channel none of these
// tests look at (timing, power draw, RF fingerprinting). Statistical testing
// can refute a security claim decisively but can only ever support one
// provisionally. Say exactly that in your report — overclaiming here is the
// most common way an evaluation chapter gets torn apart.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <numeric>
#include <set>
#include <string>
#include <vector>

#include "../core/crypto.hpp"
#include "../core/packet.hpp"
#include "../core/ring_node.hpp"

using namespace shadownet;

// =====================================================================
// Statistics helpers
// =====================================================================

// Regularized upper incomplete gamma Q(a,x), by series or continued
// fraction (Numerical Recipes, standard). Needed for chi-square p-values.
static double gser(double a, double x) {
    const int ITMAX = 300;
    const double EPS = 3e-12;
    double gln = std::lgamma(a);
    if (x <= 0) return 0.0;
    double ap = a, sum = 1.0 / a, del = sum;
    for (int n = 1; n <= ITMAX; ++n) {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if (std::fabs(del) < std::fabs(sum) * EPS) break;
    }
    return sum * std::exp(-x + a * std::log(x) - gln); // this is P(a,x)
}

static double gcf(double a, double x) {
    const int ITMAX = 300;
    const double EPS = 3e-12, FPMIN = 1e-300;
    double gln = std::lgamma(a);
    double b = x + 1.0 - a, c = 1.0 / FPMIN, d = 1.0 / b, h = d;
    for (int i = 1; i <= ITMAX; ++i) {
        double an = -i * (i - a);
        b += 2.0;
        d = an * d + b; if (std::fabs(d) < FPMIN) d = FPMIN;
        c = b + an / c;  if (std::fabs(c) < FPMIN) c = FPMIN;
        d = 1.0 / d;
        double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < EPS) break;
    }
    return std::exp(-x + a * std::log(x) - gln) * h; // this is Q(a,x)
}

// Q(a,x) = upper tail
static double gammq(double a, double x) {
    if (x < 0 || a <= 0) return 1.0;
    if (x < a + 1.0) return 1.0 - gser(a, x);
    return gcf(a, x);
}

// p-value for a chi-square statistic with df degrees of freedom
static double chi2_pvalue(double chi2, double df) {
    if (df <= 0) return 1.0;
    return gammq(df / 2.0, chi2 / 2.0);
}

static const char* verdict(double p) {
    // We use 0.01 as the alarm threshold: with many tests run, 0.05 alarms
    // too often by chance alone.
    if (p < 0.001) return "*** FAIL (highly significant deviation) ***";
    if (p < 0.01)  return "*** SUSPICIOUS ***";
    return "pass";
}

// =====================================================================
// Randomness battery — run on a byte stream
// =====================================================================

struct RandomnessReport {
    double entropy_bits_per_byte = 0;
    double monobit_p = 0, runs_p = 0, uniformity_p = 0;
    double serial_corr = 0;
    size_t n_bytes = 0;
};

static RandomnessReport randomness_battery(const std::vector<uint8_t>& data) {
    RandomnessReport r;
    r.n_bytes = data.size();
    if (data.size() < 100) return r;

    // --- Shannon entropy over byte values (max 8.0 bits/byte) ---
    std::array<size_t, 256> hist{};
    for (uint8_t b : data) hist[b]++;
    for (size_t c : hist) {
        if (!c) continue;
        double p = double(c) / data.size();
        r.entropy_bits_per_byte -= p * std::log2(p);
    }

    // --- Byte-value uniformity chi-square, df = 255 ---
    double expected = double(data.size()) / 256.0;
    double chi2 = 0;
    for (size_t c : hist) {
        double d = double(c) - expected;
        chi2 += d * d / expected;
    }
    r.uniformity_p = chi2_pvalue(chi2, 255);

    // --- Monobit (frequency) test over bits, NIST SP 800-22 style ---
    long ones = 0, total_bits = long(data.size()) * 8;
    for (uint8_t b : data) ones += __builtin_popcount(b);
    double s_obs = std::fabs(2.0 * ones - total_bits) / std::sqrt(double(total_bits));
    r.monobit_p = std::erfc(s_obs / std::sqrt(2.0));

    // --- Runs test over the bit stream ---
    double pi = double(ones) / total_bits;
    if (std::fabs(pi - 0.5) < 2.0 / std::sqrt(double(total_bits))) {
        long runs = 1;
        int prev = (data[0] >> 7) & 1;
        for (size_t i = 0; i < data.size(); ++i)
            for (int bit = 7; bit >= 0; --bit) {
                if (i == 0 && bit == 7) continue;
                int cur = (data[i] >> bit) & 1;
                if (cur != prev) runs++;
                prev = cur;
            }
        double num = std::fabs(double(runs) - 2.0 * total_bits * pi * (1 - pi));
        double den = 2.0 * std::sqrt(2.0 * total_bits) * pi * (1 - pi);
        r.runs_p = std::erfc(num / den);
    } else {
        r.runs_p = 0.0; // monobit already failed; runs test is not applicable
    }

    // --- Serial correlation coefficient (lag 1) ---
    double mean = 0;
    for (uint8_t b : data) mean += b;
    mean /= data.size();
    double num = 0, den = 0;
    for (size_t i = 0; i + 1 < data.size(); ++i)
        num += (data[i] - mean) * (data[i + 1] - mean);
    for (uint8_t b : data) den += (b - mean) * (b - mean);
    r.serial_corr = den > 0 ? num / den : 0;

    return r;
}

static void print_randomness(const char* label, const RandomnessReport& r) {
    std::printf("  %s  (%zu bytes)\n", label, r.n_bytes);
    std::printf("    Shannon entropy      : %.4f bits/byte   (ideal 8.0)   %s\n",
                r.entropy_bits_per_byte,
                r.entropy_bits_per_byte > 7.9 ? "pass" : "*** LOW ***");
    std::printf("    byte uniformity chi2 : p = %.4f                       %s\n",
                r.uniformity_p, verdict(r.uniformity_p));
    std::printf("    monobit (bit freq)   : p = %.4f                       %s\n",
                r.monobit_p, verdict(r.monobit_p));
    std::printf("    runs test            : p = %.4f                       %s\n",
                r.runs_p, verdict(r.runs_p));
    std::printf("    serial correlation   : %+.5f            (ideal 0.0)   %s\n",
                r.serial_corr,
                std::fabs(r.serial_corr) < 0.02 ? "pass" : "*** CORRELATED ***");
}

// =====================================================================
// Test fixture
// =====================================================================
struct Ring {
    GatewayNode gw;
    ForwarderNode f1{1};
    ForwarderNode f2{2};
    Ring() {
        KeyPair gk{}, k1{}, k2{};
        generate_keypair(gk); generate_keypair(k1); generate_keypair(k2);
        gw.set_keypair(gk); f1.set_keypair(k1); f2.set_keypair(k2);
        gw.add_forwarder(1, k1.pub); gw.add_forwarder(2, k2.pub);
        f1.set_gateway_pubkey(gk.pub); f2.set_gateway_pubkey(gk.pub);
        WirePacket ri = gw.start_ring(7);
        bool o1 = false, o2 = false;
        WirePacket relay = f1.handle_ring_init(ri, o1);
        f2.handle_ring_init(relay, o2);
        if (!o1 || !o2) { std::printf("FATAL: ring init failed\n"); std::exit(1); }
    }
};

// Capture the final-hop packet (F2 -> Gateway) for a given activity class.
// That is the most information-rich vantage point for an attacker: it is the
// only transmission that every activity pattern reaches.
static WirePacket capture_final_hop(Ring& r, int cls, uint16_t seq) {
    const bool a1 = cls & 1, a2 = cls & 2;
    uint8_t d[CONTROL_DATA_LEN] = {0};
    std::memcpy(d, "access request!!", CONTROL_DATA_LEN);
    WirePacket c  = r.gw.build_carrier(seq);
    WirePacket h1 = r.f1.process_uplink_cycle(c,  a1, PacketType::ACCESS_REQUEST, d);
    WirePacket h2 = r.f2.process_uplink_cycle(h1, a2, PacketType::ACCESS_REQUEST, d);
    return h2;
}

static const char* CLASS_NAME[4] = {"nobody active", "F1 active", "F2 active", "both active"};

// =====================================================================
// T1 — ciphertext randomness
// =====================================================================
static void t1_ciphertext_randomness(Ring& r) {
    std::printf("\n=====================================================================\n");
    std::printf(" T1  Ciphertext randomness\n");
    std::printf("=====================================================================\n");
    std::printf("  Encrypted output must be statistically indistinguishable from\n");
    std::printf("  random. A deviation here would mean the encryption itself is\n");
    std::printf("  structurally broken, which would make every later test moot.\n\n");

    const int N = 4000;
    std::vector<uint8_t> body;
    body.reserve(N * ONION_BODY_LEN);
    for (int i = 0; i < N; ++i) {
        WirePacket p = capture_final_hop(r, i % 4, uint16_t(i));
        body.insert(body.end(), p.ciphertext, p.ciphertext + ONION_BODY_LEN);
    }
    print_randomness("full onion body (all activity classes pooled)", randomness_battery(body));
}

// =====================================================================
// T2 — is the random PADDING distinguishable from real ciphertext?
//
// This directly tests the fix that closed the header leak. Bodies are now
// padded to a constant length with random bytes. If those padding bytes were
// distinguishable from genuine ciphertext, an attacker could measure where
// the real content ends — recovering exactly the onion depth that the
// padding exists to hide, and re-opening the leak by another route.
// =====================================================================
static void t2_padding_indistinguishability(Ring& r) {
    std::printf("\n=====================================================================\n");
    std::printf(" T2  Padding vs real ciphertext\n");
    std::printf("=====================================================================\n");
    std::printf("  The leak fix pads every body to a constant length with random\n");
    std::printf("  bytes. If padding were distinguishable from real ciphertext, an\n");
    std::printf("  attacker could find where real content ends and recover the onion\n");
    std::printf("  depth anyway. This tests that it cannot.\n\n");

    // In the "F2 active" class F2 wraps its own short message, so bytes
    // [onion_real_len(1) .. ONION_BODY_LEN) are padding, and bytes
    // [0 .. onion_real_len(1)) are genuine ciphertext.
    const size_t real_end = onion_real_len(1);
    const size_t pad_len  = ONION_BODY_LEN - real_end;
    if (pad_len == 0) { std::printf("  (no padding in this configuration — skipped)\n"); return; }

    const int N = 6000;
    std::vector<uint8_t> real_bytes, pad_bytes;
    for (int i = 0; i < N; ++i) {
        WirePacket p = capture_final_hop(r, 2 /* F2 active */, uint16_t(i));
        real_bytes.insert(real_bytes.end(), p.ciphertext, p.ciphertext + real_end);
        pad_bytes.insert(pad_bytes.end(), p.ciphertext + real_end,
                          p.ciphertext + ONION_BODY_LEN);
    }

    print_randomness("real ciphertext region", randomness_battery(real_bytes));
    std::printf("\n");
    print_randomness("random padding region ", randomness_battery(pad_bytes));

    // Two-sample chi-square test of homogeneity on byte distributions.
    std::array<size_t, 256> h1{}, h2{};
    for (uint8_t b : real_bytes) h1[b]++;
    for (uint8_t b : pad_bytes)  h2[b]++;
    double n1 = double(real_bytes.size()), n2 = double(pad_bytes.size());
    double chi2 = 0;
    int df = 0;
    for (int v = 0; v < 256; ++v) {
        double tot = double(h1[v] + h2[v]);
        if (tot < 5) continue; // pooled-cell rule
        double e1 = tot * n1 / (n1 + n2), e2 = tot * n2 / (n1 + n2);
        chi2 += (h1[v] - e1) * (h1[v] - e1) / e1 + (h2[v] - e2) * (h2[v] - e2) / e2;
        df++;
    }
    df = df > 0 ? df - 1 : 1;
    double p = chi2_pvalue(chi2, df);
    std::printf("\n  two-sample homogeneity (padding vs real ciphertext):\n");
    std::printf("    chi2 = %.2f, df = %d, p = %.4f   %s\n", chi2, df, p, verdict(p));
    std::printf("    %s\n", p >= 0.01
        ? "Padding is statistically indistinguishable from real ciphertext."
        : "PADDING IS DISTINGUISHABLE — the length hiding is defeated.");
}

// =====================================================================
// T3 — THE test: can any statistic distinguish the activity classes?
// =====================================================================
static void t3_activity_indistinguishability(Ring& r) {
    std::printf("\n=====================================================================\n");
    std::printf(" T3  Activity-class indistinguishability  [the decisive test]\n");
    std::printf("=====================================================================\n");
    std::printf("  Collect many packets for each activity pattern, then test every\n");
    std::printf("  observable byte position for a distribution difference between\n");
    std::printf("  classes. This is what an attacker with unlimited captured traffic\n");
    std::printf("  and unlimited patience would actually do.\n\n");

    const int N = 6000; // packets per class
    const size_t NBYTES = WIRE_PACKET_SIZE;

    // counts[class][byte_position][byte_value]
    static std::vector<std::vector<std::array<size_t, 256>>> counts(
        4, std::vector<std::array<size_t, 256>>(NBYTES));

    for (int cls = 0; cls < 4; ++cls)
        for (int i = 0; i < N; ++i) {
            WirePacket p = capture_final_hop(r, cls, uint16_t(i));
            const uint8_t* raw = reinterpret_cast<const uint8_t*>(&p);
            for (size_t b = 0; b < NBYTES; ++b) counts[cls][b][raw[b]]++;
        }

    // For each byte position, chi-square test of homogeneity across the 4
    // classes. Then Bonferroni-correct for testing 128 positions.
    double min_p = 1.0;
    size_t worst_pos = 0;
    int constant_positions = 0, leaking_constants = 0;
    std::vector<size_t> flagged;

    for (size_t b = 0; b < NBYTES; ++b) {
        // Is this position constant across everything? (headers should be)
        std::set<uint8_t> seen_all;
        std::array<std::set<uint8_t>, 4> seen_cls;
        for (int c = 0; c < 4; ++c)
            for (int v = 0; v < 256; ++v)
                if (counts[c][b][v]) { seen_all.insert(uint8_t(v)); seen_cls[c].insert(uint8_t(v)); }

        if (seen_all.size() == 1) { constant_positions++; continue; } // same value always: no leak

        // A position that is constant WITHIN each class but differs BETWEEN
        // classes is a total, deterministic leak — the strongest possible.
        bool const_in_each = true;
        for (int c = 0; c < 4; ++c) if (seen_cls[c].size() != 1) const_in_each = false;
        if (const_in_each) {
            leaking_constants++;
            flagged.push_back(b);
            min_p = 0.0;
            worst_pos = b;
            continue;
        }

        double chi2 = 0;
        int cells = 0;
        for (int v = 0; v < 256; ++v) {
            double tot = 0;
            for (int c = 0; c < 4; ++c) tot += counts[c][b][v];
            if (tot < 5) continue;
            for (int c = 0; c < 4; ++c) {
                double e = tot / 4.0; // equal sample sizes per class
                chi2 += (counts[c][b][v] - e) * (counts[c][b][v] - e) / e;
            }
            cells++;
        }
        int df = cells > 0 ? (cells - 1) * 3 : 1;
        double p = chi2_pvalue(chi2, df);
        if (p < min_p) { min_p = p; worst_pos = b; }
        if (p * NBYTES < 0.01) flagged.push_back(b);
    }

    std::printf("  samples            : %d packets x 4 activity classes = %d total\n",
                N, N * 4);
    std::printf("  byte positions     : %zu\n", NBYTES);
    std::printf("  constant everywhere: %d  (identical in every class — cannot leak)\n",
                constant_positions);
    std::printf("  deterministic leaks: %d  (constant within a class, differs between)\n",
                leaking_constants);
    std::printf("  most extreme p     : %.6f at byte %zu\n", min_p, worst_pos);
    std::printf("  Bonferroni-corrected (x%zu): %.4f\n", NBYTES,
                std::min(1.0, min_p * NBYTES));
    std::printf("  positions flagged  : %zu\n\n", flagged.size());

    if (!flagged.empty()) {
        std::printf("  FLAGGED BYTE POSITIONS: ");
        for (size_t i = 0; i < std::min<size_t>(flagged.size(), 20); ++i)
            std::printf("%zu ", flagged[i]);
        std::printf("%s\n", flagged.size() > 20 ? "..." : "");
        std::printf("  (bytes 0-%zu are the cleartext header; %zu+ is the encrypted body)\n",
                    HEADER_SIZE - 1, HEADER_SIZE);
    }

    const bool secure = flagged.empty() && leaking_constants == 0;
    std::printf("\n  VERDICT: %s\n", secure
        ? "no byte position distinguishes the activity classes."
        : "*** LEAK DETECTED — activity class is recoverable from traffic ***");

    // Sanity check the test itself: it must be able to FIND a leak that we
    // deliberately introduce. A test that never fires is worthless.
    std::printf("\n  --- positive control (does this test actually detect leaks?) ---\n");
    {
        std::vector<std::array<size_t, 256>> ctrl(4);
        for (int c = 0; c < 4; ++c)
            for (int i = 0; i < N; ++i)
                ctrl[c][uint8_t(0x02 + (c == 0 ? 0 : 1))]++;  // the OLD `type` leak
        double chi2 = 0;
        int cells = 0;
        for (int v = 0; v < 256; ++v) {
            double tot = 0;
            for (int c = 0; c < 4; ++c) tot += ctrl[c][v];
            if (tot < 5) continue;
            for (int c = 0; c < 4; ++c) {
                double e = tot / 4.0;
                chi2 += (ctrl[c][v] - e) * (ctrl[c][v] - e) / e;
            }
            cells++;
        }
        double p = chi2_pvalue(chi2, cells > 0 ? (cells - 1) * 3 : 1);
        std::printf("  injected the pre-fix `type` leak: chi2 = %.1f, p = %.6f -> %s\n",
                    chi2, p, p < 0.01 ? "DETECTED (test works)" : "missed (test is broken!)");
    }
}

// =====================================================================
// T4 — nonce and ciphertext uniqueness
//
// Nonce reuse under the same key is catastrophic for AES-GCM: it leaks the
// XOR of plaintexts and can expose the authentication subkey, allowing
// forgery. Worth testing explicitly rather than trusting the RNG.
// =====================================================================
static void t4_nonce_uniqueness(Ring& r) {
    std::printf("\n=====================================================================\n");
    std::printf(" T4  Nonce and ciphertext uniqueness\n");
    std::printf("=====================================================================\n");
    std::printf("  AES-GCM fails catastrophically on nonce reuse under the same key:\n");
    std::printf("  it leaks the XOR of the plaintexts and can expose the auth subkey,\n");
    std::printf("  enabling forgery. This checks the RNG is actually delivering.\n\n");

    const int N = 50000;
    std::set<std::string> nonces, bodies;
    int dup_nonce = 0, dup_body = 0;
    for (int i = 0; i < N; ++i) {
        WirePacket p = capture_final_hop(r, i % 4, uint16_t(i));
        std::string n(reinterpret_cast<char*>(p.ciphertext), NONCE_LEN);
        std::string b(reinterpret_cast<char*>(p.ciphertext), ONION_BODY_LEN);
        if (!nonces.insert(n).second) dup_nonce++;
        if (!bodies.insert(b).second) dup_body++;
    }
    std::printf("  packets generated       : %d\n", N);
    std::printf("  distinct outer nonces   : %zu\n", nonces.size());
    std::printf("  repeated nonces         : %d   %s\n", dup_nonce,
                dup_nonce == 0 ? "pass" : "*** CRITICAL FAILURE ***");
    std::printf("  repeated full bodies    : %d   %s\n", dup_body,
                dup_body == 0 ? "pass" : "*** CRITICAL FAILURE ***");
    // Birthday bound sanity: with a 96-bit nonce, P(any collision in N draws)
    // ~ N^2 / 2^97, which is astronomically small — so ANY collision here
    // means the RNG is broken, not that we got unlucky.
    double expected = std::pow(double(N), 2) / std::pow(2.0, 97);
    std::printf("  expected collisions at this N (96-bit nonce): %.3e\n", expected);
    std::printf("  So any collision above would indicate a broken RNG, not bad luck.\n");

    // Identical plaintext must still produce different ciphertext every time
    // (semantic security / IND-CPA).
    std::printf("\n  identical-plaintext test: same message, %d transmissions\n", 1000);
    std::set<std::string> repeated;
    for (int i = 0; i < 1000; ++i) {
        WirePacket p = capture_final_hop(r, 1 /* F1 active, same data each time */, 42);
        repeated.insert(std::string(reinterpret_cast<char*>(p.ciphertext), ONION_BODY_LEN));
    }
    std::printf("  distinct ciphertexts    : %zu / 1000   %s\n", repeated.size(),
                repeated.size() == 1000 ? "pass (semantically secure)"
                                         : "*** DETERMINISTIC — IND-CPA BROKEN ***");
}

// =====================================================================
// T5 — avalanche: plaintext and key sensitivity
// =====================================================================
static void t5_avalanche() {
    std::printf("\n=====================================================================\n");
    std::printf(" T5  Avalanche effect\n");
    std::printf("=====================================================================\n");
    std::printf("  Flipping one input bit should flip ~50%% of output bits. Anything\n");
    std::printf("  much below that indicates structure surviving encryption.\n\n");

    const int N = 2000;
    uint8_t key[KEY_LEN], nonce[NONCE_LEN];
    random_bytes(key, KEY_LEN);
    random_bytes(nonce, NONCE_LEN);
    const size_t PL = CONTROL_MSG_LEN;

    auto bit_diff = [&](const uint8_t* a, const uint8_t* b, size_t len) {
        int d = 0;
        for (size_t i = 0; i < len; ++i) d += __builtin_popcount(uint8_t(a[i] ^ b[i]));
        return d;
    };

    // --- plaintext avalanche ---
    double sum = 0;
    for (int i = 0; i < N; ++i) {
        uint8_t pt[PL], pt2[PL], ct[PL], ct2[PL], tag[TAG_LEN], tag2[TAG_LEN];
        random_bytes(pt, PL);
        std::memcpy(pt2, pt, PL);
        pt2[i % PL] ^= (1 << (i % 8));
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt,  PL, ct,  tag);
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt2, PL, ct2, tag2);
        sum += 100.0 * bit_diff(ct, ct2, PL) / (PL * 8);
    }
    double pt_av = sum / N;
    // GCM is a counter mode: ciphertext = plaintext XOR keystream, so one
    // flipped plaintext bit flips exactly one ciphertext bit BY DESIGN. The
    // expected value is therefore 1/(PL*8), not 50%. Judging this against a
    // 50% target would be a false alarm — the diffusion that matters in an
    // AEAD lives in the authentication tag, which is checked next.
    const double expected_ctr = 100.0 / (PL * 8);
    const bool ctr_ok = std::fabs(pt_av - expected_ctr) < 0.15;
    std::printf("  1-bit plaintext change -> %.2f%% of ciphertext bits flip\n", pt_av);
    std::printf("    expected for a counter mode: %.2f%% (exactly one bit)      %s\n",
                expected_ctr, ctr_ok ? "pass" : "*** UNEXPECTED ***");
    std::printf("    This is correct GCM behaviour, NOT a weakness: ciphertext is\n");
    std::printf("    plaintext XOR keystream. Integrity comes from the tag, below —\n");
    std::printf("    that is what makes a flipped bit detectable rather than silent.\n");

    // --- tag avalanche (this is the meaningful one for GCM) ---
    sum = 0;
    for (int i = 0; i < N; ++i) {
        uint8_t pt[PL], pt2[PL], ct[PL], ct2[PL], tag[TAG_LEN], tag2[TAG_LEN];
        random_bytes(pt, PL);
        std::memcpy(pt2, pt, PL);
        pt2[i % PL] ^= (1 << (i % 8));
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt,  PL, ct,  tag);
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt2, PL, ct2, tag2);
        sum += 100.0 * bit_diff(tag, tag2, TAG_LEN) / (TAG_LEN * 8);
    }
    double tag_av = sum / N;
    std::printf("\n  1-bit plaintext change -> %.2f%% of AUTH TAG bits flip     %s\n",
                tag_av, (tag_av > 45 && tag_av < 55) ? "pass" : "*** OUT OF RANGE ***");

    // --- key avalanche ---
    sum = 0;
    for (int i = 0; i < N; ++i) {
        uint8_t k2[KEY_LEN], pt[PL], ct[PL], ct2[PL], tag[TAG_LEN], tag2[TAG_LEN];
        random_bytes(pt, PL);
        std::memcpy(k2, key, KEY_LEN);
        k2[i % KEY_LEN] ^= (1 << (i % 8));
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt, PL, ct,  tag);
        aes256gcm_encrypt(k2,  nonce, nullptr, 0, pt, PL, ct2, tag2);
        sum += 100.0 * bit_diff(ct, ct2, PL) / (PL * 8);
    }
    double key_av = sum / N;
    std::printf("  1-bit KEY change       -> %.2f%% of ciphertext bits flip   %s\n",
                key_av, (key_av > 45 && key_av < 55) ? "pass" : "*** OUT OF RANGE ***");
}

// =====================================================================
// T6 — key separation: does one node's key ever open another node's layer?
// =====================================================================
static void t6_key_separation(Ring& r) {
    std::printf("\n=====================================================================\n");
    std::printf(" T6  Key separation between ring positions\n");
    std::printf("=====================================================================\n");
    std::printf("  Each forwarder derives its own session key via HKDF from its own\n");
    std::printf("  ECDH secret. A compromised F1 must not be able to read F2's layer,\n");
    std::printf("  or the anonymity set collapses the moment any single node is\n");
    std::printf("  compromised. This checks the key derivation actually separates.\n\n");

    const int N = 3000;
    int wrong_key_success = 0;
    for (int i = 0; i < N; ++i) {
        WirePacket p = capture_final_hop(r, i % 4, uint16_t(i));
        // F1 tries to peel the outermost layer, which belongs to F2.
        DownlinkStep s = r.f1.process_downlink(p);
        if (s.ok) wrong_key_success++;
    }
    std::printf("  attempts by F1 to open F2's layer : %d\n", N);
    std::printf("  successes                          : %d   %s\n", wrong_key_success,
                wrong_key_success == 0 ? "pass (keys are properly separated)"
                                        : "*** KEY SEPARATION BROKEN ***");
    std::printf("  expected by chance (GCM tag forgery, 2^-128): ~%.3e\n",
                double(N) / std::pow(2.0, 128));
}

// =====================================================================
int main() {
    std::printf("=====================================================================\n");
    std::printf(" ShadowNet Onion Ring — statistical security test suite\n");
    std::printf("=====================================================================\n");
    std::printf(" Ring size %zu, wire packet %zu B, onion body %zu B\n",
                RING_SIZE, WIRE_PACKET_SIZE, ONION_BODY_LEN);
    std::printf(" Alarm threshold p < 0.01 (not 0.05: many tests are run, so 0.05\n");
    std::printf(" would produce false alarms by chance alone).\n");

    Ring r;
    t1_ciphertext_randomness(r);
    t2_padding_indistinguishability(r);
    t3_activity_indistinguishability(r);
    t4_nonce_uniqueness(r);
    t5_avalanche();
    t6_key_separation(r);

    std::printf("\n=====================================================================\n");
    std::printf(" How to report these results honestly\n");
    std::printf("=====================================================================\n");
    std::printf("\n These tests are NECESSARY conditions, not sufficient ones.\n");
    std::printf(" Passing them does not prove the protocol is secure. It shows that\n");
    std::printf(" this battery, at this sample size, found no leak. A weakness could\n");
    std::printf(" still sit below the detection threshold, or in a channel none of\n");
    std::printf(" these tests observe.\n");
    std::printf("\n Specifically NOT covered here, and worth naming in your report:\n");
    std::printf("   - TIMING. Tested separately (eval B6 on host, bench.ino TEST 4 on\n");
    std::printf("     the board). A timing leak breaks anonymity just as completely as\n");
    std::printf("     a header leak, and none of the tests above would see it.\n");
    std::printf("   - POWER ANALYSIS. An attacker with physical access to a node can\n");
    std::printf("     read its power draw. Out of scope here, but it exists.\n");
    std::printf("   - RF FINGERPRINTING. Individual radios have measurable hardware\n");
    std::printf("     quirks. This identifies the TRANSMITTER regardless of protocol,\n");
    std::printf("     and no onion scheme (Tor included) ever claimed to stop it.\n");
    std::printf("   - TRAFFIC ANALYSIS OVER TIME. These tests treat packets\n");
    std::printf("     independently. Correlations ACROSS cycles (intersection attacks,\n");
    std::printf("     paper Sec 5.3) are a real threat this suite does not model.\n");
    std::printf("\n The honest one-line claim you can defend:\n");
    std::printf("   \"No statistical test in our battery distinguished the activity\n");
    std::printf("    classes at n=6000 samples per class (Bonferroni-corrected\n");
    std::printf("    p > 0.01 across all 128 byte positions).\"\n");
    std::printf("\n That is a real, defensible, falsifiable result. \"Our protocol is\n");
    std::printf(" secure\" is not.\n\n");
    return 0;
}
