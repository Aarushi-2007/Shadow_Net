// ShadowNet Onion Ring — on-board benchmark
//
// Measures the things that CANNOT be measured on a laptop, because they
// depend on this specific silicon. Flash to ONE board, open Serial Monitor
// at 115200, and copy the output straight into your DP report.
//
// Everything here exists because Wu & Li's paper explicitly assumes
// hardware you do not have. Paper Section 1:
//     "The extra computing load caused by using cryptography is not a
//      concern for Mesh networks because Mesh nodes are desktop or laptop
//      computers with sufficient power supply and computing capability."
// Your nodes are 240 MHz microcontrollers on a battery. Every test below
// checks a consequence of that assumption failing.
//
// This sketch does NOT need the radio, a ring partner, or provisioned keys
// — it generates its own throwaway keys and runs standalone. Flash it, read
// the numbers, then flash the real firmware back.

#include <Preferences.h>
#include <esp_heap_caps.h>

#include "crypto.hpp"
#include "packet.hpp"
#include "ring_node.hpp"

using namespace shadownet;

// ---------------------------------------------------------------------
static void rule(const char* title) {
    Serial.println();
    Serial.println(F("====================================================="));
    Serial.print(F(" ")); Serial.println(title);
    Serial.println(F("====================================================="));
}

// Time `iters` repetitions of fn(), report mean microseconds.
template <typename F>
static double bench_us(const char* label, int iters, F&& fn) {
    // warm up (first call pulls code into cache / triggers lazy init)
    fn();
    uint32_t t0 = micros();
    for (int i = 0; i < iters; ++i) fn();
    uint32_t t1 = micros();
    double per = double(t1 - t0) / iters;
    Serial.printf("  %-34s %9.2f us  (%d iters)\n", label, per, iters);
    return per;
}

// Collect samples and report mean + standard deviation, for the timing
// side-channel test where the SPREAD matters as much as the mean.
struct Acc {
    double n = 0, sum = 0, sumsq = 0, lo = 1e18, hi = -1e18;
    void add(double x) {
        n++; sum += x; sumsq += x * x;
        if (x < lo) lo = x;
        if (x > hi) hi = x;
    }
    double mean() const { return n ? sum / n : 0; }
    double sd() const {
        if (n < 2) return 0;
        double m = mean();
        double v = (sumsq / n) - m * m;
        return v > 0 ? sqrt(v) : 0;
    }
};

// ---------------------------------------------------------------------
static void test1_crypto_primitives() {
    rule("TEST 1 - Cryptographic primitive cost on this MCU");
    Serial.println(F("  Paper Sec 1 assumes crypto cost is negligible. Check it here."));
    Serial.println();

    KeyPair kp{};
    bench_us("X25519 keypair generation", 20, [&] { generate_keypair(kp); });

    KeyPair a{}, b{};
    generate_keypair(a);
    generate_keypair(b);
    uint8_t shared[KEY_LEN];
    double t_ecdh = bench_us("X25519 ECDH shared secret", 20,
                              [&] { ecdh_shared_secret(a.priv, b.pub, shared); });

    uint8_t okm[KEY_LEN];
    bench_us("HKDF-SHA256 derive 32 B", 200, [&] {
        hkdf_sha256(shared, KEY_LEN, (const uint8_t*)"salt", 4,
                    (const uint8_t*)"info", 4, okm, KEY_LEN);
    });

    uint8_t key[KEY_LEN], nonce[NONCE_LEN], tag[TAG_LEN];
    uint8_t pt[ONION_BODY_LEN] = {0}, ct[ONION_BODY_LEN];
    random_bytes(key, KEY_LEN);
    random_bytes(nonce, NONCE_LEN);

    const size_t inner = onion_real_len(RING_SIZE - 1);
    double t_enc = bench_us("AES-256-GCM encrypt one layer", 500, [&] {
        aes256gcm_encrypt(key, nonce, nullptr, 0, pt, inner, ct, tag);
    });
    aes256gcm_encrypt(key, nonce, nullptr, 0, pt, inner, ct, tag);
    double t_dec = bench_us("AES-256-GCM decrypt one layer", 500, [&] {
        aes256gcm_decrypt(key, nonce, nullptr, 0, ct, inner, tag, pt);
    });

    Serial.println();
    Serial.printf("  One-time provisioning cost (keygen + ECDH): dominated by ECDH at %.0f us\n", t_ecdh);
    Serial.printf("  Steady-state per-cycle crypto, a forwarder : %.0f us (1 encrypt)\n", t_enc);
    Serial.printf("  Steady-state per-cycle crypto, the gateway : %.0f us (up to %d decrypts)\n",
                  t_dec * RING_SIZE, (int)RING_SIZE);
    Serial.println(F("  Compare against ~914 ms time-on-air per LoRa frame: if the numbers"));
    Serial.println(F("  above are in the hundreds of microseconds, crypto is ~1000x cheaper"));
    Serial.println(F("  than the radio and is NOT your bottleneck. Say so with the numbers."));
}

// ---------------------------------------------------------------------
static void test2_protocol_steps() {
    rule("TEST 2 - Full protocol step cost (not just raw crypto)");

    KeyPair gk{}, k1{}, k2{};
    generate_keypair(gk);
    generate_keypair(k1);
    generate_keypair(k2);

    GatewayNode gw;
    ForwarderNode f1(1), f2(2);
    gw.set_keypair(gk);
    f1.set_keypair(k1);
    f2.set_keypair(k2);
    gw.add_forwarder(1, k1.pub);
    gw.add_forwarder(2, k2.pub);
    f1.set_gateway_pubkey(gk.pub);
    f2.set_gateway_pubkey(gk.pub);

    uint32_t t0 = micros();
    WirePacket ri = gw.start_ring(7);
    uint32_t t_ring = micros() - t0;

    bool ok1 = false, ok2 = false;
    WirePacket relay = f1.handle_ring_init(ri, ok1);
    f2.handle_ring_init(relay, ok2);
    if (!ok1 || !ok2) {
        Serial.println(F("  FATAL: ring init failed on-board — cannot continue TEST 2."));
        return;
    }
    Serial.printf("  ring init build (gateway)          %9lu us  (once per epoch)\n",
                  (unsigned long)t_ring);

    uint8_t data[CONTROL_DATA_LEN] = {0};
    memcpy(data, "bench request", 13);
    WirePacket carrier = gw.build_carrier(1);

    bench_us("gateway build_carrier", 200, [&] { carrier = gw.build_carrier(1); });

    WirePacket h1 = f1.process_uplink_cycle(carrier, false, PacketType::DUMMY, data);
    bench_us("forwarder uplink step (relay)", 200,
             [&] { h1 = f1.process_uplink_cycle(carrier, false, PacketType::DUMMY, data); });
    bench_us("forwarder uplink step (originate)", 200,
             [&] { h1 = f1.process_uplink_cycle(carrier, true, PacketType::ACCESS_REQUEST, data); });

    WirePacket h2 = f2.process_uplink_cycle(h1, false, PacketType::DUMMY, data);
    UplinkResult res = gw.receive_uplink(h2);
    Serial.printf("  gateway decode valid=%d origin=F%u\n", res.valid ? 1 : 0, res.origin_position);
    bench_us("gateway receive_uplink (peel+auth)", 200, [&] { res = gw.receive_uplink(h2); });

    WirePacket dl = gw.build_downlink(2, PacketType::GRANT_DOWNLINK, data, 2);
    bench_us("gateway build_downlink", 200,
             [&] { dl = gw.build_downlink(2, PacketType::GRANT_DOWNLINK, data, 2); });
    DownlinkStep st = f1.process_downlink(dl);
    bench_us("forwarder downlink step", 200, [&] { st = f1.process_downlink(dl); });
    Serial.printf("  downlink relay ok=%d consumed=%d\n", st.ok ? 1 : 0, st.consumed ? 1 : 0);
}

// ---------------------------------------------------------------------
static void test3_memory() {
    rule("TEST 3 - Memory footprint on this MCU");
    Serial.printf("  sizeof(WirePacket)                 %6u B\n", (unsigned)sizeof(WirePacket));
    Serial.printf("  sizeof(ControlMsg)                 %6u B\n", (unsigned)sizeof(ControlMsg));
    Serial.printf("  sizeof(GatewayNode)                %6u B  (grows with RING_SIZE)\n",
                  (unsigned)sizeof(GatewayNode));
    Serial.printf("  sizeof(ForwarderNode)              %6u B  (constant)\n",
                  (unsigned)sizeof(ForwarderNode));
    Serial.printf("  ONION_BODY_LEN (padded body)       %6u B\n", (unsigned)ONION_BODY_LEN);
    Serial.printf("  CIPHERTEXT_AREA (max body)         %6u B\n", (unsigned)CIPHERTEXT_AREA);
    Serial.println();
    Serial.printf("  free heap now                      %6u B\n", (unsigned)ESP.getFreeHeap());
    Serial.printf("  largest free block                 %6u B\n",
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    Serial.printf("  min free heap since boot           %6u B\n", (unsigned)ESP.getMinFreeHeap());
    Serial.println();
    Serial.println(F("  Note the protocol code uses std::vector internally, so heap"));
    Serial.println(F("  fragmentation over long runs is worth watching. If min-free-heap"));
    Serial.println(F("  keeps dropping across a long test, report it — that is a real"));
    Serial.println(F("  finding for an embedded implementation and an honest limitation."));
}

// ---------------------------------------------------------------------
// The decisive test. Paper Sec 5.3 claims: "The activity for an active
// node, such as sending a request, receiving a downlink packet, and sending
// an uplink packet, is indistinguishable from the activity for an inactive
// node, i.e., forwarding an 'Onion'."
//
// That argument is about CIPHERTEXT. It says nothing about TIME. On a
// microcontroller an originating node runs a different code path than a
// relaying node, and if that path is measurably slower, an adversary with a
// timestamping SDR can identify the active node without breaking any
// encryption at all — exactly the attack the whole protocol exists to stop.
//
// The host-side eval cannot settle this: it runs on a CPU ~100x faster with
// a completely different cache and branch-predictor. This is the test that
// counts.
static void test4_timing_sidechannel() {
    rule("TEST 4 - Timing side-channel: active vs idle forwarder");
    Serial.println(F("  Paper Sec 5.3 claims active and inactive nodes are"));
    Serial.println(F("  indistinguishable. It argues that about ciphertext only."));
    Serial.println(F("  This measures whether it also holds in the TIME domain."));
    Serial.println();

    KeyPair gk{}, k1{};
    generate_keypair(gk);
    generate_keypair(k1);
    GatewayNode gw;
    ForwarderNode f1(1);
    gw.set_keypair(gk);
    f1.set_keypair(k1);
    gw.add_forwarder(1, k1.pub);
    f1.set_gateway_pubkey(gk.pub);
    // position 2 must exist for the gateway to build a ring
    KeyPair k2{};
    generate_keypair(k2);
    ForwarderNode f2(2);
    f2.set_keypair(k2);
    gw.add_forwarder(2, k2.pub);
    f2.set_gateway_pubkey(gk.pub);

    WirePacket ri = gw.start_ring(7);
    bool ok = false;
    WirePacket relay = f1.handle_ring_init(ri, ok);
    f2.handle_ring_init(relay, ok);

    uint8_t data[CONTROL_DATA_LEN] = {0};
    memcpy(data, "access request", 14);

    const int N = 400;
    Acc active, idle;
    // Interleave the two cases so any thermal/clock drift affects both
    // equally rather than biasing one.
    for (int i = 0; i < N; ++i) {
        WirePacket c = gw.build_carrier(i);

        uint32_t a0 = micros();
        volatile WirePacket ra = f1.process_uplink_cycle(c, true, PacketType::ACCESS_REQUEST, data);
        uint32_t a1 = micros();
        active.add(a1 - a0);

        uint32_t b0 = micros();
        volatile WirePacket rb = f1.process_uplink_cycle(c, false, PacketType::DUMMY, data);
        uint32_t b1 = micros();
        idle.add(b1 - b0);
        (void)ra; (void)rb;
    }

    Serial.printf("  originating (active): mean %8.2f us   sd %7.2f   min %6.0f   max %6.0f\n",
                  active.mean(), active.sd(), active.lo, active.hi);
    Serial.printf("  relaying    (idle)  : mean %8.2f us   sd %7.2f   min %6.0f   max %6.0f\n",
                  idle.mean(), idle.sd(), idle.lo, idle.hi);

    double diff = active.mean() - idle.mean();
    double pooled = sqrt((active.sd() * active.sd() + idle.sd() * idle.sd()) / 2.0);
    double d = pooled > 0 ? diff / pooled : 0;
    Serial.printf("  difference          : %+8.2f us  (%.2f%%)\n",
                  diff, idle.mean() > 0 ? 100.0 * diff / idle.mean() : 0.0);
    Serial.printf("  Cohen's d           : %+8.3f   (|d| < 0.2 = negligible)\n", d);
    Serial.println();

    if (fabs(d) < 0.2) {
        Serial.println(F("  VERDICT: no meaningful timing difference. The paper's"));
        Serial.println(F("  indistinguishability claim holds in the time domain here."));
    } else {
        Serial.println(F("  VERDICT: MEASURABLE timing difference between an active and an"));
        Serial.println(F("  idle forwarder. This is a real side channel the paper does not"));
        Serial.println(F("  address. Mitigation: do not transmit as soon as processing is"));
        Serial.println(F("  done — transmit on a fixed schedule (a deadline timer), so the"));
        Serial.println(F("  time from receive to transmit is constant regardless of what"));
        Serial.println(F("  happened in between. Report this either way; a negative result"));
        Serial.println(F("  is still a result, and a positive one is a genuine finding."));
    }
    Serial.println();
    Serial.println(F("  IMPORTANT: micros() has ~1 us resolution, so if both means are only"));
    Serial.println(F("  a few microseconds apart the measurement is at its noise floor —"));
    Serial.println(F("  say that rather than claiming a precise null result."));
}

// ---------------------------------------------------------------------
static void test5_airtime_reference() {
    rule("TEST 5 - Airtime and duty cycle reference");
    // Closed-form Semtech formula, same as eval/lora_model.hpp, recomputed
    // here so the board's output is self-contained for your report.
    const int SF = 9, CR = 3;         // CR=3 => coding rate 4/7
    const double BW = 125000.0;
    const int PL = 1 + WIRE_PACKET_SIZE;  // dest_hop byte + WirePacket
    const double Tsym = pow(2.0, SF) / BW;
    const int DE = (Tsym > 0.016) ? 1 : 0;
    double num = 8.0 * PL - 4.0 * SF + 28.0 + 16.0 * 1 - 20.0 * 0;
    double den = 4.0 * (SF - 2.0 * DE);
    double nsym = 8.0 + max(ceil(num / den) * (CR + 4), 0.0);
    double Tpre = (8 + 4.25) * Tsym;
    double Tpay = nsym * Tsym;
    double Tpkt = Tpre + Tpay;

    Serial.printf("  config              : SF%d BW%.0f kHz CR4/%d, payload %d B\n",
                  SF, BW / 1000, CR + 4, PL);
    Serial.printf("  symbol time         : %.3f ms\n", Tsym * 1000);
    Serial.printf("  time on air, 1 frame: %.1f ms\n", Tpkt * 1000);
    Serial.printf("  full ring cycle (%d) : %.1f ms\n", (int)RING_SIZE + 1, (RING_SIZE + 1) * Tpkt * 1000);
    Serial.println();
    for (int interval : {4, 30, 60, 300}) {
        double duty = ((RING_SIZE + 1) * Tpkt) / interval;
        Serial.printf("  carrier every %3d s : duty cycle %6.2f%%   %s\n",
                      interval, duty * 100, duty <= 0.01 ? "within 1% limit" : "OVER 1% LIMIT");
    }
    Serial.println();
    Serial.println(F("  To verify this empirically on real hardware: timestamp the moment"));
    Serial.println(F("  before radio.transmit() and the moment it returns, on the gateway,"));
    Serial.println(F("  and compare against the figure above. RadioLib's transmit() blocks"));
    Serial.println(F("  until the packet is sent, so the delta IS the time on air."));
}

// ---------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println();
    Serial.println(F("#####################################################"));
    Serial.println(F("#  ShadowNet Onion Ring — on-board benchmark        #"));
    Serial.println(F("#  Wu & Li, 'Achieving Privacy in Mesh Networks'    #"));
    Serial.println(F("#####################################################"));
    Serial.printf("  chip        : %s rev%d, %d core(s) @ %d MHz\n",
                  ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores(),
                  ESP.getCpuFreqMHz());
    Serial.printf("  ring size   : %d forwarders\n", (int)RING_SIZE);
    Serial.printf("  wire packet : %d B (body padded to %d B)\n",
                  (int)WIRE_PACKET_SIZE, (int)ONION_BODY_LEN);

    test1_crypto_primitives();
    test2_protocol_steps();
    test3_memory();
    test4_timing_sidechannel();
    test5_airtime_reference();

    Serial.println();
    Serial.println(F("=== benchmark complete — copy everything above into your report ==="));
}

void loop() { delay(10000); }
