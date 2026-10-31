// ShadowNet Onion Ring — Gateway firmware
//
// Flash firmware/tools/keygen to this board FIRST (see README.md), then
// fill in node_config.h with F1's and F2's printed public keys, then
// flash this sketch.
//
// This drives the exact same core/ring_node.* protocol logic the sim/
// demo already proved correct on a laptop — this file's only job is
// gluing that logic to the board's onboard SX1262 over RadioLib and to
// persistent keys in flash. LoRa here is used as a shared broadcast medium
// among all 3 boards; a 1-byte `dest_hop` routing header (added only at
// this radio framing layer, NOT part of the anonymity-relevant onion
// protocol) tells each board whether a given over-the-air packet is its
// turn to act on. See README.md "Why dest_hop doesn't weaken the
// anonymity property."
//
// Hardware target: Heltec WiFi LoRa 32 V3 (ESP32-S3 + internal SX1262).
// See README.md "Heltec V3 / SX1262 notes" for the Vext power-gate,
// DIO2-as-RF-switch, and TCXO details this board needs that a plain
// external SX1276 module didn't.

#include <RadioLib.h>
#include <SPI.h>
#include <Preferences.h>
#include "node_config.h"
#include "crypto.hpp"
#include "packet.hpp"
#include "geo.h"
#include "ring_node.hpp"
#include "display.hpp"

using namespace shadownet;

#define STR_(x) #x
#define STR(x) STR_(x)

SX1262 radio = new Module(LORA_NSS_PIN, LORA_DIO1_PIN, LORA_RST_PIN, LORA_BUSY_PIN);
Preferences prefs;
GatewayNode gw;

// dest_hop values: 0 = Gateway, 1 = F1, 2 = F2
struct RadioFrame {
    uint8_t dest_hop;
    uint8_t payload[WIRE_PACKET_SIZE];
};
static_assert(sizeof(RadioFrame) == 1 + WIRE_PACKET_SIZE, "unexpected padding in RadioFrame");

uint16_t g_seq = 0;

// --- Battery-demo scoreboard -------------------------------------------
// With no Serial Monitor attached, the 128x64 screen has to carry the
// whole story on its own. These two counters are the headline: how many
// laps came back intact, and how many were rejected because something had
// altered them in flight. A tamper attack moves the second number and
// nothing else, which is the entire claim in one line of text.
uint32_t g_ok       = 0;   // laps that decrypted and verified
uint32_t g_rejected = 0;   // laps rejected -- bad auth tag / wrong ring

void scoreLine(char* buf, size_t len) {
    snprintf(buf, len, "ok %lu   bad %lu",
             (unsigned long)g_ok, (unsigned long)g_rejected);
}

// --- Ring re-announcement -----------------------------------------------
// The gateway used to announce the ring exactly once, inside setup(), so
// the whole system depended on power-on order: a forwarder that booted
// late, missed the announcement, or was reset mid-session stayed on
// ring_id 0 forever. receive_uplink() drops anything whose ring_id does
// not match, silently -- so from the outside every board looked healthy,
// counters climbing, while no message could ever complete a lap.
//
// Re-announcing on a timer makes the ring self-healing: boot the boards
// in any order, reset any of them at any time, and they rejoin within a
// few seconds on their own.
#define RING_REANNOUNCE_CYCLES 10   // routine refresh, every N cycles
#define RING_REANNOUNCE_FAILS   3   // or straight away after N bad cycles

uint8_t  g_consecutive_fails = 0;
uint16_t g_last_announce_seq = 0;

void announceRing(const char* why) {
    Serial.print(F("[ring] announcing epoch "));
    Serial.print(RING_EPOCH_ID);
    Serial.print(F(" ("));
    Serial.print(why);
    Serial.println(F(")"));

    oledShow("GATEWAY", "announcing ring", "epoch " STR(RING_EPOCH_ID), why);

    WirePacket ri = gw.start_ring(RING_EPOCH_ID);
    sendFrame(1, ri);          // -> F1, who relays the inner layer to F2
    delay(RING_SETTLE_MS);     // let the F1 -> F2 relay finish before we
                               // put a carrier on top of it

    g_last_announce_seq = g_seq;
    g_consecutive_fails = 0;
}

bool hexToBytes(const char* hex, uint8_t* out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        char hi = hex[2 * i], lo = hex[2 * i + 1];
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return true;
}

void sendFrame(uint8_t dest_hop, const WirePacket& pkt) {
    RadioFrame f;
    f.dest_hop = dest_hop;
    memcpy(f.payload, &pkt, WIRE_PACKET_SIZE);
    radio.transmit(reinterpret_cast<uint8_t*>(&f), sizeof(f));
}

// Blocking receive, filtered to a specific dest_hop, with an overall timeout.
bool recvFrameFor(uint8_t want_dest_hop, WirePacket& out, uint32_t timeout_ms) {
    uint32_t start = millis();
    RadioFrame f;
    while (millis() - start < timeout_ms) {
        int state = radio.receive(reinterpret_cast<uint8_t*>(&f), sizeof(f));
        if (state == RADIOLIB_ERR_NONE && f.dest_hop == want_dest_hop) {
            memcpy(&out, f.payload, WIRE_PACKET_SIZE);
            return true;
        }
        // wrong hop's packet, or a timeout/CRC error on this single receive
        // call — keep listening until the overall timeout above.
    }
    return false;
}

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.println(F("=== ShadowNet Onion Ring — Gateway ==="));
    oledBegin();
    oledShow("GATEWAY", "Booting...");

    // Load persistent keypair (generated once by tools/keygen).
    prefs.begin("shadownet", true);
    if (!prefs.isKey("priv")) {
        Serial.println(F("FATAL: no keypair in flash. Flash tools/keygen to this board first."));
        oledShow("GATEWAY", "FATAL:", "no keypair in flash", "flash keygen first");
        while (true) delay(1000);
    }
    KeyPair kp{};
    prefs.getBytes("priv", kp.priv, KEY_LEN);
    prefs.getBytes("pub", kp.pub, KEY_LEN);
    prefs.end();
    gw.set_keypair(kp);

    uint8_t f1_pub[KEY_LEN], f2_pub[KEY_LEN];
    if (!hexToBytes(F1_PUBKEY_HEX, f1_pub, KEY_LEN) || !hexToBytes(F2_PUBKEY_HEX, f2_pub, KEY_LEN)) {
        Serial.println(F("FATAL: F1_PUBKEY_HEX / F2_PUBKEY_HEX in node_config.h are malformed."));
        oledShow("GATEWAY", "FATAL:", "bad F1/F2 pubkey", "check node_config.h");
        while (true) delay(1000);
    }
    gw.add_forwarder(1, f1_pub);
    gw.add_forwarder(2, f2_pub);
    Serial.println(F("Loaded keypair + forwarder link keys."));

    // Heltec V3-specific: the onboard SX1262 sits behind a power gate (Vext)
    // that must be driven LOW to turn it on, and its SPI pins aren't the
    // ESP32-S3's default hardware-SPI pins, so SPI.begin() needs them
    // spelled out explicitly before radio.begin() touches the bus.
    pinMode(VEXT_PIN, OUTPUT);
    digitalWrite(VEXT_PIN, LOW);
    delay(100);
    SPI.begin(LORA_SCK_PIN, LORA_MISO_PIN, LORA_MOSI_PIN, LORA_NSS_PIN);

    int rstate = radio.begin(LORA_FREQ_MHZ, LORA_BW_KHZ, LORA_SF, LORA_CR, LORA_SYNCWORD,
                              LORA_POWER_DBM, 8, LORA_TCXO_VOLTAGE, false);
    if (rstate != RADIOLIB_ERR_NONE) {
        Serial.print(F("FATAL: radio.begin() failed, code "));
        Serial.println(rstate);
        char eb[22];
        snprintf(eb, sizeof(eb), "radio.begin code %d", rstate);
        oledShow("GATEWAY", "FATAL:", eb);
        Serial.println(F("  (see README 'Heltec V3 / SX1262 notes' — likely TCXO voltage"));
        Serial.println(F("   or a pin mismatch against your specific board revision.)"));
        while (true) delay(1000);
    }
    // Heltec V3 (like most SX1262 modules) routes the antenna RF switch
    // through the chip's DIO2 pin rather than a separate GPIO — RadioLib
    // needs to be told to drive it, or TX/RX power at the antenna is
    // wrong even though begin() reports success.
    radio.setDio2AsRfSwitch(true);
    Serial.println(F("Radio ready."));
    oledShow("GATEWAY", "Radio ready");

    // --- Ring initiation ---------------------------------------------------
    Serial.print(F("Starting ring epoch "));
    Serial.println(RING_EPOCH_ID);
    announceRing("boot");
    Serial.println(F("Ring init sent. (Watch F1/F2 screens for 'joined ring 7'.)\n"));
}

void loop() {
    g_seq++;

    // Routine refresh so a late or restarted forwarder converges by itself.
    if ((uint16_t)(g_seq - g_last_announce_seq) >= RING_REANNOUNCE_CYCLES) {
        announceRing("periodic");
    }
    Serial.print(F("[cycle "));
    Serial.print(g_seq);
    Serial.println(F("] sending carrier..."));
    char cyc[22];
    snprintf(cyc, sizeof(cyc), "cycle %u", g_seq);
    oledShow("GATEWAY", cyc, "sending carrier...");

    WirePacket carrier = gw.build_carrier(g_seq);
    sendFrame(1, carrier); // -> F1, who will relay through F2 and back to us

    WirePacket incoming;
    uint32_t hold_ms = RESULT_HOLD_MS;   // raised below when a report lands
    if (recvFrameFor(0, incoming, CARRIER_INTERVAL_MS)) {
        UplinkResult r = gw.receive_uplink(incoming);
        if (!r.valid) {
            Serial.println(F("  received a frame but it didn't decode (wrong ring / tampered?)"));
            g_rejected++;
            g_consecutive_fails++;
            {
                char sc[22];
                scoreLine(sc, sizeof(sc));
                oledShow("** TAMPER **", cyc, "packet was ALTERED",
                         "rejected by gateway", sc);
            }
        } else if (r.msg_type == PacketType::DUMMY) {
            Serial.print(F("  idle cycle (dummy content synthesized at position "));
            Serial.print(r.origin_position);
            Serial.println(F(")"));
            char pos[22];
            snprintf(pos, sizeof(pos), "dummy @ pos %d", (int)r.origin_position);
            g_ok++;
            {
                char sc[22];
                scoreLine(sc, sizeof(sc));
                oledShow("GATEWAY", cyc, "idle cycle", pos, sc);
            }
            g_consecutive_fails = 0;   // a clean lap: the ring is healthy
        } else {
            // The node number lives only in r.origin_position, which is
            // used a few lines below to address the reply and nowhere else.
            // Nothing above this layer records or displays it.
#if SHOW_ORIGIN
            Serial.print(F("  [debug] origin=F"));
            Serial.println(r.origin_position);
#endif
            GeoReport gr{};
            memcpy(&gr, r.data.data(), CONTROL_DATA_LEN);
            char pos[24], note[9] = {0};
            geo_pair(gr, pos, sizeof(pos));
            memcpy(note, gr.note, sizeof(gr.note));

            Serial.print(F("  REPORT received at "));
            Serial.print(pos);
            Serial.print(F("  note=\""));
            Serial.print(note);
            Serial.println(F("\""));

            g_ok++;
            g_consecutive_fails = 0;   // a clean lap: the ring is healthy
            hold_ms = REPORT_HOLD_MS;  // a report is worth reading

            // Send the reply BEFORE drawing, then draw once. The previous
            // version drew the report and then immediately overwrote it
            // with a "replying" screen, so the report itself was visible
            // for microseconds and never actually readable.
            const char* reply_line = "";
            if (r.msg_type == PacketType::ACCESS_REQUEST) {
                Serial.println(F("  -> granting + sending downlink reply..."));
                uint8_t reply[CONTROL_DATA_LEN] = {0};
                memcpy(reply, "200 OK ack", 10);
                WirePacket dl = gw.build_downlink(r.origin_position, PacketType::GRANT_DOWNLINK, reply, g_seq);
                sendFrame(1, dl); // downlink always starts at F1
                reply_line = "replied: 200 OK";
            }

            {
                char sc[22];
                scoreLine(sc, sizeof(sc));
                oledShow("** REPORT **", cyc, pos, note, reply_line, sc);
            }
        }
        // Keep the result on the OLED readable; otherwise the next loop()
        // iteration overwrites it with "sending carrier..." within ms.
        delay(hold_ms);
    } else {
        Serial.println(F("  no reply within timeout (check F1/F2 power + wiring)"));
        oledShow("GATEWAY", cyc, "no reply (timeout)", "check F1/F2 power");
        g_consecutive_fails++;
    }
    if (g_consecutive_fails >= RING_REANNOUNCE_FAILS) {
        // Several laps in a row came back wrong or not at all -- most
        // likely a forwarder rebooted onto the wrong epoch. Re-announce
        // rather than sit in a dead ring.
        announceRing("recovery");
    }

    Serial.println();
}
