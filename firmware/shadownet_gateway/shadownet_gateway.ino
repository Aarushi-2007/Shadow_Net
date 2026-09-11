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
#include "ring_node.hpp"

using namespace shadownet;

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

    // Load persistent keypair (generated once by tools/keygen).
    prefs.begin("shadownet", true);
    if (!prefs.isKey("priv")) {
        Serial.println(F("FATAL: no keypair in flash. Flash tools/keygen to this board first."));
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

    // --- Ring initiation ---------------------------------------------------
    Serial.print(F("Starting ring epoch "));
    Serial.println(RING_EPOCH_ID);
    WirePacket ri = gw.start_ring(RING_EPOCH_ID);
    sendFrame(1, ri); // -> F1
    delay(500);       // give F1 -> F2 relay time to happen over the air
    Serial.println(F("Ring init sent. (Watch F1/F2 Serial output to confirm they joined.)\n"));
}

void loop() {
    g_seq++;
    Serial.print(F("[cycle "));
    Serial.print(g_seq);
    Serial.println(F("] sending carrier..."));

    WirePacket carrier = gw.build_carrier(g_seq);
    sendFrame(1, carrier); // -> F1, who will relay through F2 and back to us

    WirePacket incoming;
    if (recvFrameFor(0, incoming, CARRIER_INTERVAL_MS)) {
        UplinkResult r = gw.receive_uplink(incoming);
        if (!r.valid) {
            Serial.println(F("  received a frame but it didn't decode (wrong ring / tampered?)"));
        } else if (r.msg_type == PacketType::DUMMY) {
            Serial.print(F("  idle cycle (dummy content synthesized at position "));
            Serial.print(r.origin_position);
            Serial.println(F(")"));
        } else {
            Serial.print(F("  ACTIVE: origin=F"));
            Serial.print(r.origin_position);
            Serial.print(F(" type="));
            Serial.print((int)r.msg_type);
            Serial.print(F(" data=\""));
            Serial.write(r.data.data(), CONTROL_DATA_LEN);
            Serial.println(F("\""));

            if (r.msg_type == PacketType::ACCESS_REQUEST) {
                Serial.println(F("  -> granting + sending downlink reply..."));
                uint8_t reply[CONTROL_DATA_LEN] = {0};
                memcpy(reply, "200 OK ack", 10);
                WirePacket dl = gw.build_downlink(r.origin_position, PacketType::GRANT_DOWNLINK, reply, g_seq);
                sendFrame(1, dl); // downlink always starts at F1
            }
        }
    } else {
        Serial.println(F("  no reply within timeout (check F1/F2 power + wiring)"));
    }
    Serial.println();
}
