// ShadowNet Onion Ring — Forwarder firmware (F1 or F2)
//
// Flash firmware/tools/keygen to this board FIRST, fill in node_config.h
// with the Gateway's printed public key AND set MY_POSITION (1 for F1, 2
// for F2), then flash this sketch. Flash the exact same .ino to both
// forwarder boards — only node_config.h's MY_POSITION differs between them.
//
// Hold the BOOT button (DEMO_BUTTON_PIN) down when this board's turn comes
// up in a cycle to originate a real access request instead of relaying a
// dummy — that's your live "watch the anonymity property work" demo.
//
// Hardware target: Heltec WiFi LoRa 32 V3 (ESP32-S3 + internal SX1262).
// See README.md "Heltec V3 / SX1262 notes."

#include <RadioLib.h>
#include <SPI.h>
#include <Preferences.h>
#include "node_config.h"
#include "oled.h" 
#include "crypto.hpp"
#include "packet.hpp"
#include "ring_node.hpp"
#include "display.hpp"

using namespace shadownet;

SX1262 radio = new Module(LORA_NSS_PIN, LORA_DIO1_PIN, LORA_RST_PIN, LORA_BUSY_PIN);
Preferences prefs;
ForwarderNode node(MY_POSITION);
char g_title[16];

struct RadioFrame {
    uint8_t dest_hop; // 0 = Gateway, 1 = F1, 2 = F2
    uint8_t payload[WIRE_PACKET_SIZE];
};

// Message typed into the Serial Monitor, queued until this board's next
// uplink cycle. Truncated to CONTROL_DATA_LEN bytes (the payload size).
char g_pending[CONTROL_DATA_LEN + 1] = {0};
bool g_has_pending = false;

void pollSerialInput() {
    static char line[64];
    static size_t n = 0;
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c != '\n') {
            if (n < sizeof(line) - 1) line[n++] = c;
            continue;
        }
        line[n] = 0;
        if (n > 0) {
            snprintf(g_pending, sizeof(g_pending), "%s", line);
            g_has_pending = true;
            if (n > CONTROL_DATA_LEN) Serial.println(F("  (message truncated to 16 chars)"));
            Serial.print(F("  queued message: \""));
            Serial.print(g_pending);
            Serial.println(F("\" -- will send on next cycle"));
            oledShow(g_title, "queued:", g_pending, "sends next cycle");
        }
        n = 0;
    }
}

uint8_t nextHop() { return node.is_last() ? 0 : (uint8_t)(MY_POSITION + 1); }

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

void setup() {
    Serial.begin(115200);
    delay(1500);
    Serial.print(F("=== ShadowNet Onion Ring — Forwarder F"));
    Serial.print(MY_POSITION);
    Serial.println(F(" ==="));
    oledBegin();
    snprintf(g_title, sizeof(g_title), "FORWARDER F%d", MY_POSITION);
    oledShow(g_title, "Booting...");

    pinMode(DEMO_BUTTON_PIN, INPUT_PULLUP);

    prefs.begin("shadownet", true);
    if (!prefs.isKey("priv")) {
        Serial.println(F("FATAL: no keypair in flash. Flash tools/keygen to this board first."));
        oledShow(g_title, "FATAL:", "no keypair in flash", "flash keygen first");
        while (true) delay(1000);
    }
    KeyPair kp{};
    prefs.getBytes("priv", kp.priv, KEY_LEN);
    prefs.getBytes("pub", kp.pub, KEY_LEN);
    prefs.end();
    node.set_keypair(kp);

    uint8_t gw_pub[KEY_LEN];
    if (!hexToBytes(GATEWAY_PUBKEY_HEX, gw_pub, KEY_LEN)) {
        Serial.println(F("FATAL: GATEWAY_PUBKEY_HEX in node_config.h is malformed."));
        oledShow(g_title, "FATAL:", "bad gateway pubkey", "check node_config.h");
        while (true) delay(1000);
    }
    node.set_gateway_pubkey(gw_pub);
    Serial.println(F("Loaded keypair + Gateway link key. Waiting for ring init..."));

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
        oledShow(g_title, "FATAL:", eb);
        Serial.println(F("  (see README 'Heltec V3 / SX1262 notes')"));
        while (true) delay(1000);
    }
    radio.setDio2AsRfSwitch(true);
    Serial.println(F("Radio ready.\n"));
    oledShow(g_title, "Radio ready", "waiting for ring init");
}

void handleRingInit(const WirePacket& pkt) {
    bool ok;
    WirePacket relay = node.handle_ring_init(pkt, ok);
    if (!ok) {
        Serial.println(F("  ring_init: FAILED to decrypt (check GATEWAY_PUBKEY_HEX)"));
        oledShow(g_title, "ring init FAILED", "check GATEWAY key");
        return;
    }
    Serial.print(F("  joined ring_id="));
    Serial.println(node.active_ring_id());
    char rid[22];
    snprintf(rid, sizeof(rid), "joined ring %d", (int)node.active_ring_id());
    oledShow(g_title, rid, node.is_last() ? "" : "relayed to next hop");
    if (!node.is_last()) {
        sendFrame(nextHop(), relay);
        Serial.println(F("  relayed ring_init to next hop"));
    }
}

void handleUplinkCycle(const WirePacket& pkt) {
    bool originate = g_has_pending || digitalRead(DEMO_BUTTON_PIN) == LOW;
    uint8_t data[CONTROL_DATA_LEN] = {0};
    PacketType type = PacketType::DUMMY;
    if (originate) {
        type = PacketType::ACCESS_REQUEST;
        if (g_has_pending) memcpy(data, g_pending, strnlen(g_pending, CONTROL_DATA_LEN));
        else memcpy(data, "hii", 3); // PRG button with nothing typed
        g_has_pending = false;
        Serial.print(F("  *** originating access request: \""));
        Serial.write(data, CONTROL_DATA_LEN);
        Serial.println(F("\" ***"));
        char dat[22];
        snprintf(dat, sizeof(dat), "%.*s", (int)CONTROL_DATA_LEN, (const char*)data);
        oledShow(g_title, "ORIGINATING request", dat);
    }
    if (!originate) oledShow(g_title, "uplink cycle", "relaying dummy");
    WirePacket out = node.process_uplink_cycle(pkt, originate, type, data);
    sendFrame(nextHop(), out);
}

void handleDownlink(const WirePacket& pkt) {
    DownlinkStep step = node.process_downlink(pkt);
    if (!step.ok) {
        Serial.println(F("  downlink: FAILED to decrypt (not for our ring / tampered)"));
        oledShow(g_title, "downlink FAILED", "not our ring/tampered");
        return;
    }
    if (step.consumed) {
        Serial.print(F("  downlink DELIVERED to us: \""));
        Serial.write(step.msg.data, CONTROL_DATA_LEN);
        Serial.println(F("\" -- sending ack upstream"));
        char dl[22];
        snprintf(dl, sizeof(dl), "%.*s", (int)CONTROL_DATA_LEN, (const char*)step.msg.data);
        oledShow(g_title, "DOWNLINK DELIVERED", dl, "sending ack upstream");
        uint8_t ack[CONTROL_DATA_LEN] = {0};
        memcpy(ack, "ack", 3);
        WirePacket empty{}; // used_len=0: originate fresh, same as a cycle start
        WirePacket out = node.process_uplink_cycle(empty, true, PacketType::UPLINK_DATA, ack);
        sendFrame(nextHop(), out);
    } else {
        sendFrame(nextHop(), step.forward);
        Serial.println(F("  relayed downlink remainder to next hop"));
        oledShow(g_title, "downlink", "relayed to next hop");
    }
}

void loop() {
    pollSerialInput();
    RadioFrame f;
    int state = radio.receive(reinterpret_cast<uint8_t*>(&f), sizeof(f));
    if (state != RADIOLIB_ERR_NONE) return; // timeout / CRC error — just keep listening
    if (f.dest_hop != MY_POSITION) return;  // not our turn — ignore, keep listening

    WirePacket pkt;
    memcpy(&pkt, f.payload, WIRE_PACKET_SIZE);

    switch (static_cast<PacketType>(pkt.type)) {
        case PacketType::RING_INIT:      Serial.println(F("[frame] RING_INIT"));   handleRingInit(pkt);    break;
        case PacketType::GRANT_DOWNLINK: Serial.println(F("[frame] DOWNLINK"));    handleDownlink(pkt);    break;
        default:                         Serial.println(F("[frame] uplink cycle")); handleUplinkCycle(pkt); break;
    }
}
