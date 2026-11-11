#include <RadioLib.h>
#include <SPI.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
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

struct RadioFrame {
    uint8_t dest_hop;
    uint8_t payload[WIRE_PACKET_SIZE];
};

static_assert(sizeof(RadioFrame) == 1 + WIRE_PACKET_SIZE,
              "unexpected padding in RadioFrame");

uint16_t g_seq = 0;

static const char* SHADOWNET_BLE_SERVICE_UUID =
    "12345678-1234-1234-1234-123456789000";

static const char* SHADOWNET_BLE_STATUS_UUID =
    "12345678-1234-1234-1234-123456789002";

BLECharacteristic* g_bleStatusCharacteristic = nullptr;

class GatewayBleServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* server) override {
        Serial.println(F("  [BLE] client connected to Gateway"));
    }

    void onDisconnect(BLEServer* server) override {
        Serial.println(F("  [BLE] client disconnected; restarting advertising"));
        BLEDevice::startAdvertising();
    }
};

void startGatewayBle() {
    BLEDevice::init("ShadowNet_GW");

    BLEServer* server = BLEDevice::createServer();
    server->setCallbacks(new GatewayBleServerCallbacks());

    BLEService* service =
        server->createService(SHADOWNET_BLE_SERVICE_UUID);

    g_bleStatusCharacteristic = service->createCharacteristic(
        SHADOWNET_BLE_STATUS_UUID,
        BLECharacteristic::PROPERTY_READ |
        BLECharacteristic::PROPERTY_NOTIFY
    );

    g_bleStatusCharacteristic->addDescriptor(new BLE2902());
    g_bleStatusCharacteristic->setValue("GATEWAY_ONLINE");

    service->start();

    BLEAdvertising* advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(SHADOWNET_BLE_SERVICE_UUID);
    advertising->setScanResponse(true);

    BLEDevice::startAdvertising();

    Serial.println(F("  [BLE] advertising as ShadowNet_GW"));
}

void publishGatewayBleStatus(const char* status) {
    if (g_bleStatusCharacteristic == nullptr) return;

    g_bleStatusCharacteristic->setValue(status);
    g_bleStatusCharacteristic->notify();
}

// Battery-demo scoreboard
uint32_t g_ok = 0;
uint32_t g_rejected = 0;

void scoreLine(char* buf, size_t len) {
    snprintf(buf, len, "ok %lu   bad %lu",
             (unsigned long)g_ok,
             (unsigned long)g_rejected);
}

// Ring re-announcement
#define RING_REANNOUNCE_CYCLES 10
#define RING_REANNOUNCE_FAILS 3

uint8_t g_consecutive_fails = 0;
uint16_t g_last_announce_seq = 0;

void announceRing(const char* why) {
    Serial.print(F("[ring] announcing epoch "));
    Serial.print(RING_EPOCH_ID);
    Serial.print(F(" ("));
    Serial.print(why);
    Serial.println(F(")"));

    oledShow("GATEWAY", "announcing ring",
             "epoch " STR(RING_EPOCH_ID), why);

    WirePacket ri = gw.start_ring(RING_EPOCH_ID);

    sendFrame(1, ri);
    delay(RING_SETTLE_MS);

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

bool recvFrameFor(uint8_t want_dest_hop,
                  WirePacket& out,
                  uint32_t timeout_ms) {
    uint32_t start = millis();
    RadioFrame f;

    while (millis() - start < timeout_ms) {
        int state = radio.receive(
            reinterpret_cast<uint8_t*>(&f),
            sizeof(f)
        );

        if (state == RADIOLIB_ERR_NONE &&
            f.dest_hop == want_dest_hop) {

            memcpy(&out, f.payload, WIRE_PACKET_SIZE);
            return true;
        }
    }

    return false;
}

void setup() {
    Serial.begin(115200);
    delay(1500);

    startGatewayBle();

    Serial.println(F("=== ShadowNet Onion Ring — Gateway ==="));

    oledBegin();
    oledShow("GATEWAY", "Booting...");

    // Load persistent keypair
    prefs.begin("shadownet", true);

    if (!prefs.isKey("priv")) {
        Serial.println(F("FATAL: no keypair in flash. Flash tools/keygen to this board first."));
        oledShow("GATEWAY", "FATAL:",
                 "no keypair in flash",
                 "flash keygen first");

        while (true) delay(1000);
    }

    KeyPair kp{};

    prefs.getBytes("priv", kp.priv, KEY_LEN);
    prefs.getBytes("pub", kp.pub, KEY_LEN);

    prefs.end();

    gw.set_keypair(kp);

    uint8_t f1_pub[KEY_LEN], f2_pub[KEY_LEN];

    if (!hexToBytes(F1_PUBKEY_HEX, f1_pub, KEY_LEN) ||
        !hexToBytes(F2_PUBKEY_HEX, f2_pub, KEY_LEN)) {

        Serial.println(F("FATAL: F1_PUBKEY_HEX / F2_PUBKEY_HEX in node_config.h are malformed."));

        oledShow("GATEWAY", "FATAL:",
                 "bad F1/F2 pubkey",
                 "check node_config.h");

        while (true) delay(1000);
    }

    gw.add_forwarder(1, f1_pub);
    gw.add_forwarder(2, f2_pub);

    Serial.println(F("Loaded keypair + forwarder link keys."));

    // Heltec V3 power and SPI setup
    pinMode(VEXT_PIN, OUTPUT);
    digitalWrite(VEXT_PIN, LOW);
    delay(100);

    SPI.begin(
        LORA_SCK_PIN,
        LORA_MISO_PIN,
        LORA_MOSI_PIN,
        LORA_NSS_PIN
    );

    int rstate = radio.begin(
        LORA_FREQ_MHZ,
        LORA_BW_KHZ,
        LORA_SF,
        LORA_CR,
        LORA_SYNCWORD,
        LORA_POWER_DBM,
        8,
        LORA_TCXO_VOLTAGE,
        false
    );

    if (rstate != RADIOLIB_ERR_NONE) {
        Serial.print(F("FATAL: radio.begin() failed, code "));
        Serial.println(rstate);

        char eb[22];
        snprintf(eb, sizeof(eb), "radio.begin code %d", rstate);

        oledShow("GATEWAY", "FATAL:", eb);

        Serial.println(F("  (see README 'Heltec V3 / SX1262 notes'"));
        Serial.println(F("   or check the board pin configuration.)"));

        while (true) delay(1000);
    }

    radio.setDio2AsRfSwitch(true);

    Serial.println(F("Radio ready."));
    oledShow("GATEWAY", "Radio ready");

    // Ring initiation
    Serial.print(F("Starting ring epoch "));
    Serial.println(RING_EPOCH_ID);

    announceRing("boot");

    Serial.println(
        F("Ring init sent. (Watch F1/F2 screens for joined ring.)")
    );
}

void loop() {
    g_seq++;

    // Routine ring refresh
    if ((uint16_t)(g_seq - g_last_announce_seq) >=
        RING_REANNOUNCE_CYCLES) {
        announceRing("periodic");
    }

    Serial.print(F("[cycle "));
    Serial.print(g_seq);
    Serial.println(F("] sending carrier..."));

    char cyc[22];
    snprintf(cyc, sizeof(cyc), "cycle %u", g_seq);

    oledShow("GATEWAY", cyc, "sending carrier...");

    WirePacket carrier = gw.build_carrier(g_seq);

    sendFrame(1, carrier);

    WirePacket incoming;
    uint32_t hold_ms = RESULT_HOLD_MS;

    if (recvFrameFor(0, incoming, CARRIER_INTERVAL_MS)) {

        UplinkResult r = gw.receive_uplink(incoming);

        if (!r.valid) {
            Serial.println(F("  received a frame but it didn't decode (wrong ring / tampered?)"));

            g_rejected++;
            publishGatewayBleStatus("PACKET_REJECTED");
            g_consecutive_fails++;

            char sc[22];
            scoreLine(sc, sizeof(sc));

            oledShow("** TAMPER **",
                     cyc,
                     "packet was ALTERED",
                     "rejected by gateway",
                     sc);

        } else if (r.msg_type == PacketType::DUMMY) {

            Serial.print(F("  idle cycle (dummy content synthesized at position "));
            Serial.print(r.origin_position);
            Serial.println(F(")"));

            char pos[22];
            snprintf(pos, sizeof(pos),
                     "dummy @ pos %d",
                     (int)r.origin_position);

            g_ok++;
            publishGatewayBleStatus("IDLE_CYCLE_OK");

            char sc[22];
            scoreLine(sc, sizeof(sc));

            oledShow("GATEWAY", cyc, "idle cycle", pos, sc);

            g_consecutive_fails = 0;

        } else {

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
            publishGatewayBleStatus("REPORT_RECEIVED");

            g_consecutive_fails = 0;
            hold_ms = REPORT_HOLD_MS;

            const char* reply_line = "";

            if (r.msg_type == PacketType::ACCESS_REQUEST) {

                Serial.println(F("  -> granting + sending downlink reply..."));

                uint8_t reply[CONTROL_DATA_LEN] = {0};
                memcpy(reply, "200 OK ack", 10);

                WirePacket dl = gw.build_downlink(
                    r.origin_position,
                    PacketType::GRANT_DOWNLINK,
                    reply,
                    g_seq
                );

                sendFrame(1, dl);

                reply_line = "replied: 200 OK";
            }

            char sc[22];
            scoreLine(sc, sizeof(sc));

            oledShow("** REPORT **",
                     cyc,
                     pos,
                     note,
                     reply_line,
                     sc);
        }

        delay(hold_ms);

    } else {

        Serial.println(F("  no reply within timeout (check F1/F2 power + wiring)"));

        publishGatewayBleStatus("CYCLE_TIMEOUT");

        oledShow("GATEWAY",
                 cyc,
                 "no reply (timeout)",
                 "check F1/F2 power");

        g_consecutive_fails++;
    }

    if (g_consecutive_fails >= RING_REANNOUNCE_FAILS) {
        announceRing("recovery");
    }

    Serial.println();
}