#include <RadioLib.h>
#include <SPI.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include "node_config.h"
#include "crypto.hpp"
#include "packet.hpp"
#include "ring_node.hpp"
#include "display.hpp"
#include "geo.h"

using namespace shadownet;

SX1262 radio = new Module(LORA_NSS_PIN, LORA_DIO1_PIN, LORA_RST_PIN, LORA_BUSY_PIN);
Preferences prefs;
ForwarderNode node(MY_POSITION);
char g_title[16];

#if ATTACK_MODE
bool g_tamper_armed = false;
#endif

#define EVENT_HOLD_MS 5000
uint32_t g_hold_until = 0;

void oledShowHeld(const char* title, const char* l1,
                  const char* l2 = "", const char* l3 = "",
                  const char* l4 = "") {
    oledShow(title, l1, l2, l3, l4);
    g_hold_until = millis() + EVENT_HOLD_MS;
}

void oledShowRoutine(const char* title, const char* l1,
                     const char* l2 = "", const char* l3 = "",
                     const char* l4 = "") {
    if ((int32_t)(millis() - g_hold_until) < 0) return;
    oledShow(title, l1, l2, l3, l4);
}

struct RadioFrame {
    uint8_t dest_hop;
    uint8_t payload[WIRE_PACKET_SIZE];
};

#if GEO_REPORT
int32_t g_lat_e7 = HOME_LAT_E7;
int32_t g_lon_e7 = HOME_LON_E7;
char g_note[9] = DEFAULT_NOTE;
bool readGps() { return false; }
#endif

char g_pending[CONTROL_DATA_LEN + 1] = {0};
bool g_has_pending = false;

static constexpr size_t BLE_INPUT_MAX = 63;

struct BleInputLine {
    char text[BLE_INPUT_MAX + 1];
};

QueueHandle_t g_bleInputQueue = nullptr;

static const char* SHADOWNET_BLE_SERVICE_UUID =
    "12345678-1234-1234-1234-123456789000";

static const char* SHADOWNET_BLE_MESSAGE_UUID =
    "12345678-1234-1234-1234-123456789001";

class ForwarderBleServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* server) override {
        Serial.println(F("  [BLE] phone connected"));
    }

    void onDisconnect(BLEServer* server) override {
        Serial.println(F("  [BLE] phone disconnected; restarting advertising"));
        BLEDevice::startAdvertising();
    }
};

class ForwarderBleMessageCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* characteristic) override {
        if (g_bleInputQueue == nullptr) return;

        auto value = characteristic->getValue();
        const size_t valueLen = value.length();
        if (valueLen == 0) return;

        BleInputLine incoming{};
        size_t copyLen = valueLen;
        if (copyLen > BLE_INPUT_MAX) copyLen = BLE_INPUT_MAX;

        memcpy(incoming.text, value.c_str(), copyLen);
        incoming.text[copyLen] = '\0';

        if (xQueueSend(g_bleInputQueue, &incoming, 0) != pdTRUE) {
            Serial.println(F("  [BLE] input queue full; message dropped"));
        }
    }
};

void startForwarderBle() {
    g_bleInputQueue = xQueueCreate(4, sizeof(BleInputLine));

    if (g_bleInputQueue == nullptr) {
        Serial.println(F("  [BLE] failed to create input queue"));
        return;
    }

    char deviceName[24];
    snprintf(deviceName, sizeof(deviceName), "ShadowNet_F%d", MY_POSITION);
    BLEDevice::init(deviceName);

    BLEServer* server = BLEDevice::createServer();
    server->setCallbacks(new ForwarderBleServerCallbacks());

    BLEService* service = server->createService(SHADOWNET_BLE_SERVICE_UUID);

    BLECharacteristic* messageCharacteristic = service->createCharacteristic(
        SHADOWNET_BLE_MESSAGE_UUID,
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_WRITE_NR
    );

    messageCharacteristic->setCallbacks(new ForwarderBleMessageCallbacks());

    service->start();

    BLEAdvertising* advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(SHADOWNET_BLE_SERVICE_UUID);
    advertising->setScanResponse(true);
    BLEDevice::startAdvertising();

    Serial.print(F("  [BLE] advertising as "));
    Serial.println(deviceName);
}

void processInputLine(char* line, size_t n) {
    line[n] = 0;

#if ATTACK_MODE
    if (n > 0 && strcmp(line, "tamper") == 0) {
        g_tamper_armed = true;
        Serial.println(F("  [ATTACK] armed: next relayed packet gets 1 bit flipped"));
        oledShowHeld(g_title, "TAMPER ARMED", "next packet will be", "corrupted");
        return;
    }
#endif

    if (n == 0) return;

#if GEO_REPORT
    char* c1 = strchr(line, ',');

    if (c1) {
        *c1 = 0;
        char* rest = c1 + 1;
        char* c2 = strchr(rest, ',');

        if (c2) {
            *c2 = 0;
            snprintf(g_note, sizeof(g_note), "%s", c2 + 1);
        }

        g_lat_e7 = geo_parse(line);
        g_lon_e7 = geo_parse(rest);
    } else {
        snprintf(g_note, sizeof(g_note), "%s", line);
    }

    g_has_pending = true;

    char pos[24];
    GeoReport preview{};
    preview.lat_e7 = g_lat_e7;
    preview.lon_e7 = g_lon_e7;
    geo_pair(preview, pos, sizeof(pos));

    Serial.print(F("  queued report: "));
    Serial.print(pos);
    Serial.print(F("  note=\""));
    Serial.print(g_note);
    Serial.println(F("\" -- sends next cycle"));

    oledShowHeld(g_title, "queued report:", pos, g_note);

#else
    snprintf(g_pending, sizeof(g_pending), "%s", line);
    g_has_pending = true;

    if (n > CONTROL_DATA_LEN) {
        Serial.println(F("  (message truncated to 16 chars)"));
    }

    Serial.print(F("  queued message: \""));
    Serial.print(g_pending);
    Serial.println(F("\" -- will send on next cycle"));

    oledShowHeld(g_title, "queued:", g_pending, "sends next cycle");
#endif
}

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

        processInputLine(line, n);
        n = 0;
    }
}

void pollBleInput() {
    if (g_bleInputQueue == nullptr) return;

    BleInputLine incoming{};

    while (xQueueReceive(g_bleInputQueue, &incoming, 0) == pdTRUE) {
        Serial.print(F("  [BLE] received: "));
        Serial.println(incoming.text);

        processInputLine(
            incoming.text,
            strnlen(incoming.text, sizeof(incoming.text))
        );
    }
}

#if ATTACK_MODE
uint32_t g_read_tries = 0;
uint32_t g_read_wins = 0;

void attackTryRead(const WirePacket& pkt) {
    static bool control_done = false;

    if (!control_done) {
        control_done = true;

        const uint8_t probe[8] = {'c','o','n','t','r','o','l','!'};
        uint8_t nonce[NONCE_LEN], ct[8], tag[TAG_LEN], back[8];

        random_bytes(nonce, NONCE_LEN);
        aes256gcm_encrypt(node.session_key(), nonce, nullptr, 0,
                          probe, 8, ct, tag);

        bool ok = aes256gcm_decrypt(node.session_key(), nonce, nullptr, 0,
                                    ct, 8, tag, back);

        Serial.print(F("  [ATTACK] control: my key opens my own ciphertext -> "));
        Serial.println(ok ? F("YES  (so the attack code works)")
                          : F("NO   (attack code is broken)"));
    }

    uint8_t plain[ONION_BODY_LEN];

    for (size_t len = NONCE_LEN + TAG_LEN; len <= ONION_BODY_LEN; ++len) {
        size_t ct_len = len - NONCE_LEN - TAG_LEN;
        g_read_tries++;

        if (aes256gcm_decrypt(node.session_key(),
                              pkt.ciphertext,
                              nullptr, 0,
                              pkt.ciphertext + NONCE_LEN, ct_len,
                              pkt.ciphertext + NONCE_LEN + ct_len,
                              plain)) {
            g_read_wins++;
            Serial.print(F("  [ATTACK] *** PAYLOAD READ at length "));
            Serial.print(len);
            Serial.println(F(" ***"));
        }
    }

    Serial.print(F("  [ATTACK] decryption attempts so far: "));
    Serial.print(g_read_tries);
    Serial.print(F(", succeeded: "));
    Serial.println(g_read_wins);
}

uint32_t g_atk_seen = 0;
uint32_t g_atk_claims = 0;
uint16_t g_atk_len = 0;
bool g_atk_len_set = false;
bool g_atk_len_varies = false;

void attackObserve(const WirePacket& pkt) {
    g_atk_seen++;

    const bool claim = (pkt.type != (uint8_t)PacketType::CARRIER);
    if (claim) g_atk_claims++;

    if (!g_atk_len_set) {
        g_atk_len = pkt.used_len();
        g_atk_len_set = true;
    } else if (pkt.used_len() != g_atk_len) {
        g_atk_len_varies = true;
    }

    Serial.print(F("  [ATTACK] type="));
    Serial.print(pkt.type);
    Serial.print(F(" used_len="));
    Serial.print(pkt.used_len());
    Serial.print(F("  -> "));
    Serial.println(claim ? F("*** SENDER IDENTIFIED ***")
                         : F("cannot tell (identical to every other cycle)"));

    attackTryRead(pkt);

    char a[22], b[22], c[22];

    snprintf(a, sizeof(a), "watched %lu cycles", (unsigned long)g_atk_seen);
    snprintf(b, sizeof(b), "senders found: %lu", (unsigned long)g_atk_claims);
    snprintf(c, sizeof(c), "payloads read: %lu", (unsigned long)g_read_wins);

    if (claim) oledShowHeld(g_title, "*** ATTACK HIT ***", a, b, c);
    else oledShowRoutine(g_title, "ATTACK: cannot tell", a, b, c);
}
#endif

uint8_t nextHop() {
    return node.is_last() ? 0 : (uint8_t)(MY_POSITION + 1);
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

void setup() {
    Serial.begin(115200);
    delay(1500);

    startForwarderBle();

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

    int rstate = radio.begin(
        LORA_FREQ_MHZ, LORA_BW_KHZ, LORA_SF, LORA_CR, LORA_SYNCWORD,
        LORA_POWER_DBM, 8, LORA_TCXO_VOLTAGE, false
    );

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
#if ATTACK_MODE
    attackObserve(pkt);

    if (digitalRead(DEMO_BUTTON_PIN) == LOW && !g_tamper_armed) {
        g_tamper_armed = true;
        Serial.println(F("  [ATTACK] armed by button"));
        oledShowHeld(g_title, "TAMPER ARMED", "next packet will be",
                     "corrupted");
    }

    bool originate = g_has_pending;
#else
    bool originate = g_has_pending || digitalRead(DEMO_BUTTON_PIN) == LOW;
#endif

    uint8_t data[CONTROL_DATA_LEN] = {0};
    PacketType type = PacketType::DUMMY;

    if (originate) {
        type = PacketType::ACCESS_REQUEST;

#if GEO_REPORT
        readGps();

        GeoReport gr{};
        gr.lat_e7 = g_lat_e7;
        gr.lon_e7 = g_lon_e7;
        memcpy(gr.note, g_note, strnlen(g_note, sizeof(gr.note)));
        memcpy(data, &gr, CONTROL_DATA_LEN);

        g_has_pending = false;

        char pos[24];
        geo_pair(gr, pos, sizeof(pos));

        Serial.print(F("  *** originating report: "));
        Serial.print(pos);
        Serial.print(F("  note=\""));
        Serial.print(g_note);
        Serial.println(F("\" ***"));

        oledShowHeld(g_title, "SENDING REPORT", pos, g_note);
#else
        if (g_has_pending) {
            memcpy(data, g_pending, strnlen(g_pending, CONTROL_DATA_LEN));
        } else {
            memcpy(data, "enemy at gate", 13);
        }

        g_has_pending = false;

        Serial.print(F("  *** originating access request: \""));
        Serial.write(data, CONTROL_DATA_LEN);
        Serial.println(F("\" ***"));

        char dat[22];
        snprintf(dat, sizeof(dat), "%.*s", (int)CONTROL_DATA_LEN, (const char*)data);
        oledShowHeld(g_title, "ORIGINATING request", dat);
#endif
    }

#if !ATTACK_MODE
    if (!originate) oledShowRoutine(g_title, "uplink cycle", "relaying dummy");
#endif

    WirePacket out = node.process_uplink_cycle(pkt, originate, type, data);

#if ATTACK_MODE
    if (g_tamper_armed) {
        g_tamper_armed = false;
        out.ciphertext[0] ^= 0x01;
        Serial.println(F("  [ATTACK] flipped 1 bit in the relayed packet"));
        Serial.println(F("  [ATTACK] -> watch the Gateway reject this cycle"));
        oledShowHeld(g_title, "*** TAMPERED ***", "flipped 1 bit",
                     "watch the gateway");
    }
#endif

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

        oledShowHeld(g_title, "DOWNLINK DELIVERED", dl, "sending ack upstream");

        uint8_t ack[CONTROL_DATA_LEN] = {0};
        memcpy(ack, "ack", 3);

        WirePacket empty{};
        WirePacket out = node.process_uplink_cycle(
            empty, true, PacketType::UPLINK_DATA, ack
        );

        sendFrame(nextHop(), out);
    } else {
        sendFrame(nextHop(), step.forward);
        Serial.println(F("  relayed downlink remainder to next hop"));
        oledShowRoutine(g_title, "downlink", "relayed to next hop");
    }
}

void loop() {
    pollBleInput();
    pollSerialInput();

    RadioFrame f;

    int state = radio.receive(reinterpret_cast<uint8_t*>(&f), sizeof(f));
    if (state != RADIOLIB_ERR_NONE) return;
    if (f.dest_hop != MY_POSITION) return;

    WirePacket pkt;
    memcpy(&pkt, f.payload, WIRE_PACKET_SIZE);

    switch (static_cast<PacketType>(pkt.type)) {
        case PacketType::RING_INIT:
            Serial.println(F("[frame] RING_INIT"));
            handleRingInit(pkt);
            break;

        case PacketType::GRANT_DOWNLINK:
            Serial.println(F("[frame] DOWNLINK"));
            handleDownlink(pkt);
            break;

        default:
            Serial.println(F("[frame] uplink cycle"));
            handleUplinkCycle(pkt);
            break;
    }
}