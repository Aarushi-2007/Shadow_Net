/*
 * ShadowNet F3 - Independent Attacker
 *
 * F3 does not join the ring.
 * It does not have a ring position.
 * It does not possess legitimate ring keys.
 *
 * It transmits deliberately unauthenticated test frames.
 */

#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>

#include "attacker_config.h"

SX1262 radio = new Module(
    LORA_NSS_PIN,
    LORA_DIO1_PIN,
    LORA_RST_PIN,
    LORA_BUSY_PIN
);

uint16_t g_sequence = 1;
bool g_radio_ready = false;


// ---------------------------------------------------------
// SERIAL MENU
// ---------------------------------------------------------

void printMenu() {

    Serial.println();
    Serial.println(F("======================================"));
    Serial.println(F("       SHADOWNET F3 ATTACKER"));
    Serial.println(F("       Independent / Not in Ring"));
    Serial.println(F("======================================"));

    Serial.println(F("1. Inject unauthenticated RING_INIT -> F1"));
    Serial.println(F("2. Inject unauthenticated RING_INIT -> F2"));
    Serial.println(F("3. Inject unauthenticated CARRIER -> Gateway"));

    Serial.println(F("m. Show menu"));

    Serial.println(F("--------------------------------------"));
    Serial.println(F("Enter choice then press Return:"));
}


// ---------------------------------------------------------
// HELPER FUNCTIONS
// ---------------------------------------------------------

void put16(uint8_t* p, uint16_t value) {

    p[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(value & 0xFF);
}


void fillRandom(uint8_t* p, size_t n) {

    for (size_t i = 0; i < n; ++i) {
        p[i] = static_cast<uint8_t>(esp_random() & 0xFF);
    }
}


// ---------------------------------------------------------
// TEST FRAME TRANSMISSION
// ---------------------------------------------------------

bool transmitTestFrame(
    uint8_t destination,
    uint8_t packetType,
    uint16_t usedLength,
    const char* label
) {

    if (!g_radio_ready) {

        Serial.println(F("[F3] ERROR: radio is not ready."));

        return false;
    }

    uint8_t frame[RADIO_FRAME_SIZE] = {0};

    // Outer RadioFrame destination.

    frame[0] = destination;

    // Inner WirePacket.

    uint8_t* pkt = &frame[1];

    pkt[0] = 7;  // Existing ring epoch ID.

    put16(&pkt[1], g_sequence++);

    pkt[3] = packetType;

    put16(&pkt[4], usedLength);

    // Deliberately random, unauthenticated body.

    fillRandom(
        &pkt[6],
        WIRE_PACKET_SIZE - 6
    );

    Serial.println();

    Serial.print(F("[F3] Transmitting test frame: "));
    Serial.println(label);

    Serial.print(F("[F3] Destination hop = "));
    Serial.println(destination);

    Serial.print(F("[F3] Packet type = 0x"));
    Serial.println(packetType, HEX);

    Serial.println(
        F("[F3] Payload is intentionally unauthenticated.")
    );

    int state = radio.transmit(
        frame,
        sizeof(frame)
    );

    if (state == RADIOLIB_ERR_NONE) {

        Serial.println(F("[F3] TX complete."));

        Serial.println(
            F("[F3] Check target Serial Monitor/OLED.")
        );

        return true;
    }

    Serial.print(
        F("[F3] Radio transmit failed, RadioLib code ")
    );

    Serial.println(state);

    return false;
}


// ---------------------------------------------------------
// SETUP
// ---------------------------------------------------------

void setup() {

    Serial.begin(115200);

    delay(1500);

    Serial.println();

    Serial.println(
        F("=== ShadowNet F3 Independent Attacker ===")
    );

    Serial.println(
        F("No ring membership or cryptographic keys loaded.")
    );

    pinMode(VEXT_PIN, OUTPUT);

    digitalWrite(VEXT_PIN, LOW);

    delay(100);

    SPI.begin(
        LORA_SCK_PIN,
        LORA_MISO_PIN,
        LORA_MOSI_PIN,
        LORA_NSS_PIN
    );

    int state = radio.begin(
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

    if (state != RADIOLIB_ERR_NONE) {

        Serial.print(
            F("[F3] FATAL: radio.begin() failed, code ")
        );

        Serial.println(state);

        while (true) {
            delay(1000);
        }
    }

    radio.setDio2AsRfSwitch(true);

    g_radio_ready = true;

    Serial.println(F("[F3] LoRa radio ready."));

    Serial.println(
        F("[F3] Independent attacker mode.")
    );

    printMenu();
}


// ---------------------------------------------------------
// MAIN LOOP
// ---------------------------------------------------------

void loop() {

    if (!Serial.available()) {
        delay(5);
        return;
    }

    String command = Serial.readStringUntil('\n');

    command.trim();


    if (command == "1") {

        transmitTestFrame(
            DEST_F1,
            TYPE_RING_INIT,
            FAKE_RING_INIT_LEN,
            "fake RING_INIT addressed to F1"
        );
    }

    else if (command == "2") {

        transmitTestFrame(
            DEST_F2,
            TYPE_RING_INIT,
            FAKE_RING_INIT_LEN,
            "fake RING_INIT addressed to F2"
        );
    }

    else if (command == "3") {

        transmitTestFrame(
            DEST_GATEWAY,
            TYPE_CARRIER,
            EXISTING_ONION_BODY_LEN,
            "fake CARRIER addressed to Gateway"
        );
    }

    else if (command == "m" || command == "M") {

        printMenu();
    }

    else if (command.length() > 0) {

        Serial.println(
            F("[F3] Unknown option. Type m for menu.")
        );
    }

    delay(250);
}