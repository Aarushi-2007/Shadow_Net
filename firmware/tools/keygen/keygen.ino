// ShadowNet Onion Ring — one-time key provisioning sketch
//
// Flash this to EACH of your 3 boards ONCE, before flashing the real
// gateway/forwarder firmware. It generates a persistent X25519 keypair
// (stored in NVS flash via Preferences, so it survives reboots and
// re-flashing of the *other* sketches), and prints the board's PUBLIC key
// as a hex string over Serial.
//
// Copy that hex string into the matching *_PUBKEY_HEX slot in the other
// two boards' node_config.h (see README.md "Provisioning" for exactly
// which key goes where). This mirrors the paper's assumption (Section
// 2.1) that public keys are configured into every node before the ring
// runs — here it's a one-time, out-of-band copy-paste instead of a live
// PKI enrollment step, which is a reasonable simplification for a 3-node
// class project.

#include <Preferences.h>
#include "crypto.hpp"

using namespace shadownet;

Preferences prefs;

void printHex(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] < 0x10) Serial.print('0');
        Serial.print(buf[i], HEX);
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    delay(1500);

    prefs.begin("shadownet", false);
    KeyPair kp{};
    bool have = prefs.isKey("priv") && prefs.getBytesLength("priv") == KEY_LEN;

    if (!have) {
        Serial.println(F("No stored keypair found — generating a new one..."));
        generate_keypair(kp);
        prefs.putBytes("priv", kp.priv, KEY_LEN);
        prefs.putBytes("pub", kp.pub, KEY_LEN);
    } else {
        Serial.println(F("Existing keypair found in flash — reusing it."));
        prefs.getBytes("priv", kp.priv, KEY_LEN);
        prefs.getBytes("pub", kp.pub, KEY_LEN);
    }
    prefs.end();

    Serial.println(F("\n=== This board's PUBLIC key (copy into peers' node_config.h) ==="));
    printHex(kp.pub, KEY_LEN);
    Serial.println(F("=================================================================\n"));
    Serial.println(F("Done. You can now flash shadownet_gateway or shadownet_forwarder"));
    Serial.println(F("to this board — it will reuse the same keypair from flash."));
}

void loop() {}
