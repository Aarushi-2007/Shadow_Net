// Fill this in after running firmware/tools/keygen on F1 and F2, and
// pasting each board's printed public key hex here. See README.md
// "Provisioning" for the full walkthrough.
#pragma once

// --- Radio pins — Heltec WiFi LoRa 32 V3 (ESP32-S3 + onboard SX1262). ----
//     These are fixed by the board (internal transceiver, not user-wired),
//     taken from Heltec's published V3 pinout / RadioLib community configs.
//     If radio.begin() fails on your specific unit, these 7 numbers are the
//     first thing to re-verify — see README "Heltec V3 / SX1262 notes".
#define LORA_NSS_PIN   8    // chip select
#define LORA_SCK_PIN   9
#define LORA_MISO_PIN  11
#define LORA_MOSI_PIN  10
#define LORA_RST_PIN   12
#define LORA_BUSY_PIN  13   // SX126x BUSY line (SX1276 didn't have this — new for SX1262)
#define LORA_DIO1_PIN  14
#define VEXT_PIN       36   // Heltec-specific: external power rail gating the radio.
                             // Must be driven LOW to power the SX1262 on. Not present
                             // on your old external-SX1276 boards — new for this board.

#define LORA_FREQ_MHZ 433.0   // CHECK your board's silkscreen/listing: Heltec V3 ships in
                              // a 433, 470, 868, or 915 MHz variant — using the wrong one
                              // for your specific unit won't error, it'll just never link.
#define LORA_BW_KHZ   125.0
#define LORA_SF       9
#define LORA_CR       7
#define LORA_SYNCWORD 0x12
#define LORA_POWER_DBM 14
#define LORA_TCXO_VOLTAGE 1.6   // Heltec V3's SX1262 uses a TCXO, not a plain crystal —
                                // 1.6V is the commonly-documented value for this board;
                                // see README if radio.begin() returns a TCXO-related error.

// --- Ring topology (fixed for this milestone — see core/ring_node.hpp) --
#define RING_EPOCH_ID 7     // bump this (and reflash all 3 boards) to rotate session keys

// --- Peer public keys, 32 bytes each, as hex strings from keygen.ino ----
// EXAMPLE — replace with your real F1 / F2 output:
#define F1_PUBKEY_HEX "43E3D7B1AF65B1C45934228585FB880CE0A981182AE52D8B99D9D7B0772B8639"
#define F2_PUBKEY_HEX "07E6AD95944666B171E246B0217EFBC227B48F5A08D5B951600952D4D7D7AE1A"

// --- Demo behavior -------------------------------------------------------
#define CARRIER_INTERVAL_MS 4000   // how often the Gateway starts a new cycle
                                   // (this is your privacy/latency/duty-cycle
                                   // tradeoff — see the process guide, Phase 4)
