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
// Spreading factor. This was 9, and that was the bug that made the ring
// never close: at SF9 a 129-byte frame spends 914 ms in the air, so one
// G->F1->F2->G lap costs ~2.75 s of pure transmission before any crypto,
// radio turnaround or missed receive window is counted. The gateway only
// waits CARRIER_INTERVAL_MS (4 s) for the lap to finish, so a single
// hiccup anywhere pushed the reply past the deadline and the gateway
// logged a timeout -- every cycle, forever, while the forwarders happily
// relayed and looked perfectly healthy.
//
// SF7 cuts a frame to 293 ms and a full lap to ~880 ms, leaving over 4x
// headroom in the same window. Range drops (SF7 is the shortest-range
// setting), but for three boards on a bench that is irrelevant.
// MUST be identical on all three boards.
#define LORA_SF       7
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
// How long to wait after announcing the ring before the first carrier
// goes out. The old value was an inline delay(500), which was shorter
// than the time F1 needs just to RECEIVE the announcement (914 ms at
// SF9) -- so the gateway started transmitting carriers while F1 was
// still relaying the announcement to F2, and the two collided. F2
// therefore never joined, sat on ring_id 0, and every packet it sent
// was discarded by the gateway's ring_id check.
// --- Operator view -----------------------------------------------------
// The Gateway must know which ring position originated a packet: it has to
// encrypt the reply under that node's session key, so there is no way to
// make the routing layer blind. What CAN be withheld is everything above
// it -- the display and the log.
//
// With SHOW_ORIGIN 0 the node number is used only inside the few lines
// that build the reply, and is never printed, shown or stored. The
// operator sees a report identified solely by where it came from on the
// ground. Set to 1 while debugging, when you need to know which board
// is talking.
#define SHOW_ORIGIN 0

#define RING_SETTLE_MS 2500

// How long the OLED holds a result before the next cycle overwrites it.
// These are blocking delays on the Gateway, which paces the ring, so they
// set the visible cycle length. They affect NOTHING in the protocol --
// raise them freely for a demo, lower them when collecting timing data.
//
// Two values, because an idle cycle is not worth staring at while a real
// report is: idle cycles stay brisk and reports stay up long enough to
// read out loud.
#define RESULT_HOLD_MS 2500        // an idle / dummy cycle
#define REPORT_HOLD_MS 9000        // a real report arrived -- hold it
                                   // (this is your privacy/latency/duty-cycle
                                   // tradeoff — see the process guide, Phase 4)

// --- Onboard OLED (SSD1306 128x64, I2C) — Heltec WiFi LoRa 32 V3 ---------
//     Shares the Vext power rail with the radio (VEXT_PIN LOW = on).
#define USE_OLED     1
#define OLED_SDA_PIN 17
#define OLED_SCL_PIN 18
#define OLED_RST_PIN 21
