// Fill this in after running firmware/tools/keygen on the Gateway board,
// and pasting its printed public key hex here. See README.md
// "Provisioning" for the full walkthrough.
#pragma once

// --- Which forwarder is THIS board? Set to 1 for F1, 2 for F2, before
//     flashing (flash this same .ino twice, once per board, changing only
//     this line and re-uploading).
#define MY_POSITION 1

// --- Radio pins — Heltec WiFi LoRa 32 V3 (ESP32-S3 + onboard SX1262). ----
//     Fixed by the board (internal transceiver). Same values as the
//     Gateway's node_config.h — must match across all 3 boards.
#define LORA_NSS_PIN   8
#define LORA_SCK_PIN   9
#define LORA_MISO_PIN  11
#define LORA_MOSI_PIN  10
#define LORA_RST_PIN   12
#define LORA_BUSY_PIN  13
#define LORA_DIO1_PIN  14
#define VEXT_PIN       36   // must be driven LOW to power the onboard SX1262 on

#define LORA_FREQ_MHZ 433.0   // CHECK your board's silkscreen/listing — see gateway's
                              // node_config.h comment; must match the Gateway exactly.
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
#define LORA_TCXO_VOLTAGE 1.6

// --- Gateway's public key, 32 bytes as hex from keygen.ino --------------
#define GATEWAY_PUBKEY_HEX "DF8847ACB4F49EE879A2BAC8F65B5FF1611328C9811429B9166700016438025F"

// --- Demo behavior: does THIS board originate a request on a button press?
//     Wire a push-button to this pin (active-low, internal pullup) to
//     trigger an access request during a live demo instead of scripting one.
#define DEMO_BUTTON_PIN 0   // GPIO0 ("BOOT" button) on most ESP32 dev boards

// --- Onboard OLED (SSD1306 128x64, I2C) — Heltec WiFi LoRa 32 V3 ---------
//     Shares the Vext power rail with the radio (VEXT_PIN LOW = on).
#define USE_OLED     1
#define OLED_SDA_PIN 17
#define OLED_SCL_PIN 18
#define OLED_RST_PIN 21
