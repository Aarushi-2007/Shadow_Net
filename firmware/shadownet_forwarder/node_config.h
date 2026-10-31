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
// --- Attack demonstration ----------------------------------------------
// Set to 1 to turn THIS board into a compromised relay. It keeps forwarding
// correctly -- a node that stopped relaying would just be noticed -- but it
// also tries to work out whether the node before it in the ring originated
// the packet it is carrying.
//
// It attacks the only thing it can read without any key: the cleartext
// header. Before the padding fix this worked perfectly, because an
// originating node stamped the real message type and the real body length
// there. The fix makes both constant, so the attack sees nothing.
//
// Enable this on F2, which sits directly after F1 in the ring and so
// carries F1's traffic. Leave it 0 on F1.
#define ATTACK_MODE 0


// --- Geo report --------------------------------------------------------
// The payload is a position fix plus a short tag instead of free text.
// Same 16 bytes, so nothing about the anonymity properties changes.
//
// With no GPS module attached the coordinates below are used. Type
// "lat,lon" or "lat,lon,NOTE" into the Serial Monitor to override them at
// run time; a line with no comma is treated as the note alone. When a real
// module arrives, fill readGps() in the sketch and the rest is unchanged.
#define GEO_REPORT  1
#define HOME_LAT_E7 317754000   // +31.7754  (IIT Mandi, Kamand)
#define HOME_LON_E7 769861000   // +76.9861
#define DEFAULT_NOTE "ENEMY"

#define DEMO_BUTTON_PIN 0   // GPIO0 ("BOOT" button) on most ESP32 dev boards

// --- Onboard OLED (SSD1306 128x64, I2C) — Heltec WiFi LoRa 32 V3 ---------
//     Shares the Vext power rail with the radio (VEXT_PIN LOW = on).
#define USE_OLED     1
#define OLED_SDA_PIN 17
#define OLED_SCL_PIN 18
#define OLED_RST_PIN 21
