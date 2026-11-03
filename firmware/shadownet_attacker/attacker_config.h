#pragma once

// ShadowNet independent attacker node.
// Hardware: Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262).

#define LORA_NSS_PIN       8
#define LORA_SCK_PIN       9
#define LORA_MISO_PIN      11
#define LORA_MOSI_PIN      10
#define LORA_RST_PIN       12
#define LORA_BUSY_PIN      13
#define LORA_DIO1_PIN      14
#define VEXT_PIN           36

#define LORA_FREQ_MHZ      433.0
#define LORA_BW_KHZ        125.0
#define LORA_SF            7
#define LORA_CR            7
#define LORA_SYNCWORD      0x12
#define LORA_POWER_DBM     14
#define LORA_TCXO_VOLTAGE  1.6

// Existing ShadowNet framing:
// RadioFrame = dest_hop byte + 128-byte WirePacket.

#define WIRE_PACKET_SIZE   128
#define RADIO_FRAME_SIZE  (1 + WIRE_PACKET_SIZE)

// Destination values.

#define DEST_GATEWAY       0
#define DEST_F1            1
#define DEST_F2            2

// Existing packet types.

#define TYPE_RING_INIT     0x01
#define TYPE_CARRIER       0x02

// Existing two-forwarder onion body length.

#define EXISTING_ONION_BODY_LEN 75

#define FAKE_RING_INIT_LEN 60