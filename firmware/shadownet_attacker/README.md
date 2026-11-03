# ShadowNet F3 Independent Attacker

## Purpose

F3 is an independent LoRa attacker node.

It does not join the ShadowNet ring and does not possess
Gateway, F1 or F2 cryptographic keys.

## Files

- shadownet_attacker.ino
- attacker_config.h
- README.md

## Hardware

The current code assumes:

- Heltec WiFi LoRa 32 V3
- ESP32-S3
- SX1262 LoRa radio

## Libraries

- Arduino ESP32
- RadioLib

## Upload instructions

1. Open shadownet_attacker.ino.
2. Select the Heltec WiFi LoRa 32 V3 board.
3. Select F3's USB port.
4. Compile and upload.
5. Open Serial Monitor.
6. Set baud rate to 115200.
7. Set line ending to Newline.

## Serial Monitor options

1 - Fake initialization packet to F1
2 - Fake initialization packet to F2
3 - Fake carrier packet to Gateway
m - Show menu

## Important

A successful transmission only confirms that F3 transmitted
a LoRa frame. It does not prove that the target received or
rejected it.

Check the target's Serial Monitor.

This firmware is a controlled unauthenticated-injection
demonstrator. It does not implement packet capture,
replay or transparent interception.