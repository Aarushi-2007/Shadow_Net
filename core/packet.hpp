// ShadowNet Onion Ring — wire packet format
//
// Every packet transmitted over the LoRa link is exactly WIRE_PACKET_SIZE
// bytes, always, regardless of packet type or how many onion layers are on
// it. That's not an accident: Section 3.1 of the paper is explicit that if
// packet size shrinks as layers get peeled off, an eavesdropper can
// fingerprint a node's position in the route just from size alone. Keeping
// every transmission the same size on the wire is what makes a real
// access-request indistinguishable from a dummy carrier to anyone
// listening with an SDR.
//
// Constant wire size is necessary but NOT sufficient. Everything outside
// the encrypted blob — the whole HEADER_SIZE-byte header — is cleartext and
// readable by anyone with an SDR. So the header fields must be constant
// too, not just the total length. See the ONION_BODY_LEN note below for the
// leak this project actually had, how eval/ caught it, and how it is fixed.

#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "crypto.hpp"

namespace shadownet {

// ---- Tunables --------------------------------------------------------
constexpr size_t RING_SIZE          = 2;   // number of forwarders (F1, F2) — not counting the Gateway
constexpr size_t CONTROL_DATA_LEN   = 16;  // bytes of application payload carried per control message
constexpr size_t WIRE_PACKET_SIZE   = 128; // fixed size of every transmitted packet, in bytes
constexpr size_t HEADER_SIZE        = 6;   // ring_id(1) + seq(2) + type(1) + used_len(2)
constexpr size_t CIPHERTEXT_AREA    = WIRE_PACKET_SIZE - HEADER_SIZE;

constexpr uint8_t CONTROL_MAGIC = 0xA5;

enum class PacketType : uint8_t {
    RING_INIT       = 0x01, // Gateway -> ring: nested onion assigning ring positions & session keys
    CARRIER         = 0x02, // Gateway -> ring: baseline "nothing to see here" cycle starter
    ACCESS_REQUEST  = 0x03, // a node wants to open a session with the Gateway
    GRANT_DOWNLINK  = 0x04, // Gateway -> node: downlink data / access grant
    UPLINK_DATA     = 0x05, // node -> Gateway: uplink data (spontaneous or ack-piggyback after a downlink)
    DUMMY           = 0x06, // explicit dummy content (used inside ControlMsg, distinct from an empty CARRIER)
};

// ---- Innermost plaintext, exactly what one node encrypts under its own
//      session key when it originates a message (or forwards a dummy). ----
#pragma pack(push, 1)
struct ControlMsg {
    uint8_t magic = CONTROL_MAGIC;     // sanity marker so a peeling node/gateway can recognize "this is real content"
    uint8_t origin_id = 0;             // which ring position produced this (0 = gateway / n/a)
    uint8_t msg_type = static_cast<uint8_t>(PacketType::DUMMY);
    uint8_t data[CONTROL_DATA_LEN] = {0};
};
#pragma pack(pop)
constexpr size_t CONTROL_MSG_LEN = sizeof(ControlMsg);
static_assert(CONTROL_MSG_LEN == 3 + CONTROL_DATA_LEN, "ControlMsg must be packed with no padding");

// One AES-256-GCM layer wrapping either a ControlMsg or a previous layer's
// output: [nonce(12)][ciphertext(len(plaintext))][tag(16)]
constexpr size_t layer_size(size_t inner_plain_len) {
    return NONCE_LEN + inner_plain_len + TAG_LEN;
}
// Depth-1 (single layer over a raw ControlMsg) and depth-2 (one more wrap) sizes:
constexpr size_t LAYER1_LEN = layer_size(CONTROL_MSG_LEN);
constexpr size_t LAYER2_LEN = layer_size(LAYER1_LEN);
static_assert(LAYER2_LEN <= CIPHERTEXT_AREA,
    "WIRE_PACKET_SIZE too small for a 2-hop onion — grow WIRE_PACKET_SIZE if RING_SIZE increases");

// ---- Constant-length onion bodies ------------------------------------
//
// The real (unpadded) length of an onion body once the node at ring
// position p has applied its layer. Deterministic: every node applies
// exactly one layer, and each layer adds NONCE_LEN + TAG_LEN bytes.
constexpr size_t onion_real_len(size_t p) {
    return CONTROL_MSG_LEN + p * (NONCE_LEN + TAG_LEN);
}

// EVERY uplink and downlink body is padded out to this constant before
// transmission, and `used_len` always reports exactly this value.
//
// WHY THIS EXISTS (this replaced an earlier, broken design — read this
// before writing your report, it is a genuine finding):
//
// The first version of this file kept only the *wire length* constant and
// let `used_len` carry the true body length. That is not sufficient.
// `used_len` and `type` sit in the CLEARTEXT header, outside the encrypted
// blob, so a passive listener reads them for free. Both varied with who
// originated:
//   - `type` flipped CARRIER -> ACCESS_REQUEST at exactly the hop that
//     originated, and
//   - `used_len` at the final hop was 75 B if the last forwarder relayed
//     but 47 B if it originated (it discards the incoming body and wraps
//     its own shorter message).
// Either one alone identifies the active node with certainty, without
// breaking any encryption — which defeats the entire purpose of the
// protocol. eval/ detects this; sim/'s adversary table did not, because it
// compared only packet lengths and not header contents.
//
// The fix: pad every body to ONION_BODY_LEN with RANDOM bytes (random, not
// zeros — zero padding is itself a distinguisher), always report
// used_len = ONION_BODY_LEN, and always stamp the cleartext `type` with the
// direction (CARRIER for uplink, GRANT_DOWNLINK for downlink) rather than
// the semantic message type. The true message type travels inside the
// encrypted ControlMsg, where it belongs.
//
// Each node still knows exactly how many bytes are real without being told:
// its own ring position determines it (onion_real_len above). The Gateway,
// which does not know a priori which node originated, recovers it by trial
// decryption over at most RING_SIZE candidates — the GCM auth tag makes
// that unambiguous.
constexpr size_t ONION_BODY_LEN = onion_real_len(RING_SIZE);
static_assert(ONION_BODY_LEN <= CIPHERTEXT_AREA,
    "WIRE_PACKET_SIZE too small for a constant-length RING_SIZE-hop onion");

// ---- Wire packet -------------------------------------------------------
#pragma pack(push, 1)
struct WirePacket {
    uint8_t ring_id = 0;
    uint8_t seq_hi = 0;
    uint8_t seq_lo = 0;
    uint8_t type = 0;
    uint8_t used_len_hi = 0;   // how many of ciphertext[] bytes are real (rest is zero padding)
    uint8_t used_len_lo = 0;
    uint8_t ciphertext[CIPHERTEXT_AREA] = {0};

    uint16_t seq() const { return (static_cast<uint16_t>(seq_hi) << 8) | seq_lo; }
    void set_seq(uint16_t s) { seq_hi = s >> 8; seq_lo = s & 0xFF; }
    uint16_t used_len() const { return (static_cast<uint16_t>(used_len_hi) << 8) | used_len_lo; }
    void set_used_len(uint16_t l) { used_len_hi = l >> 8; used_len_lo = l & 0xFF; }
};
#pragma pack(pop)
static_assert(sizeof(WirePacket) == WIRE_PACKET_SIZE, "WirePacket must serialize to exactly WIRE_PACKET_SIZE bytes");

} // namespace shadownet
