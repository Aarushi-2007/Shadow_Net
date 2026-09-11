// ShadowNet Onion Ring — protocol state machines
//
// This is the actual "Onion Ring" logic from Section 5 of Wu & Li,
// adapted to a fixed 2-forwarder ring (matching your 3 physical nodes:
// 1 Gateway + F1 + F2). It is pure C++ with no radio or Arduino
// dependency — sim/main.cpp exercises it over an in-memory channel,
// and firmware/*.ino wires the exact same GatewayNode / ForwarderNode
// classes to a real SX1276 over RadioLib. If it behaves correctly in
// the sim, the same protocol code runs on the boards.
//
// ---------------------------------------------------------------------
// DESIGN NOTES (read this before you present to your teacher — these are
// the deliberate adaptations from the paper, and they're exactly the kind
// of thing an "alternative solutions analysis" section should call out):
//
// 1. Ring topology is FIXED for this milestone (G -> F1 -> F2 -> G always).
//    The paper allows dynamic ring re-formation (Section 5.1); that's real
//    future work, not implemented here.
//
// 2. Session keys are DERIVED, not transmitted. The paper's ring-init
//    message (Eq. 3) carries a freshly generated session key to each node
//    inside the nested onion. Here, each node instead derives its own
//    session key as HKDF(link_key, ring_id, "shadownet-ring-session").
//    Both the Gateway and the node can compute this independently once
//    they agree on a ring_id — so the ring-init message only has to carry
//    the ring_id itself, which shrinks it a lot and removes "session key
//    in transit" as an attack surface entirely.
//
// 3. Per Section 5.2's uplink mechanism: every forwarder, every cycle,
//    applies exactly one AES-256-GCM layer to *something* — either a fresh
//    message of its own (if it wants to talk, overriding whatever it
//    received — this is the paper's collision rule, Section 5.2: "the one
//    closer to the end of the ring will always erase the previous
//    request"), or the canonical fixed-size DUMMY content (if it has
//    nothing to send AND nothing arrived yet), or the raw ciphertext it
//    received (if it has nothing to send AND something already arrived).
//    The resulting ciphertext length deterministically tells the Gateway
//    how many layers are present and therefore who originated the content
//    — see GatewayNode::receive_uplink().

#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include "crypto.hpp"
#include "packet.hpp"

namespace shadownet {

// ---- Shared helpers ------------------------------------------------

// HKDF-derive a node's long-term link key with the Gateway from a raw
// ECDH shared secret. Both sides call this with the same shared secret
// and get the same key (paper Section 2.1's Gateway<->node symmetric key).
void derive_link_key(const uint8_t ecdh_shared[KEY_LEN], uint8_t node_id,
                      uint8_t link_key_out[KEY_LEN]);

// HKDF-derive this ring epoch's session key from the link key + ring_id.
void derive_session_key(const uint8_t link_key[KEY_LEN], uint8_t ring_id,
                         uint8_t node_id, uint8_t session_key_out[KEY_LEN]);

// Result of a Gateway peeling an uplink packet.
struct UplinkResult {
    bool valid = false;
    uint8_t origin_position = 0;   // which forwarder (1..RING_SIZE) produced this content
    PacketType msg_type = PacketType::DUMMY;
    std::array<uint8_t, CONTROL_DATA_LEN> data{};
};

// Result of a forwarder peeling one layer of a downlink packet.
struct DownlinkStep {
    bool ok = false;               // false: AES-GCM tag failed to verify (wrong key / tampered / not-for-this-ring)
    bool consumed = false;         // true: this node was the target, `msg` is valid
    ControlMsg msg{};
    WirePacket forward{};          // valid when ok && !consumed: send this to the next hop
};

// ---- Gateway ---------------------------------------------------------
class GatewayNode {
public:
    void set_keypair(const KeyPair& kp) { keys_ = kp; }
    const KeyPair& keypair() const { return keys_; }

    // Register a forwarder's public key and compute the long-term link key
    // shared with it (call once per forwarder, at provisioning time).
    void add_forwarder(uint8_t position, const uint8_t forwarder_pub[KEY_LEN]);

    // Start (or rotate) a ring epoch. Derives fresh session keys for every
    // registered forwarder and returns the RING_INIT packet to send to F1
    // (position 1) — forwarders relay it onward per ForwarderNode::handle_ring_init.
    WirePacket start_ring(uint8_t ring_id);

    // Build a periodic baseline carrier (paper Section 5.2) for the active ring.
    WirePacket build_carrier(uint16_t seq) const;

    // Build a nested downlink Onion addressed to `target_position`, e.g. an
    // access-grant or downlink data delivery (paper Section 5.2).
    WirePacket build_downlink(uint8_t target_position, PacketType type,
                               const uint8_t data[CONTROL_DATA_LEN], uint16_t seq) const;

    // Peel an uplink-direction packet (carrier / access-request / uplink-data)
    // arriving from the last forwarder in the ring. Deterministically figures
    // out how many layers are present and who originated the content.
    UplinkResult receive_uplink(const WirePacket& pkt) const;

    uint8_t ring_id() const { return ring_id_; }

private:
    KeyPair keys_{};
    uint8_t ring_id_ = 0;
    // link_keys_[p] / session_keys_[p] for forwarder position p (1..RING_SIZE); index 0 unused.
    std::array<uint8_t, RING_SIZE + 1> forwarder_registered_{};
    std::array<std::array<uint8_t, KEY_LEN>, RING_SIZE + 1> link_keys_{};
    std::array<std::array<uint8_t, KEY_LEN>, RING_SIZE + 1> session_keys_{};
};

// ---- Forwarder ---------------------------------------------------------
class ForwarderNode {
public:
    ForwarderNode(uint8_t position) : position_(position) {}

    void set_keypair(const KeyPair& kp) { keys_ = kp; }
    const KeyPair& keypair() const { return keys_; }
    uint8_t position() const { return position_; }
    bool is_last() const { return position_ == RING_SIZE; }

    // Compute the long-term link key shared with the Gateway (provisioning time).
    void set_gateway_pubkey(const uint8_t gateway_pub[KEY_LEN]);

    // Process an incoming RING_INIT packet. Updates this node's active
    // ring_id + derived session key. Sets `ok` to false if the packet did
    // not decrypt under our link key (not meant for us / tampered).
    // Returns the packet to relay to the next hop (valid only if ok && !is_last()).
    WirePacket handle_ring_init(const WirePacket& pkt, bool& ok);

    // Uplink-direction cycle step (paper Section 5.2). `originate` + `type`/`data`
    // let the caller (sim or firmware main loop) inject a real access request
    // or uplink data this cycle; otherwise this node relays/dummies as required.
    WirePacket process_uplink_cycle(const WirePacket& incoming, bool originate,
                                     PacketType type, const uint8_t data[CONTROL_DATA_LEN]) const;

    // Downlink-direction step: peel one layer with this node's session key.
    DownlinkStep process_downlink(const WirePacket& incoming) const;

    uint8_t active_ring_id() const { return ring_id_; }
    const uint8_t* session_key() const { return session_key_; }

private:
    uint8_t position_;
    KeyPair keys_{};
    uint8_t link_key_[KEY_LEN] = {0};
    uint8_t ring_id_ = 0;
    uint8_t session_key_[KEY_LEN] = {0};
};

} // namespace shadownet
