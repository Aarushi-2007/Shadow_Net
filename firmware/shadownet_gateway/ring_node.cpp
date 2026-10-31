#include "ring_node.hpp"
#include <cstring>
#include <vector>

namespace shadownet {

// ---- key derivation ----------------------------------------------------

void derive_link_key(const uint8_t ecdh_shared[KEY_LEN], uint8_t node_id,
                      uint8_t link_key_out[KEY_LEN]) {
    const uint8_t salt[] = "shadownet-link-v1";
    uint8_t info[1] = {node_id};
    hkdf_sha256(ecdh_shared, KEY_LEN, salt, sizeof(salt) - 1, info, sizeof(info),
                link_key_out, KEY_LEN);
}

void derive_session_key(const uint8_t link_key[KEY_LEN], uint8_t ring_id,
                         uint8_t node_id, uint8_t session_key_out[KEY_LEN]) {
    const uint8_t salt[] = "shadownet-ring-session-v1";
    uint8_t info[2] = {ring_id, node_id};
    hkdf_sha256(link_key, KEY_LEN, salt, sizeof(salt) - 1, info, sizeof(info),
                session_key_out, KEY_LEN);
}

// ---- low-level layer helpers --------------------------------------------
// One "layer" on the wire is [nonce(12)][ciphertext(n)][tag(16)].

static std::vector<uint8_t> encrypt_layer(const uint8_t key[KEY_LEN],
                                           const uint8_t* plain, size_t plain_len) {
    std::vector<uint8_t> out(NONCE_LEN + plain_len + TAG_LEN);
    random_bytes(out.data(), NONCE_LEN);
    aes256gcm_encrypt(key, out.data(), nullptr, 0, plain, plain_len,
                       out.data() + NONCE_LEN, out.data() + NONCE_LEN + plain_len);
    return out;
}

// Returns true and fills `plain_out` (must have room for in_len - 28 bytes)
// on success; false if in_len is too short or the auth tag fails to verify.
static bool decrypt_layer(const uint8_t key[KEY_LEN], const uint8_t* in, size_t in_len,
                           std::vector<uint8_t>& plain_out) {
    if (in_len < NONCE_LEN + TAG_LEN) return false;
    size_t ct_len = in_len - NONCE_LEN - TAG_LEN;
    plain_out.resize(ct_len);
    const uint8_t* nonce = in;
    const uint8_t* ct = in + NONCE_LEN;
    const uint8_t* tag = in + NONCE_LEN + ct_len;
    return aes256gcm_decrypt(key, nonce, nullptr, 0, ct, ct_len, tag, plain_out.data());
}

static WirePacket make_packet(uint8_t ring_id, uint16_t seq, PacketType type,
                               const uint8_t* ct, size_t ct_len) {
    WirePacket pkt{};
    pkt.ring_id = ring_id;
    pkt.set_seq(seq);
    pkt.type = static_cast<uint8_t>(type);
    pkt.set_used_len(static_cast<uint16_t>(ct_len));
    if (ct_len > 0) std::memcpy(pkt.ciphertext, ct, ct_len);
    return pkt;
}

// Build a packet whose body is padded out to the constant ONION_BODY_LEN
// with RANDOM bytes, so `used_len` always reports the same value no matter
// how many onion layers are actually present. The cleartext `type` passed
// here must be a DIRECTION (CARRIER / GRANT_DOWNLINK / RING_INIT), never a
// semantic message type — see the long note in packet.hpp for why both of
// these matter and what broke when they didn't hold.
static WirePacket make_padded_packet(uint8_t ring_id, uint16_t seq, PacketType wire_type,
                                      const uint8_t* real, size_t real_len) {
    WirePacket pkt{};
    pkt.ring_id = ring_id;
    pkt.set_seq(seq);
    pkt.type = static_cast<uint8_t>(wire_type);
#ifdef SHADOWNET_VULNERABLE_DEMO
    // DELIBERATELY BROKEN BUILD — never define this for real firmware.
    // Restores the original leak (true body length in the cleartext header)
    // so the security test suite can be shown detecting a real
    // vulnerability rather than only a synthetic one. See EVALUATION.md.
    pkt.set_used_len(static_cast<uint16_t>(real_len));
#else
    pkt.set_used_len(static_cast<uint16_t>(ONION_BODY_LEN));
#endif
    if (real_len > 0) std::memcpy(pkt.ciphertext, real, real_len);
    if (ONION_BODY_LEN > real_len)
        random_bytes(pkt.ciphertext + real_len, ONION_BODY_LEN - real_len);
    return pkt;
}

static ControlMsg make_control(uint8_t origin, PacketType type,
                                const uint8_t data[CONTROL_DATA_LEN]) {
    ControlMsg cm{};
    cm.magic = CONTROL_MAGIC;
    cm.origin_id = origin;
    cm.msg_type = static_cast<uint8_t>(type);
    if (data) std::memcpy(cm.data, data, CONTROL_DATA_LEN);
    return cm;
}

// ---- GatewayNode ---------------------------------------------------------

void GatewayNode::add_forwarder(uint8_t position, const uint8_t forwarder_pub[KEY_LEN]) {
    uint8_t shared[KEY_LEN];
    ecdh_shared_secret(keys_.priv, forwarder_pub, shared);
    derive_link_key(shared, position, link_keys_[position].data());
    forwarder_registered_[position] = 1;
}

WirePacket GatewayNode::start_ring(uint8_t ring_id) {
    ring_id_ = ring_id;
    for (size_t p = 1; p <= RING_SIZE; ++p) {
        derive_session_key(link_keys_[p].data(), ring_id, static_cast<uint8_t>(p),
                            session_keys_[p].data());
    }
    // Build from the innermost (last forwarder) outward. Every layer's
    // plaintext starts with [magic, ring_id] so EVERY hop can read the ring
    // ID directly at its own layer (matching the paper's Eq. 3, where "RI"
    // appears in every encrypted tuple, not just the innermost one) — a
    // node only needs to see the ring ID, never a later hop's session key,
    // so there's no anonymity cost to repeating it at each layer.
    std::vector<uint8_t> blob = {CONTROL_MAGIC, ring_id};
    for (size_t p = RING_SIZE; p >= 1; --p) {
        if (p != RING_SIZE) {
            std::vector<uint8_t> with_header = {CONTROL_MAGIC, ring_id};
            with_header.insert(with_header.end(), blob.begin(), blob.end());
            blob = with_header;
        }
        blob = encrypt_layer(link_keys_[p].data(), blob.data(), blob.size());
        if (p == 1) break; // avoid unsigned underflow at p==0
    }
    return make_packet(ring_id, 0, PacketType::RING_INIT, blob.data(), blob.size());
}

WirePacket GatewayNode::build_carrier(uint16_t seq) const {
    // A fresh carrier carries no real content (paper Sec 5.2), but it must
    // still be a full-length body of random bytes: an empty or short body
    // would tell a listener "this is the start of a cycle, the next
    // transmission is the first forwarder", which is exactly the kind of
    // structural hint the design exists to remove. The first forwarder
    // knows to discard this and originate its own content because it knows
    // it is at position 1 — it does not need a length cue to tell it so.
    uint8_t rnd[ONION_BODY_LEN];
    random_bytes(rnd, ONION_BODY_LEN);
    return make_padded_packet(ring_id_, seq, PacketType::CARRIER, rnd, ONION_BODY_LEN);
}

WirePacket GatewayNode::build_downlink(uint8_t target_position, PacketType type,
                                        const uint8_t data[CONTROL_DATA_LEN], uint16_t seq) const {
    ControlMsg cm = make_control(0, type, data);
    std::vector<uint8_t> blob(reinterpret_cast<uint8_t*>(&cm),
                               reinterpret_cast<uint8_t*>(&cm) + sizeof(cm));
    // Innermost = target's key, then wrap outward down to position 1's key.
    for (size_t p = target_position;; --p) {
        blob = encrypt_layer(session_keys_[p].data(), blob.data(), blob.size());
        if (p == 1) break;
    }
    // The blob's real length is 19 + target_position*28, so it would reveal
    // WHICH node the downlink is addressed to. Pad to constant, and stamp
    // the cleartext type with the direction rather than `type` (which would
    // leak whether this is a grant, data, or something else).
    return make_padded_packet(ring_id_, seq, PacketType::GRANT_DOWNLINK,
                               blob.data(), blob.size());
}

UplinkResult GatewayNode::receive_uplink(const WirePacket& pkt) const {
    UplinkResult r{};
    if (pkt.ring_id != ring_id_) return r; // not for the active ring epoch

    // Every uplink body is now padded to the same length, so length no
    // longer tells us the onion depth — that was the whole point of the
    // padding (see packet.hpp). Instead we recover the origin by trial
    // decryption: try each candidate origin position, peeling the layers
    // that origin implies. AES-GCM's auth tag makes this unambiguous — a
    // wrong candidate fails to verify with probability 1 - 2^-128, so at
    // most one candidate can succeed. Cost is at most RING_SIZE extra
    // decrypt attempts, all at the Gateway, none on a forwarder.
#ifndef SHADOWNET_VULNERABLE_DEMO
    if (pkt.used_len() != ONION_BODY_LEN) return r; // malformed
#else
    // In the deliberately broken build `used_len` carries the TRUE body
    // length, which is the leak being demonstrated. The body on the wire is
    // still physically padded to ONION_BODY_LEN, so trial decryption below
    // works unchanged -- we just must not reject the packet for having an
    // honest length field, or the broken build would fail to deliver
    // anything and the demo would show a dead ring instead of a live leak.
    (void)0;
#endif

    for (size_t origin = 1; origin <= RING_SIZE; ++origin) {
        std::vector<uint8_t> buf(pkt.ciphertext,
                                  pkt.ciphertext + onion_real_len(RING_SIZE));
        bool ok = true;
        for (size_t p = RING_SIZE; p >= origin; --p) {
            buf.resize(onion_real_len(p)); // discard this level's random padding
            std::vector<uint8_t> next;
            if (!decrypt_layer(session_keys_[p].data(), buf.data(), buf.size(), next)) {
                ok = false;
                break;
            }
            buf = std::move(next);
            if (p == origin) break;
        }
        if (!ok || buf.size() < CONTROL_MSG_LEN) continue;

        ControlMsg cm;
        std::memcpy(&cm, buf.data(), CONTROL_MSG_LEN);
        if (cm.magic != CONTROL_MAGIC) continue;

        r.valid = true;
        r.origin_position = static_cast<uint8_t>(origin);
        r.msg_type = static_cast<PacketType>(cm.msg_type);
        std::memcpy(r.data.data(), cm.data, CONTROL_DATA_LEN);
        return r;
    }
    return r;
}

// ---- ForwarderNode ---------------------------------------------------------

void ForwarderNode::set_gateway_pubkey(const uint8_t gateway_pub[KEY_LEN]) {
    uint8_t shared[KEY_LEN];
    ecdh_shared_secret(keys_.priv, gateway_pub, shared);
    derive_link_key(shared, position_, link_key_);
}

WirePacket ForwarderNode::handle_ring_init(const WirePacket& pkt, bool& ok) {
    std::vector<uint8_t> plain;
    ok = decrypt_layer(link_key_, pkt.ciphertext, pkt.used_len(), plain);
    if (!ok || plain.size() < 2 || plain[0] != CONTROL_MAGIC) { ok = false; return WirePacket{}; }

    // Every layer's plaintext starts with [magic, ring_id] regardless of
    // position, so every hop learns the ring ID directly at its own layer.
    ring_id_ = plain[1];
    derive_session_key(link_key_, ring_id_, position_, session_key_);

    if (is_last()) return WirePacket{}; // nothing further to relay
    // Remaining bytes after [magic, ring_id] are the next hop's still-wrapped layer.
    return make_packet(pkt.ring_id, pkt.seq(), PacketType::RING_INIT, plain.data() + 2, plain.size() - 2);
}

WirePacket ForwarderNode::process_uplink_cycle(const WirePacket& incoming, bool originate,
                                                PacketType type,
                                                const uint8_t data[CONTROL_DATA_LEN]) const {
    // How many bytes this node must wrap is fixed by its own ring position:
    // it wraps exactly the real body its predecessor produced. No length cue
    // from the packet is needed or used — which is precisely what lets every
    // packet on the wire carry the same padded length.
    const size_t in_len = onion_real_len(position_ - 1);
    std::vector<uint8_t> to_wrap(in_len);

    // Position 1 always REPLACES the body: it is first to touch a fresh
    // carrier, whose content is meaningless random. Later positions relay
    // unless they have something of their own to say — and when they do,
    // they overwrite what they received, which is the paper's collision rule
    // (Sec 5.2: "the one closer to the end of the ring will always erase the
    // previous request").
    const bool replace = originate || position_ == 1;
    if (replace) {
        ControlMsg cm = make_control(originate ? position_ : 0,
                                      originate ? type : PacketType::DUMMY,
                                      originate ? data : nullptr);
        std::memcpy(to_wrap.data(), &cm, CONTROL_MSG_LEN);
        // Random, not zero, fill: zero padding is itself a distinguisher.
        if (in_len > CONTROL_MSG_LEN)
            random_bytes(to_wrap.data() + CONTROL_MSG_LEN, in_len - CONTROL_MSG_LEN);
    } else {
        std::memcpy(to_wrap.data(), incoming.ciphertext, in_len);
    }

    std::vector<uint8_t> wrapped = encrypt_layer(session_key_, to_wrap.data(), in_len);
    // ALWAYS CARRIER on the wire. The real message type rides inside the
    // encrypted ControlMsg. Stamping the true type here is what leaked the
    // originating node in the previous version of this code.
#ifdef SHADOWNET_VULNERABLE_DEMO
    const PacketType wire_type = originate ? type : static_cast<PacketType>(incoming.type);
#else
    const PacketType wire_type = PacketType::CARRIER;
#endif
    return make_padded_packet(ring_id_, incoming.seq(), wire_type,
                               wrapped.data(), wrapped.size());
}

DownlinkStep ForwarderNode::process_downlink(const WirePacket& incoming) const {
    DownlinkStep step{};
    if (incoming.used_len() != ONION_BODY_LEN) return step;

    // A downlink onion still carries one layer per hop from here to its
    // target, and the target is exactly what the padding hides — so unlike
    // the uplink, this node cannot compute the real body length from its own
    // position. It tries each plausible remaining depth; the GCM tag
    // identifies the right one unambiguously.
    const size_t max_remaining = RING_SIZE - position_ + 1;
    for (size_t remaining = 1; remaining <= max_remaining; ++remaining) {
        const size_t real_len = onion_real_len(remaining);
        if (real_len > ONION_BODY_LEN) break;

        std::vector<uint8_t> plain;
        if (!decrypt_layer(session_key_, incoming.ciphertext, real_len, plain)) continue;

        if (plain.size() == CONTROL_MSG_LEN) {
            std::memcpy(&step.msg, plain.data(), CONTROL_MSG_LEN);
            step.ok = step.msg.magic == CONTROL_MAGIC;
            step.consumed = step.ok;
            return step;
        }
        // Still wrapped for a later hop: relay the remainder, re-padded so
        // the next transmission is the same length as every other one.
        step.ok = true;
        step.consumed = false;
        step.forward = make_padded_packet(incoming.ring_id, incoming.seq(),
                                           PacketType::GRANT_DOWNLINK,
                                           plain.data(), plain.size());
        return step;
    }
    return step; // ok stays false: not for our ring / tampered
}

} // namespace shadownet