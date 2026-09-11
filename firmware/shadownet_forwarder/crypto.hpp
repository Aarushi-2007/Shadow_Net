// ShadowNet Onion Ring — crypto primitives interface
//
// This header is the ONLY thing ring_node.cpp depends on for cryptography.
// Two backends implement it:
//   - core/crypto_openssl.cpp   (host build: the sim/ demo on your laptop, uses OpenSSL EVP)
//   - firmware/crypto_mbedtls.cpp (ESP32 build: uses mbedTLS, bundled with the Arduino/ESP-IDF core)
//
// Both backends implement the exact same primitives the paper (Wu & Li,
// "Achieving Privacy in Mesh Networks") relies on, with one substitution:
// X25519 ECDH + HKDF-SHA256 in place of the paper's raw RSA public-key
// encryption, since that's cheaper on an ESP32 and is standard practice
// today. Document this substitution in your alt-solutions analysis.

#pragma once
#include <cstdint>
#include <cstddef>

namespace shadownet {

constexpr size_t KEY_LEN   = 32; // X25519 keys and derived AES-256 keys are both 32 bytes
constexpr size_t NONCE_LEN = 12; // AES-GCM standard nonce size
constexpr size_t TAG_LEN   = 16; // AES-GCM auth tag size

struct KeyPair {
    uint8_t pub[KEY_LEN];
    uint8_t priv[KEY_LEN];
};

// Fill `buf` with `len` cryptographically random bytes.
void random_bytes(uint8_t* buf, size_t len);

// Generate a fresh X25519 keypair.
void generate_keypair(KeyPair& kp);

// X25519 ECDH: derive the raw shared secret from my private key + peer's public key.
void ecdh_shared_secret(const uint8_t my_priv[KEY_LEN],
                         const uint8_t peer_pub[KEY_LEN],
                         uint8_t shared_out[KEY_LEN]);

// HKDF-SHA256(ikm, salt, info) -> okm_len bytes. Used to turn the raw ECDH
// shared secret into a proper AES-256 session key (paper section 2.1's
// "symmetric key established between the Gateway router and each Mesh node").
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* info, size_t info_len,
                  uint8_t* okm, size_t okm_len);

// AES-256-GCM encrypt. ct_out must have room for pt_len bytes. Returns false on failure.
bool aes256gcm_encrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct_out, uint8_t tag_out[TAG_LEN]);

// AES-256-GCM decrypt + verify. pt_out must have room for ct_len bytes.
// Returns false if the auth tag does not verify (tampered / wrong key) —
// this is exactly the signal the Gateway uses in ring_node.cpp to figure
// out how many onion layers are actually present on an incoming packet.
bool aes256gcm_decrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t tag[TAG_LEN],
                        uint8_t* pt_out);

} // namespace shadownet
