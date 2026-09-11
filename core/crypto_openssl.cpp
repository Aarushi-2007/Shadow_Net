// Host-build crypto backend for core/crypto.hpp, using OpenSSL's EVP API.
// Used by sim/main.cpp so the full protocol can be built and run on your
// laptop (no ESP32 hardware needed) before flashing firmware/.
//
// Build: see sim/README section in the top-level README.md.

#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace shadownet {

void random_bytes(uint8_t* buf, size_t len) {
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

void generate_keypair(KeyPair& kp) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        throw std::runtime_error("X25519 keygen init failed");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("X25519 keygen failed");
    }
    size_t pub_len = KEY_LEN, priv_len = KEY_LEN;
    EVP_PKEY_get_raw_public_key(pkey, kp.pub, &pub_len);
    EVP_PKEY_get_raw_private_key(pkey, kp.priv, &priv_len);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

void ecdh_shared_secret(const uint8_t my_priv[KEY_LEN],
                         const uint8_t peer_pub[KEY_LEN],
                         uint8_t shared_out[KEY_LEN]) {
    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_priv, KEY_LEN);
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, KEY_LEN);
    if (!priv_key || !peer_key) throw std::runtime_error("ECDH key import failed");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    size_t secret_len = KEY_LEN;
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(ctx, shared_out, &secret_len) <= 0) {
        throw std::runtime_error("ECDH derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);
}

void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* info, size_t info_len,
                  uint8_t* okm, size_t okm_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, static_cast<int>(ikm_len)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, static_cast<int>(info_len)) <= 0) {
        throw std::runtime_error("HKDF setup failed");
    }
    size_t len = okm_len;
    if (EVP_PKEY_derive(ctx, okm, &len) <= 0) {
        throw std::runtime_error("HKDF derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
}

bool aes256gcm_encrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct_out, uint8_t tag_out[TAG_LEN]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, ct_len = 0;
    bool ok = ctx &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
    if (ok && aad_len > 0) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1;
    }
    if (ok) ok = EVP_EncryptUpdate(ctx, ct_out, &len, pt, static_cast<int>(pt_len)) == 1;
    ct_len = len;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, ct_out + ct_len, &len) == 1;
    ct_len += len;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out) == 1;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok && ct_len == static_cast<int>(pt_len);
}

bool aes256gcm_decrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t tag[TAG_LEN],
                        uint8_t* pt_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, pt_len = 0;
    bool ok = ctx &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
    if (ok && aad_len > 0) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1;
    }
    if (ok) ok = EVP_DecryptUpdate(ctx, pt_out, &len, ct, static_cast<int>(ct_len)) == 1;
    pt_len = len;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<uint8_t*>(tag)) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, pt_out + pt_len, &len) == 1; // fails if tag is wrong
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // namespace shadownet
