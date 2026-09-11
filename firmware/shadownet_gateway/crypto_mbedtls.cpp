// ESP32-build crypto backend for core/crypto.hpp, using mbedTLS — the TLS
// library already bundled with the Arduino-ESP32 / ESP-IDF core, so this
// adds zero extra library dependencies to your firmware build.
//
// This file is the one piece of this project that could NOT be compiled or
// run in the sandbox this project was written in (no ESP32 toolchain
// there) — everything in core/ring_node.cpp and the whole protocol was
// verified via sim/ (built against core/crypto_openssl.cpp instead). This
// file follows mbedTLS's own documented Curve25519 ECDH pattern (see
// mbedTLS's programs/pkey/ecdh_curve25519.c) and its standard GCM/HKDF
// APIs, but you should build it once in isolation (Arduino IDE: File >
// Examples, or `pio run`) before wiring it into the full ring firmware, in
// case your specific mbedTLS version needs small adjustments. If
// MBEDTLS_ECP_DP_CURVE25519_ENABLED turns out to be off in your
// sdkconfig, see README.md "If X25519 doesn't build" for a fallback.

#include "crypto.hpp"

#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <cstring>

#if defined(ARDUINO) || defined(ESP_PLATFORM)
#include <esp_system.h>
#include <esp_random.h> // esp_random() lives here on newer ESP-IDF/arduino-esp32
                         // cores (esp_system.h no longer pulls it in transitively) —
                         // kept both includes so this also builds on older cores
                         // where esp_random.h may not exist but esp_system.h sufficed.
#endif

namespace shadownet {

void random_bytes(uint8_t* buf, size_t len) {
#if defined(ARDUINO) || defined(ESP_PLATFORM)
    size_t i = 0;
    while (i < len) {
        uint32_t r = esp_random();
        size_t n = (len - i) < 4 ? (len - i) : 4;
        std::memcpy(buf + i, &r, n);
        i += n;
    }
#else
#error "crypto_mbedtls.cpp needs esp_random() — build this only for the ESP32 target"
#endif
}

void generate_keypair(KeyPair& kp) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    // esp_random() satisfies the f_rng signature via this tiny adapter:
    auto rng = [](void*, unsigned char* out, size_t out_len) -> int {
        random_bytes(out, out_len);
        return 0;
    };
    mbedtls_ecdh_gen_public(&grp, &d, &Q, rng, nullptr);

    size_t olen = 0;
    mbedtls_mpi_write_binary(&d, kp.priv, KEY_LEN);
    mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, kp.pub, KEY_LEN);

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
}

void ecdh_shared_secret(const uint8_t my_priv[KEY_LEN],
                         const uint8_t peer_pub[KEY_LEN],
                         uint8_t shared_out[KEY_LEN]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q_peer;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q_peer);

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_mpi_read_binary(&d, my_priv, KEY_LEN);
    mbedtls_ecp_point_read_binary(&grp, &Q_peer, peer_pub, KEY_LEN);

    auto rng = [](void*, unsigned char* out, size_t out_len) -> int {
        random_bytes(out, out_len);
        return 0;
    };
    mbedtls_ecdh_compute_shared(&grp, &z, &Q_peer, &d, rng, nullptr);
    mbedtls_mpi_write_binary(&z, shared_out, KEY_LEN);

    mbedtls_ecp_point_free(&Q_peer);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
}

void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* info, size_t info_len,
                  uint8_t* okm, size_t okm_len) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len);
}

bool aes256gcm_encrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct_out, uint8_t tag_out[TAG_LEN]) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
    if (ok) {
        ok = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
                                        nonce, NONCE_LEN, aad, aad_len,
                                        pt, ct_out, TAG_LEN, tag_out) == 0;
    }
    mbedtls_gcm_free(&ctx);
    return ok;
}

bool aes256gcm_decrypt(const uint8_t key[KEY_LEN],
                        const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t tag[TAG_LEN],
                        uint8_t* pt_out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
    if (ok) {
        // auth_decrypt returns MBEDTLS_ERR_GCM_AUTH_FAILED (nonzero) if the
        // tag doesn't verify — this IS the "malicious/faulty forwarder"
        // signal the ring's intruder-identification logic relies on.
        ok = mbedtls_gcm_auth_decrypt(&ctx, ct_len, nonce, NONCE_LEN, aad, aad_len,
                                       tag, TAG_LEN, ct, pt_out) == 0;
    }
    mbedtls_gcm_free(&ctx);
    return ok;
}

} // namespace shadownet
