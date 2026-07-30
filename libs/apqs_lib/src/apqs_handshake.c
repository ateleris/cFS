#include "apqs_handshake.h"

#include "apqs_app_crypto.h"
#include "apqs_app_pem.h"
#include "apqs_app_pki.h"
#include "apqs_app_cert_renewal.h"
#include "apqs_app_spki.h"
#include "apqs_event.h"

#include "protobuf/pb_decode.h"
#include "protobuf/pb_encode.h"
#include "protobuf/handshake.pb.h"

#include "cfe.h"

#include "cf_msgids.h"
#include "cf_msgdefs.h"
#include "cf_msgstruct.h"
#include "cf_fcncodes.h"

#include "apqs_api.h"

#include <assert.h>
#include <stdio.h>
#include <pqclean_fwd.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

// CFDP
#define M2_FILE_PATH "/cf/M2.pbin"
#define CFDP_GROUND_EID 1

/* CFDP inbound directories. CF_RX_BASE_DIR must match the CF config table's rx_base_dir
 * (apps/cf/fsw/tables/cf_def_config.c). The ground delivers M1 as "handshake/M1.pbin"
 * relative to that base; CF/CFDP/OS_mkdir do not create intermediate dirs, so APQS ensures
 * HS_INBOUND_DIR exists at init (see handshake_init). */
#define CF_RX_BASE_DIR "/cf/upload"
#define HS_INBOUND_DIR "/cf/upload/handshake"

/* SDLS EP simulation (handshake_simulate_sdls_ep_commands): the SA/SPI is
 * operator-chosen and arrives with the M1 request as sdls_key_id; 44 matches
 * the EP test setup and ci_lab's GVCID config (scid 3, vcid 44). */
#define SDLS_EP_SA_SPI     44
#define SDLS_EP_GVCID_SCID 3
#define SDLS_EP_GVCID_VCID 44

static const uint8_t domainsep[] = "MLKEM768ECDH25519SHA3512";
static const uint8_t kc_1_e[] = "KC_1_E";
static const uint8_t kc_2_d[] = "KC_2_D";

// cert data
static uint8_t F_PK_sat_pq[ML_KEM_768_PK_LENGTH];
static uint8_t F_SK_sat_pq[ML_KEM_768_SK_LENGTH];
static uint8_t F_PK_mcs_pq[ML_KEM_768_PK_LENGTH];

static uint8_t id_mcs[APQS_MAX_IDENTITY_LENGTH];
static uint32_t id_mcs_len = 0;
static uint8_t id_sat[APQS_MAX_IDENTITY_LENGTH];
static uint32_t id_sat_len = 0;

// crypto artifacts
static uint32_t key_id = UINT32_MAX;
static uint8_t epk_mcs_ec[ECDH_KEY_LENGTH];
static uint8_t epk_sat_ec[ECDH_KEY_LENGTH];
static uint8_t esk_sat_ec[ECDH_KEY_LENGTH];
static uint8_t epk_mcs_pq[ML_KEM_768_PK_LENGTH];
static uint8_t cipher_init_rekey[ML_KEM_768_CIPHER_LENGTH];
static uint8_t key_init_rekey[SHARED_SECRET_LENGTH];
static uint8_t cipher_rekey_resp1[ML_KEM_768_CIPHER_LENGTH];
static uint8_t key_rekey_resp1[SHARED_SECRET_LENGTH];
static uint8_t cipher_rekey_resp2[ML_KEM_768_CIPHER_LENGTH];
static uint8_t key_rekey_resp2[SHARED_SECRET_LENGTH];
static uint8_t ss_ec[SHARED_SECRET_LENGTH];
static uint8_t key_kc[SHARED_SECRET_LENGTH];
static uint8_t key_session[SHARED_SECRET_LENGTH];
static uint8_t kdf_input_container[
    SHARED_SECRET_LENGTH * 4
        + ML_KEM_768_CIPHER_LENGTH * 3
        + ML_KEM_768_PK_LENGTH * 3
        + ECDH_KEY_LENGTH * 2
        + sizeof(domainsep) - 1
];
static uint8_t T_sat[HMAC_SHA3_384_TAG_LENGTH];

/*
** reset all crypto artifacts
*/
void handshake_reset_keys(bool reset_session_key_and_key_id)
{
    memset(id_mcs, 0, sizeof(id_mcs));
    memset(id_sat, 0, sizeof(id_sat));
    memset(F_PK_sat_pq, 0, sizeof(F_PK_sat_pq));
    memset(F_SK_sat_pq, 0, sizeof(F_SK_sat_pq));
    memset(F_PK_mcs_pq, 0, sizeof(F_PK_mcs_pq));
    memset(epk_mcs_ec, 0, sizeof(epk_mcs_ec));
    memset(epk_sat_ec, 0, sizeof(epk_sat_ec));
    memset(esk_sat_ec, 0, sizeof(esk_sat_ec));
    memset(epk_mcs_pq, 0, sizeof(epk_mcs_pq));
    memset(cipher_init_rekey, 0, sizeof(cipher_init_rekey));
    memset(key_init_rekey, 0, sizeof(key_init_rekey));
    memset(cipher_rekey_resp1, 0, sizeof(cipher_rekey_resp1));
    memset(key_rekey_resp1, 0, sizeof(key_rekey_resp1));
    memset(cipher_rekey_resp2, 0, sizeof(cipher_rekey_resp2));
    memset(key_rekey_resp2, 0, sizeof(key_rekey_resp2));
    memset(ss_ec, 0, sizeof(ss_ec));
    memset(key_kc, 0, sizeof(key_kc));
    memset(kdf_input_container, 0, sizeof(kdf_input_container));
    memset(T_sat, 0, sizeof(T_sat));
    if (reset_session_key_and_key_id)
    {
        key_id = UINT32_MAX;
        memset(key_session, 0, sizeof(key_session));
    }
}

/*
** load keys from pem files
*/
int handshake_load_keys(void)
{
    if (pem_load_sat_secret_key(pki_path_sat(), F_PK_sat_pq, F_SK_sat_pq) != 0)
    {
        apqs_event_send(APQS_PEM_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to load SAT private key from %s", pki_path_sat());
        return -1;
    }

    if (pem_load_public_key(pki_path_mcs(), F_PK_mcs_pq) != 0)
    {
        apqs_event_send(APQS_PEM_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to load MCS public key from %s", pki_path_mcs());
        return -1;
    }

    if (pem_load_identity(pki_path_sat(), id_sat, &id_sat_len) != 0)
    {
        apqs_event_send(APQS_PEM_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to load SAT identity from %s", pki_path_sat());
        return -1;
    }

    if (pem_load_identity(pki_path_mcs(), id_mcs, &id_mcs_len) != 0)
    {
        apqs_event_send(APQS_PEM_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to load MCS identity from %s", pki_path_mcs());
        return -1;
    }

    apqs_event_send(APQS_PEM_INF_EID, APQS_EVENT_INFO, "APQS: PQ keys loaded from PEM files");
    return 0;
}

/*
** cleanup ecdh_keygen
*/
void ecdh_keygen_cleanup(EVP_PKEY_CTX* pctx, EVP_PKEY* pkey)
{
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

/*
** create ecdh X25519 public and secret key
*/
int ecdh_keygen(uint8_t* public_key, uint8_t* secret_key)
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx)
    {
        OS_printf("EVP_PKEY_CTX_new_id failed\n");
        return HANDSHAKE_ERROR;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1)
    {
        OS_printf("EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(pctx);
        return HANDSHAKE_ERROR;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1)
    {
        OS_printf("EVP_PKEY_keygen failed\n");
        ecdh_keygen_cleanup(pctx, pkey);
        return HANDSHAKE_ERROR;
    }

    size_t pub_len = ECDH_KEY_LENGTH;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len) != 1)
    {
        OS_printf("EVP_PKEY_get_raw_public_key failed\n");
        ecdh_keygen_cleanup(pctx, pkey);
        return HANDSHAKE_ERROR;
    }
    assert(pub_len == ECDH_KEY_LENGTH);

    size_t sec_len = ECDH_KEY_LENGTH;
    if (EVP_PKEY_get_raw_private_key(pkey, secret_key, &sec_len) != 1)
    {
        OS_printf("EVP_PKEY_get_raw_private_key failed\n");
        ecdh_keygen_cleanup(pctx, pkey);
        return HANDSHAKE_ERROR;
    }
    assert(sec_len == ECDH_KEY_LENGTH);

    ecdh_keygen_cleanup(pctx, pkey);
    return HANDSHAKE_SUCCESS;
}

/*
** cleanup ecdh_calc_secret
*/
void ecdh_calc_secret_cleanup(EVP_PKEY* local_key, EVP_PKEY* peer_key, EVP_PKEY_CTX* ctx)
{
    EVP_PKEY_free(local_key);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(ctx);
}

/*
** calculate X25519 shared secret
*/
int ecdh_calc_secret(uint8_t* shared_secret, uint8_t* secret_key, uint8_t* remote_public_key)
{
    EVP_PKEY* local_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key, ECDH_KEY_LENGTH);
    if (!local_key)
    {
        OS_printf("EVP_PKEY_new_raw_private_key failed\n");
        return HANDSHAKE_ERROR;
    }

    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, remote_public_key, ECDH_KEY_LENGTH);
    if (!peer_key)
    {
        OS_printf("EVP_PKEY_new_raw_public_key failed\n");
        EVP_PKEY_free(local_key);
        return HANDSHAKE_ERROR;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (!ctx)
    {
        OS_printf("EVP_PKEY_CTX_new failed\n");
        EVP_PKEY_free(local_key);
        EVP_PKEY_free(peer_key);
        return HANDSHAKE_ERROR;
    }

    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        OS_printf("EVP_PKEY_derive_init failed\n");
        ecdh_calc_secret_cleanup(local_key, peer_key, ctx);
        return HANDSHAKE_ERROR;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) != 1)
    {
        OS_printf("EVP_PKEY_derive_set_peer failed\n");
        ecdh_calc_secret_cleanup(local_key, peer_key, ctx);
        return HANDSHAKE_ERROR;
    }

    size_t secret_len = ECDH_KEY_LENGTH;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) != 1)
    {
        OS_printf("EVP_PKEY_derive failed\n");
        ecdh_calc_secret_cleanup(local_key, peer_key, ctx);
        return HANDSHAKE_ERROR;
    }
    assert(secret_len == ECDH_KEY_LENGTH);

    if (secret_len != ECDH_KEY_LENGTH)
    {
        OS_printf("Unexpected shared secret length: %zu (expected %d)\n", secret_len, ECDH_KEY_LENGTH);
        ecdh_calc_secret_cleanup(local_key, peer_key, ctx);
        return HANDSHAKE_ERROR;
    }

    ecdh_calc_secret_cleanup(local_key, peer_key, ctx);
    return HANDSHAKE_SUCCESS;
}

/*
** HMAC-based key derivation function
*/
int hmac_kdf(uint8_t* key_kc, uint8_t* key_session)
{
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
    {
        OS_printf("EVP_KDF_fetch failed\n");
        return HANDSHAKE_ERROR;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
    {
        OS_printf("EVP_KDF_CTX_new failed\n");
        return HANDSHAKE_ERROR;
    }

    size_t i = 0;
    memcpy(kdf_input_container + i, key_init_rekey, sizeof(key_init_rekey));
    i += sizeof(key_init_rekey);
    memcpy(kdf_input_container + i, key_rekey_resp1, sizeof(key_rekey_resp1));
    i += sizeof(key_rekey_resp1);
    memcpy(kdf_input_container + i, key_rekey_resp2, sizeof(key_rekey_resp2));
    i += sizeof(key_rekey_resp2);
    memcpy(kdf_input_container + i, ss_ec, sizeof(ss_ec));
    i += sizeof(ss_ec);

    memcpy(kdf_input_container + i, cipher_init_rekey, sizeof(cipher_init_rekey));
    i += sizeof(cipher_init_rekey);
    memcpy(kdf_input_container + i, cipher_rekey_resp1, sizeof(cipher_rekey_resp1));
    i += sizeof(cipher_rekey_resp1);
    memcpy(kdf_input_container + i, cipher_rekey_resp2, sizeof(cipher_rekey_resp2));
    i += sizeof(cipher_rekey_resp2);

    memcpy(kdf_input_container + i, F_PK_sat_pq, sizeof(F_PK_sat_pq));
    i += sizeof(F_PK_sat_pq);
    memcpy(kdf_input_container + i, F_PK_mcs_pq, sizeof(F_PK_mcs_pq));
    i += sizeof(F_PK_mcs_pq);

    memcpy(kdf_input_container + i, epk_mcs_pq, sizeof(epk_mcs_pq));
    i += sizeof(epk_mcs_pq);
    memcpy(kdf_input_container + i, epk_sat_ec, sizeof(epk_sat_ec));
    i += sizeof(epk_sat_ec);
    memcpy(kdf_input_container + i, epk_mcs_ec, sizeof(epk_mcs_ec));
    i += sizeof(epk_mcs_ec);
    memcpy(kdf_input_container + i, domainsep, sizeof(domainsep) - 1);
    i += sizeof(domainsep) - 1;
    assert(i == sizeof(kdf_input_container));

    uint8_t temp_key_container[SHARED_SECRET_LENGTH * 2];
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA3-512", 0),
        OSSL_PARAM_construct_octet_string("salt", (void*)domainsep, sizeof(domainsep) - 1),
        OSSL_PARAM_construct_octet_string("key", (void*)kdf_input_container, sizeof(kdf_input_container)),
        OSSL_PARAM_construct_octet_string("info", NULL, 0),
        OSSL_PARAM_construct_octet_string("output", temp_key_container, sizeof(temp_key_container)),
        OSSL_PARAM_END
    };

    if (EVP_KDF_derive(kctx, temp_key_container, sizeof(temp_key_container), params) != 1)
    {
        OS_printf("EVP_KDF_derive failed\n");
        OPENSSL_cleanse(temp_key_container, sizeof(temp_key_container));
        EVP_KDF_CTX_free(kctx);
        return HANDSHAKE_ERROR;
    }

    memcpy(key_kc, temp_key_container, SHARED_SECRET_LENGTH);
    memcpy(key_session, temp_key_container + SHARED_SECRET_LENGTH, SHARED_SECRET_LENGTH);
    OPENSSL_cleanse(temp_key_container, sizeof(temp_key_container));

    EVP_KDF_CTX_free(kctx);
    return HANDSHAKE_SUCCESS;
}

/*
** HMAC tag calculation (MAC_DATA_sat, "KC_1_E")
*/
int hmac_derive_tag(uint8_t* tag)
{
    const hmac_part_t parts[] = {
        { kc_1_e, sizeof(kc_1_e) - 1 },
        { id_sat, id_sat_len },
        { id_mcs, id_mcs_len },
        { epk_sat_ec, sizeof(epk_sat_ec) },
        { cipher_rekey_resp1, sizeof(cipher_rekey_resp1) },
        { cipher_rekey_resp2, sizeof(cipher_rekey_resp2) },
        { epk_mcs_pq, sizeof(epk_mcs_pq) },
        { epk_mcs_ec, sizeof(epk_mcs_ec) },
        { cipher_init_rekey, sizeof(cipher_init_rekey) },
    };

    if (hmac_sha3_384(key_kc, sizeof(key_kc), parts, sizeof(parts) / sizeof(parts[0]), tag) != 0)
        return HANDSHAKE_ERROR;

    return HANDSHAKE_SUCCESS;
}

/*
** handshake rekey process
*/
int handshake_rekey_pb(handshake_HandshakeRequest* hs_request, uint8_t* hs_response_msg, size_t* out_encoded_size)
{
    handshake_reset_keys(true);

    key_id = hs_request->sdls_key_id;

    if (handshake_load_keys() != 0)
    {
        OS_printf("APQS: handshake_load_keys() failed — cannot proceed with handshake\n");
        return HANDSHAKE_ERROR;
    }

    if (spki_decode_ml_kem_768(hs_request->epk_sender_pqc.bytes,
        hs_request->epk_sender_pqc.size,
        epk_mcs_pq, sizeof(epk_mcs_pq)) != 0)
    {
        OS_printf("APQS: spki_decode_ml_kem_768 failed\n");
        return HANDSHAKE_ERROR;
    }
    if (spki_decode_x25519(hs_request->epk_sender_ec.bytes,
        hs_request->epk_sender_ec.size,
        epk_mcs_ec, sizeof(epk_mcs_ec)) != 0)
    {
        OS_printf("APQS: spki_decode_x25519 failed\n");
        return HANDSHAKE_ERROR;
    }
    if (hs_request->cipher_init_rekey.size != sizeof(cipher_init_rekey))
    {
        OS_printf("APQS: cipher_init_rekey size %u (expected %zu)\n", (unsigned)hs_request->cipher_init_rekey.size, sizeof(cipher_init_rekey));
        return HANDSHAKE_ERROR;
    }
    memcpy(cipher_init_rekey, hs_request->cipher_init_rekey.bytes, sizeof(cipher_init_rekey));

    // Verify the MCS certificate chain against the CA (Crypto.Ver_Cert_PKCA) before trusting its OCSP status
    if (pem_verify_cert_against_ca(pki_path_mcs(), pki_path_ca()) != 0)
    {
        apqs_event_send(APQS_CERTVER_ERR_EID, APQS_EVENT_ERROR, "APQS: MCS certificate chain verification failed");
        return HANDSHAKE_ERROR;
    }
    apqs_event_send(APQS_CERTVER_INF_EID, APQS_EVENT_INFO, "APQS: MCS certificate verified against CA");

    // Validate OCSP response from M1 before any key operations
    if (hs_request->ocspresp_mcs.size > 0)
    {
        if (ocsp_verify_response(hs_request->ocspresp_mcs.bytes, hs_request->ocspresp_mcs.size, pki_path_mcs(), pki_path_ca()) != 0)
        {
            apqs_event_send(APQS_OCSP_ERR_EID, APQS_EVENT_ERROR, "APQS: OCSP validation failed for MCS certificate");
            return HANDSHAKE_ERROR;
        }
        apqs_event_send(APQS_OCSP_INF_EID, APQS_EVENT_INFO, "APQS: OCSP response validated — MCS certificate status GOOD");
    }
    else
    {
        apqs_event_send(APQS_OCSP_ERR_EID, APQS_EVENT_ERROR, "APQS: No OCSP response in M1 — aborting handshake");
        return HANDSHAKE_ERROR;
    }

    // mlkem_decaps_m2
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(key_init_rekey, cipher_init_rekey, F_SK_sat_pq) != 0)
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec failed\n");
        return HANDSHAKE_ERROR;
    }

    // mlkem_encaps_m2 part 1
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(cipher_rekey_resp1, key_rekey_resp1, F_PK_mcs_pq) != 0)
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc 1 failed\n");
        return HANDSHAKE_ERROR;
    }

    // mlkem_encaps_m2 part 2
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(cipher_rekey_resp2, key_rekey_resp2, epk_mcs_pq) != 0)
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc 2 failed\n");
        return HANDSHAKE_ERROR;
    }

    // ecdh_keygen
    if (ecdh_keygen(epk_sat_ec, esk_sat_ec) != HANDSHAKE_SUCCESS)
    {
        OS_printf("ecdh_keygen failed\n");
        return HANDSHAKE_ERROR;
    }

    // ecdh_calc_secret
    if (ecdh_calc_secret(ss_ec, esk_sat_ec, epk_mcs_ec) != HANDSHAKE_SUCCESS)
    {
        OS_printf("ecdh_calc_secret failed\n");
        return HANDSHAKE_ERROR;
    }

    // kdf
    if (hmac_kdf(key_kc, key_session) != HANDSHAKE_SUCCESS)
    {
        OS_printf("hmac_kdf failed\n");
        return HANDSHAKE_ERROR;
    }

    // calc_hmac
    if (hmac_derive_tag(T_sat) != HANDSHAKE_SUCCESS)
    {
        OS_printf("hmac_derive_tag failed\n");
        return HANDSHAKE_ERROR;
    }

    pb_ostream_t stream = pb_ostream_from_buffer(hs_response_msg, M2_BUFFER_SIZE);
    handshake_HandshakeMessage response_msg = handshake_HandshakeMessage_init_zero;
    response_msg.which_payload = handshake_HandshakeMessage_response_tag;
    memcpy(&response_msg.payload.response.cipher_rekey_resp1.bytes, cipher_rekey_resp1, sizeof(cipher_rekey_resp1));
    response_msg.payload.response.cipher_rekey_resp1.size = sizeof(cipher_rekey_resp1);
    memcpy(&response_msg.payload.response.cipher_rekey_resp2.bytes, cipher_rekey_resp2, sizeof(cipher_rekey_resp2));
    response_msg.payload.response.cipher_rekey_resp2.size = sizeof(cipher_rekey_resp2);
    {
        uint8_t spki_sat_ec[X25519_SPKI_SIZE];
        int spki_len = spki_encode_x25519(epk_sat_ec, sizeof(epk_sat_ec),
            spki_sat_ec, sizeof(spki_sat_ec));
        if (spki_len < 0)
        {
            OS_printf("APQS: spki_encode_x25519 failed\n");
            return HANDSHAKE_ERROR;
        }
        memcpy(&response_msg.payload.response.epk_replier_ec.bytes, spki_sat_ec, (size_t)spki_len);
        response_msg.payload.response.epk_replier_ec.size = (pb_size_t)spki_len;
    }
    memcpy(&response_msg.payload.response.tag_replier.bytes, T_sat, sizeof(T_sat));
    response_msg.payload.response.tag_replier.size = sizeof(T_sat);

    bool status = pb_encode(&stream, handshake_HandshakeMessage_fields, &response_msg);
    if (!status)
    {
        OS_printf("pb_encode failed\n");
        return HANDSHAKE_ERROR;
    }

    if (out_encoded_size != NULL)
    {
        *out_encoded_size = stream.bytes_written;
    }

    return HANDSHAKE_SUCCESS;
}

/*
** handshake key confirmation process
*/
int handshake_key_conf_pb(handshake_HandshakeKeyConfirmation* hs_key_conf)
{
    const hmac_part_t parts[] = {
        { kc_2_d, sizeof(kc_2_d) - 1 },
        { id_mcs, id_mcs_len },
        { id_sat, id_sat_len },
        { epk_mcs_pq, sizeof(epk_mcs_pq) },
        { epk_mcs_ec, sizeof(epk_mcs_ec) },
        { cipher_init_rekey, sizeof(cipher_init_rekey) },
        { epk_sat_ec, sizeof(epk_sat_ec) },
        { cipher_rekey_resp1, sizeof(cipher_rekey_resp1) },
        { cipher_rekey_resp2, sizeof(cipher_rekey_resp2) },
    };

    uint8_t check_t_mcs[HMAC_SHA3_384_TAG_LENGTH];
    if (hmac_sha3_384(key_kc, sizeof(key_kc), parts, sizeof(parts) / sizeof(parts[0]), check_t_mcs) != 0)
        return HANDSHAKE_ERROR;

    if (hs_key_conf->tag_sender.size != sizeof(check_t_mcs))
    {
        OS_printf("APQS: tag_sender size %u (expected %zu)\n", (unsigned)hs_key_conf->tag_sender.size, sizeof(check_t_mcs));
        return HANDSHAKE_ERROR;
    }
    if (CRYPTO_memcmp(hs_key_conf->tag_sender.bytes, check_t_mcs, sizeof(check_t_mcs)) != 0)
    {
        OS_printf("tag compare failed\n");
        return HANDSHAKE_ERROR;
    }

    return HANDSHAKE_SUCCESS;
}

/*
** handshake set session key
*/
int handshake_set_session_key(void)
{
    if (key_id == UINT32_MAX) { return HANDSHAKE_ERROR; }

    crypto_key_t* ekid = get_key_interface_internal()->get_key(key_id);
    if (ekid == NULL) { return HANDSHAKE_ERROR; }

    ekid->key_state = KEY_PREACTIVE;
    ekid->key_len = sizeof(key_session);
    for (int i = 0; i < ekid->key_len; i++)
    {
        ekid->value[i] = key_session[i];
    }

    /* Logs raw key material at INFO — fine for dev/test, scrub before production. */
    char key_hex[2 * SHARED_SECRET_LENGTH + 1];
    for (int i = 0; i < SHARED_SECRET_LENGTH; i++)
    {
        snprintf(&key_hex[2 * i], 3, "%02X", key_session[i]);
    }
    apqs_event_send(APQS_HS_SESSION_KEY_INF_EID, APQS_EVENT_INFO,
                      "APQS: session key installed (key_id=%u, key=%s)",
                      (unsigned int)key_id, key_hex);

    return HANDSHAKE_SUCCESS;
}

/*
** Ensure the CFDP inbound directories the handshake needs exist. CF creates only its
** rx_base_dir; neither CFDP nor OS_mkdir create intermediate dirs, so the ground-chosen
** "handshake/" sub-dir is created here (mirrors pki_store_init for /cf/pki).
*/
int handshake_init(void)
{
    /* CF normally creates the rx base dir; create it too so we don't depend on app init order. */
    if (!pki_store_vpath_exists(CF_RX_BASE_DIR))
    {
        OS_mkdir(CF_RX_BASE_DIR, OS_READ_WRITE);
    }

    if (!pki_store_vpath_exists(HS_INBOUND_DIR))
    {
        int32 status = OS_mkdir(HS_INBOUND_DIR, OS_READ_WRITE);
        if (status != OS_SUCCESS)
        {
            apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: mkdir %s failed (rc=%ld)",
                              HS_INBOUND_DIR, (long)status);
            return -1;
        }
    }

    return 0;
}

/*
** Send file (handshake response) via CFDP
*/
void send_file_via_cfdp(const char* src_filename, const char* dst_filename)
{
    CF_TxFileCmd_t txCmd;
    memset(&txCmd, 0, sizeof(txCmd));

    CFE_MSG_Init(CFE_MSG_PTR(txCmd.CommandHeader), CFE_SB_ValueToMsgId(CF_CMD_MID), sizeof(CF_TxFileCmd_t));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(txCmd.CommandHeader), CF_TX_FILE_CC);

    /* class 1 (unacknowledged): the ground entity's class-2 response PDUs are
     * rejected by CF ("invalid destination eid"), ending acknowledged transfers
     * in ACK/NAK limit + delayed delivery on ground */
    txCmd.Payload.cfdp_class = CF_CFDP_CLASS_1;
    txCmd.Payload.keep = 0;
    txCmd.Payload.chan_num = 0;
    txCmd.Payload.priority = 0;
    txCmd.Payload.dest_id = CFDP_GROUND_EID;

    strncpy(txCmd.Payload.src_filename, src_filename, sizeof(txCmd.Payload.src_filename) - 1);
    strncpy(txCmd.Payload.dst_filename, dst_filename, sizeof(txCmd.Payload.dst_filename) - 1);

    CFE_SB_TimeStampMsg(CFE_MSG_PTR(txCmd.CommandHeader));
    CFE_Status_t status = CFE_SB_TransmitMsg(CFE_MSG_PTR(txCmd.CommandHeader), true);
    if (status != CFE_SUCCESS)
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to send CF TX FILE cmd (rc=0x%08lX)", (unsigned long)status);
}

/*
** Handle handshake rekey received via CFDP
*/
void handshake_rekey_cfdp(handshake_HandshakeRequest* request)
{
    apqs_event_send(APQS_CF_HS_M1_INF_EID, APQS_EVENT_INFO, "APQS: Processing CFDP handshake rekey");

    uint8_t m2_buf[M2_BUFFER_SIZE];
    memset(m2_buf, 0, sizeof(m2_buf));
    size_t m2_size = 0;

    if (handshake_rekey_pb(request, m2_buf, &m2_size) != HANDSHAKE_SUCCESS)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: CFDP handshake M1 processing failed");
        handshake_reset_keys(true);
        return;
    }

    // write M2 file
    osal_id_t fd;
    int32 os_status = OS_OpenCreate(&fd, M2_FILE_PATH, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY);
    if (os_status != OS_SUCCESS)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to create M2 file %s (rc=%ld)", M2_FILE_PATH, (long)os_status);
        handshake_reset_keys(true);
        return;
    }

    int32 bytes_written = OS_write(fd, m2_buf, m2_size);
    OS_close(fd);

    if (bytes_written != (int32)m2_size)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to write M2 file (wrote=%ld, expected=%lu)", (long)bytes_written, (unsigned long)m2_size);
        handshake_reset_keys(true);
        return;
    }

    /* Deliver M2 into the ground's handshake folder (mirrors M1's "handshake/M1.pbin") */
    send_file_via_cfdp(M2_FILE_PATH, "handshake/M2.pbin");
    apqs_event_send(APQS_CF_HS_M2_SENT_INF_EID, APQS_EVENT_INFO, "APQS: M2 written to %s (%lu bytes), CF TX requested", M2_FILE_PATH, (unsigned long)m2_size);
}

/*
** Handle key confirmation received via CFDP
*/
void handshake_key_conf_cfdp(handshake_HandshakeKeyConfirmation* keyconf)
{
    if (handshake_key_conf_pb(keyconf) != HANDSHAKE_SUCCESS)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: CFDP handshake M3 verification failed");
        handshake_reset_keys(true);
        return;
    }

    handshake_reset_keys(false);
    if (handshake_set_session_key() != HANDSHAKE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS: CFDP handshake set session key failed");
        handshake_reset_keys(true);
        return;
    }
    handshake_reset_keys(true);

    /* a completed handshake proves the active key/cert - drop any renewal rollback copy */
    cert_renewal_confirm_new_key();

    apqs_event_send(APQS_CF_HS_M3_OK_INF_EID, APQS_EVENT_INFO, "APQS: CFDP handshake complete");
}

/*
** CFDP handshake file handler -- reads the file, decodes the handshake protobuf,
** dispatches rekey/key confirmation
*/
void handshake_handle_cfdp_file(const char* filepath, uint32_t fsize, uint32_t txn_stat)
{
    apqs_event_send(APQS_CF_HS_M1_INF_EID, APQS_EVENT_INFO, "APQS: Handshake file detected: %s (size=%lu, txn_stat=%lu)", filepath, (unsigned long)fsize, (unsigned long)txn_stat);

    if (txn_stat != 0)
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: CFDP transfer error for %s (stat=%lu), attempting read anyway", filepath, (unsigned long)txn_stat);

    /* Try to read the file even if transfer had errors -- it may be on disk */
    osal_id_t fd;
    int32 os_status = OS_OpenCreate(&fd, filepath, OS_FILE_FLAG_NONE, OS_READ_ONLY);
    if (os_status != OS_SUCCESS)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to open handshake file %s (rc=%ld)", filepath, (long)os_status);
        return;
    }

    static uint8_t file_buf[handshake_HandshakeMessage_size];
    size_t read_size = (fsize > 0 && fsize <= handshake_HandshakeMessage_size) ? fsize : handshake_HandshakeMessage_size;
    int32 bytes_read = OS_read(fd, file_buf, read_size);
    OS_close(fd);

    if (bytes_read <= 0)
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to read handshake file %s (read=%ld)", filepath, (long)bytes_read);
        return;
    }
    apqs_event_send(APQS_CF_HS_M1_INF_EID, APQS_EVENT_INFO, "APQS: Read %ld bytes from %s, decoding protobuf", (long)bytes_read, filepath);

    static handshake_HandshakeMessage msg;
    msg = (handshake_HandshakeMessage)handshake_HandshakeMessage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(file_buf, (size_t)bytes_read);

    if (!pb_decode(&stream, handshake_HandshakeMessage_fields, &msg))
    {
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Failed to decode handshake protobuf from %s (%ld bytes)", filepath, (long)bytes_read);
        return;
    }
    apqs_event_send(APQS_CF_HS_M1_INF_EID, APQS_EVENT_INFO, "APQS: Protobuf decoded, which_payload=%u", (unsigned)msg.which_payload);

    switch (msg.which_payload)
    {
    case handshake_HandshakeMessage_request_tag:
        handshake_rekey_cfdp(&msg.payload.request);
        break;

    case handshake_HandshakeMessage_keyconfirmation_tag:
        handshake_key_conf_cfdp(&msg.payload.keyconfirmation);
        break;

    default:
        apqs_event_send(APQS_CF_HS_ERR_EID, APQS_EVENT_ERROR, "APQS: Unexpected handshake payload tag %u from %s", (unsigned)msg.which_payload, filepath);
        break;
    }
}
