#include "apqs_app_cert.h"

/* RENEWAL */

#include "apqs_app_pki.h"
#include "apqs_app_pem.h"
#include "apqs_app_crypto.h"
#include "apqs_app_hs.h"
#include "apqs_app_events.h"

#include "protobuf/pb_encode.h"

#include "cfe.h"

#include "pqclean/ml-kem-768/kem.h"
#include "pqclean/common/randombytes.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>

#include <string.h>

#define PKI_CSR_FILE_PATH "/cf/PKI_CSR.pbin"

#define CSR_MAX_DER_LENGTH 2400

/* subject for the first-time certificate when no active cert exists yet (cold start) */
#define CSR_DEFAULT_SUBJECT_CN "sat"

/*
** SHA-256 of the pending public key (state-file integrity check)
*/
static int cert_renewal_hash_pk(const uint8_t* pk, uint8_t* hash_out)
{
    unsigned int hash_len = 0;
    if (EVP_Digest(pk, ML_KEM_768_PK_LENGTH, hash_out, &hash_len, EVP_sha256(), NULL) != 1 || hash_len != 32)
    {
        OS_printf("APQS RENEWAL: EVP_Digest failed\n");
        return -1;
    }
    return 0;
}

/*
** Build an EVP_PKEY holding an ML-KEM-768 public key (raw 1184 bytes)
*/
static EVP_PKEY* cert_renewal_pubkey_to_evp(const uint8_t* pk)
{
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!pctx)
    {
        OS_printf("APQS RENEWAL: EVP_PKEY_CTX_new_from_name(ML-KEM-768) failed\n");
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pk, ML_KEM_768_PK_LENGTH),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        OS_printf("APQS RENEWAL: EVP_PKEY_fromdata (public) failed\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static void cert_renewal_build_csr_cleanup(X509* active_cert, X509_NAME* fallback_subject, X509_REQ* req, EVP_PKEY* pkey)
{
    if (pkey) EVP_PKEY_free(pkey);
    if (req) X509_REQ_free(req);
    if (fallback_subject) X509_NAME_free(fallback_subject);
    if (active_cert) X509_free(active_cert);
}

/*
** Build the unsigned CSR (RFC 2986 CertificationRequestInfo, DER) for the
** pending public key; subject is copied from the active certificate.
*/
static int cert_renewal_build_csr(const uint8_t* pk, uint8_t* csr_der, size_t* csr_len)
{
    X509* active_cert = NULL;
    X509_NAME* fallback_subject = NULL;
    X509_REQ* req = NULL;
    EVP_PKEY* pkey = NULL;

    /* subject from the active cert; cold start (no cert yet) uses the default CN */
    X509_NAME* subject = NULL;
    active_cert = pem_load_cert_x509(pki_path_sat());
    if (active_cert)
    {
        subject = X509_get_subject_name(active_cert);
    }
    else
    {
        OS_printf("APQS RENEWAL: no active certificate - first-time CSR with CN=%s\n", CSR_DEFAULT_SUBJECT_CN);
        fallback_subject = X509_NAME_new();
        if (!fallback_subject ||
            X509_NAME_add_entry_by_txt(fallback_subject, "CN", MBSTRING_ASC,
                (const unsigned char*)CSR_DEFAULT_SUBJECT_CN, -1, -1, 0) != 1)
        {
            OS_printf("APQS RENEWAL: fallback subject creation failed\n");
            cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
            return -1;
        }
        subject = fallback_subject;
    }

    req = X509_REQ_new();
    if (!req || X509_REQ_set_version(req, 0) != 1 ||
        X509_REQ_set_subject_name(req, subject) != 1)
    {
        OS_printf("APQS RENEWAL: X509_REQ setup failed\n");
        cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
        return -1;
    }

    pkey = cert_renewal_pubkey_to_evp(pk);
    if (!pkey)
    {
        cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
        return -1;
    }

    if (X509_REQ_set_pubkey(req, pkey) != 1)
    {
        OS_printf("APQS RENEWAL: X509_REQ_set_pubkey failed\n");
        cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
        return -1;
    }

    /* encode only the CertificationRequestInfo (TBS) - ML-KEM keys cannot sign,
     * authenticity comes from the PSS-keyed MAC instead */
    int der_len = i2d_re_X509_REQ_tbs(req, NULL);
    if (der_len <= 0 || der_len > CSR_MAX_DER_LENGTH)
    {
        OS_printf("APQS RENEWAL: CSR DER length %d out of range\n", der_len);
        cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
        return -1;
    }

    unsigned char* out = csr_der;
    if (i2d_re_X509_REQ_tbs(req, &out) != der_len)
    {
        OS_printf("APQS RENEWAL: CSR DER encode failed\n");
        cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
        return -1;
    }

    *csr_len = (size_t)der_len;
    cert_renewal_build_csr_cleanup(active_cert, fallback_subject, req, pkey);
    return 0;
}

/*
** Failure path of cert_renewal_start: wipe secrets, roll the persisted state
** back to IDLE so a half-started renewal cannot linger, report the error.
*/
static void cert_renewal_start_fail(uint8_t* pss, size_t pss_size, uint8_t* sk, size_t sk_size, pki_renewal_state_t* state)
{
    memset(pss, 0, pss_size);
    memset(sk, 0, sk_size);
    memset(state, 0, sizeof(*state));
    state->magic   = PKI_RENEWAL_MAGIC;
    state->version = PKI_RENEWAL_VERSION;
    state->phase   = PKI_RENEWAL_IDLE;
    pki_store_save_renewal_state(state);
    CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: cert renewal start failed");
    pki_send_status(pki_PkiMessage_renew_cert_tag, PKI_STATUS_ERR_STORE, "csr generation failed");
}

void cert_renewal_start(void)
{
    static uint8_t pk[ML_KEM_768_PK_LENGTH];
    static uint8_t sk[ML_KEM_768_SK_LENGTH];
    static uint8_t csr_der[CSR_MAX_DER_LENGTH];
    uint8_t pss[PKI_PSS_MAX_LENGTH];
    size_t pss_len = 0;
    pki_renewal_state_t state;

    /* the CSR MAC needs the PSS - check before any key material is generated */
    if (pki_store_load_pss(pss, &pss_len) != 0)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: cert renewal aborted - no PSS installed (run init_trust first)");
        pki_send_status(pki_PkiMessage_renew_cert_tag, PKI_STATUS_ERR_STATE, "no pss installed");
        return;
    }

    /* 1. Generate the pending keypair from a fresh seed (QRNG not yet available - system RNG) */
    memset(&state, 0, sizeof(state));
    state.magic   = PKI_RENEWAL_MAGIC;
    state.version = PKI_RENEWAL_VERSION;
    state.phase   = PKI_RENEWAL_CSR_PENDING;
    if (randombytes(state.seed, sizeof(state.seed)) != 0)
    {
        OS_printf("APQS RENEWAL: randombytes failed\n");
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, state.seed) != 0)
    {
        OS_printf("APQS RENEWAL: keypair_derand failed\n");
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }
    /* secret key is re-derivable from the persisted seed - do not keep it around */
    memset(sk, 0, sizeof(sk));

    if (cert_renewal_hash_pk(pk, state.pk_hash) != 0)
    {
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    /* 2. Persist the state BEFORE the CSR leaves the spacecraft */
    if (pki_store_save_renewal_state(&state) != 0)
    {
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    /* 3. Build the CSR */
    size_t csr_len = 0;
    if (cert_renewal_build_csr(pk, csr_der, &csr_len) != 0)
    {
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    /* 4. MAC the CSR with the PSS (NIST SP 800-224, HMAC-SHA3-384) */
    uint8_t mac[HMAC_SHA3_384_TAG_LENGTH];
    hmac_part_t csr_part = { csr_der, csr_len };
    int mac_status = hmac_sha3_384(pss, pss_len, &csr_part, 1, mac);
    memset(pss, 0, sizeof(pss));
    if (mac_status != 0)
    {
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    /* 5. Encode CsrRequest and hand it to CFDP */
    static pki_PkiMessage msg;
    msg = (pki_PkiMessage)pki_PkiMessage_init_zero;
    msg.which_payload = pki_PkiMessage_csr_request_tag;
    memcpy(msg.payload.csr_request.csr.bytes, csr_der, csr_len);
    msg.payload.csr_request.csr.size = (pb_size_t)csr_len;
    memcpy(msg.payload.csr_request.mac.bytes, mac, sizeof(mac));
    msg.payload.csr_request.mac.size = sizeof(mac);

    static uint8_t encode_buf[pki_CsrRequest_size + 16];
    pb_ostream_t stream = pb_ostream_from_buffer(encode_buf, sizeof(encode_buf));
    bool encoded = pb_encode(&stream, pki_PkiMessage_fields, &msg);
    memset(&msg, 0, sizeof(msg));
    if (!encoded)
    {
        OS_printf("APQS RENEWAL: CSR encode failed\n");
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    if (pki_store_write_atomic(PKI_CSR_FILE_PATH, encode_buf, stream.bytes_written) != 0)
    {
        cert_renewal_start_fail(pss, sizeof(pss), sk, sizeof(sk), &state);
        return;
    }

    send_file_via_cfdp(PKI_CSR_FILE_PATH, "PKI_CSR.pbin");
    CFE_EVS_SendEvent(APQS_PKI_CSR_SENT_INF_EID, CFE_EVS_EventType_INFORMATION, "APQS PKI: CSR sent (%lu bytes), renewal pending", (unsigned long)csr_len);

    memset(state.seed, 0, sizeof(state.seed));
}

static void cert_renewal_write_new_pem_cleanup(EVP_PKEY* pkey, EVP_PKEY_CTX* pctx, BIO* mem)
{
    if (mem)
    {
        /* the mem BIO held the private key PEM - wipe before freeing */
        char* wipe_ptr;
        long wipe_len = BIO_get_mem_data(mem, &wipe_ptr);
        if (wipe_ptr && wipe_len > 0)
            OPENSSL_cleanse(wipe_ptr, (size_t)wipe_len);
        BIO_free(mem);
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
}

/*
** Re-derive the pending keypair and write the new combined sat.pem
** (PKCS#8 seed-form private key + new certificate + CA certificate).
*/
static int cert_renewal_write_new_pem(const pki_renewal_state_t* state, X509* new_cert, X509* ca_cert)
{
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    BIO* mem = NULL;

    /* private key from the persisted seed */
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!pctx)
    {
        OS_printf("APQS RENEWAL: EVP_PKEY_CTX_new_from_name(ML-KEM-768) failed\n");
        cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void*)state->seed, sizeof(state->seed)),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
    {
        OS_printf("APQS RENEWAL: EVP_PKEY_fromdata (seed) failed\n");
        cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
        return -1;
    }

    mem = BIO_new(BIO_s_mem());
    if (!mem)
    {
        cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
        return -1;
    }

    if (PEM_write_bio_PKCS8PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL) != 1 ||
        PEM_write_bio_X509(mem, new_cert) != 1 ||
        PEM_write_bio_X509(mem, ca_cert) != 1)
    {
        OS_printf("APQS RENEWAL: PEM assembly failed\n");
        cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
        return -1;
    }

    char* pem_ptr;
    long pem_len = BIO_get_mem_data(mem, &pem_ptr);
    if (pki_store_write_atomic(PKI_VPATH_SAT_NEW, pem_ptr, (size_t)pem_len) != 0)
    {
        cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
        return -1;
    }

    cert_renewal_write_new_pem_cleanup(pkey, pctx, mem);
    return 0;
}

/*
** Free the certificates and wipe the renewal state (holds the seed) and the
** re-derived public key.
*/
static void cert_renewal_handle_new_certificate_cleanup(X509* new_cert, X509* ca_cert, pki_renewal_state_t* state, uint8_t* pk, size_t pk_size)
{
    if (ca_cert) X509_free(ca_cert);
    if (new_cert) X509_free(new_cert);
    memset(state, 0, sizeof(*state));
    memset(pk, 0, pk_size);
}

void cert_renewal_handle_new_certificate(pki_NewCertificate* new_cert_msg)
{
    static uint8_t pk[ML_KEM_768_PK_LENGTH];
    static uint8_t sk[ML_KEM_768_SK_LENGTH];
    uint8_t pk_hash[32];
    pki_renewal_state_t state;
    X509* new_cert = NULL;
    X509* ca_cert = NULL;

    /* 1. A certificate is only acceptable while a CSR is pending */
    pki_store_load_renewal_state(&state);
    if (state.phase != PKI_RENEWAL_CSR_PENDING)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: certificate received but no CSR pending");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_STATE, "no csr pending");
        return;
    }

    /* 2. Re-derive the pending public key and check state integrity */
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, state.seed) != 0 ||
        cert_renewal_hash_pk(pk, pk_hash) != 0 ||
        memcmp(pk_hash, state.pk_hash, sizeof(pk_hash)) != 0)
    {
        memset(sk, 0, sizeof(sk));
        memset(&state, 0, sizeof(state));
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: pending key re-derivation failed (state corrupt?)");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_STATE, "pending key invalid");
        return;
    }
    memset(sk, 0, sizeof(sk));

    /* 3. Parse the certificate and require its SPKI to be exactly the pending key */
    const unsigned char* p = new_cert_msg->cert_sat.bytes;
    new_cert = d2i_X509(NULL, &p, (long)new_cert_msg->cert_sat.size);
    if (!new_cert)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: new certificate does not parse");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_VALIDATION, "cert parse failed");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }

    const unsigned char* cert_pk = NULL;
    int cert_pk_len = 0;
    if (X509_PUBKEY_get0_param(NULL, &cert_pk, &cert_pk_len, NULL, X509_get_X509_PUBKEY(new_cert)) != 1 ||
        cert_pk_len != ML_KEM_768_PK_LENGTH || memcmp(cert_pk, pk, ML_KEM_768_PK_LENGTH) != 0)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: certificate public key does not match the pending CSR key");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_VALIDATION, "pubkey mismatch");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }

    /* 4. Chain verification against the trusted CA (Ver_Cert_PKCA) */
    ca_cert = pem_load_ca_cert_x509(pki_path_ca());
    if (!ca_cert || pem_verify_cert_against_ca_x509(new_cert, ca_cert) != 0)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: new certificate failed CA verification");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_VALIDATION, "ca verification failed");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }

    /* 5. Stage the new combined PEM, then swap atomically:
     *    sat_new staged -> sat.pem renamed to sat_old -> sat_new promoted -> state cleared.
     *    pki_store_init() recovers from a crash at any point in this sequence. */
    if (cert_renewal_write_new_pem(&state, new_cert, ca_cert) != 0)
    {
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_STORE, "pem staging failed");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }

    OS_remove(PKI_VPATH_SAT_OLD);
    /* first-time install (cold start): no current sat.pem to keep as rollback */
    if (pki_store_vpath_exists(PKI_VPATH_SAT_PEM) &&
        OS_rename(PKI_VPATH_SAT_PEM, PKI_VPATH_SAT_OLD) != OS_SUCCESS)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: certificate swap rename failed");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_STORE, "swap failed");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }
    if (OS_rename(PKI_VPATH_SAT_NEW, PKI_VPATH_SAT_PEM) != OS_SUCCESS)
    {
        CFE_EVS_SendEvent(APQS_PKI_RENEW_ERR_EID, CFE_EVS_EventType_ERROR, "APQS PKI: certificate swap rename failed");
        pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_ERR_STORE, "swap failed");
        cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
        return;
    }

    /* 6. Renewal complete - back to IDLE (old material kept until the next handshake succeeds) */
    memset(&state, 0, sizeof(state));
    state.magic   = PKI_RENEWAL_MAGIC;
    state.version = PKI_RENEWAL_VERSION;
    state.phase   = PKI_RENEWAL_IDLE;
    pki_store_save_renewal_state(&state);

    CFE_EVS_SendEvent(APQS_PKI_CERT_SWAP_INF_EID, CFE_EVS_EventType_INFORMATION, "APQS PKI: new certificate installed, old key retained until next successful handshake");
    pki_send_status(pki_PkiMessage_new_certificate_tag, PKI_STATUS_OK, "certificate installed");

    cert_renewal_handle_new_certificate_cleanup(new_cert, ca_cert, &state, pk, sizeof(pk));
}

void cert_renewal_confirm_new_key(void)
{
    if (pki_store_vpath_exists(PKI_VPATH_SAT_OLD))
    {
        OS_remove(PKI_VPATH_SAT_OLD);
        CFE_EVS_SendEvent(APQS_PKI_CERT_SWAP_INF_EID, CFE_EVS_EventType_INFORMATION, "APQS PKI: new key confirmed by successful handshake, rollback copy removed");
    }
}
