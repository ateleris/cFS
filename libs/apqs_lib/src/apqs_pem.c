#include "apqs_app_pem.h"
#include "cfe.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "pqclean/ml-kem-768/kem.h"

#include <string.h>

/* OCSP timestamp clock-skew tolerance; the check is warn-only (mirrors ground behavior) */
#define OCSP_VALIDITY_TOLERANCE_SEC 300


static int unwrap_der_tlv(const unsigned char* buf, int len, unsigned char expected_tag, const unsigned char** content, int* content_len)
{
    if (len < 2 || buf[0] != expected_tag)
    {
        OS_printf("APQS PEM: expected DER tag 0x%02x, got 0x%02x\n", (unsigned)expected_tag, (unsigned)buf[0]);
        return -1;
    }

    int header;
    int inner_len;

    if (buf[1] < 0x80)
    {
        inner_len = buf[1];
        header = 2;
    }
    else if (buf[1] == 0x82 && len >= 4)
    {
        inner_len = ((int)buf[2] << 8) | buf[3];
        header = 4;
    }
    else
    {
        OS_printf("APQS PEM: unsupported DER length encoding 0x%02x\n", (unsigned)buf[1]);
        return -1;
    }

    if (header + inner_len > len)
    {
        OS_printf("APQS PEM: DER length %d overflows buffer %d\n", inner_len, len);
        return -1;
    }

    *content = buf + header;
    *content_len = inner_len;
    return 0;
}

int pem_load_sat_secret_key(const char* pem_path, uint8_t* pk_out, uint8_t* sk_out)
{
    BIO* bio = BIO_new_file(pem_path, "r");
    if (!bio)
    {
        OS_printf("APQS PEM: BIO_new_file failed for %s\n", pem_path);
        return -1;
    }

    PKCS8_PRIV_KEY_INFO* p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!p8inf)
    {
        OS_printf("APQS PEM: no PRIVATE KEY block in %s\n", pem_path);
        return -1;
    }

    const unsigned char* priv_bytes = NULL;
    int priv_len = 0;

    if (PKCS8_pkey_get0(NULL, &priv_bytes, &priv_len, NULL, p8inf) != 1 || priv_bytes == NULL)
    {
        OS_printf("APQS PEM: PKCS8_pkey_get0 failed\n");
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return -1;
    }

    OS_printf("APQS PEM: privateKey OCTET STRING length = %d\n", priv_len);

    if (priv_len == ML_KEM_768_SEED_LENGTH)
    {
        OS_printf("APQS PEM: seed format, expanding ML-KEM-768 keypair\n");
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk_out, sk_out, priv_bytes) != 0)
        {
            OS_printf("APQS PEM: keypair_derand failed\n");
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
    }
    else if (priv_len == ML_KEM_768_SEED_LENGTH + 2 && priv_bytes[0] == 0x80 && priv_bytes[1] == ML_KEM_768_SEED_LENGTH)
    {
        /* OpenSSL >= 3.5 PKCS#8 seed CHOICE: [0] IMPLICIT OCTET STRING (0x80 0x40 <64-byte seed>) */
        OS_printf("APQS PEM: seed CHOICE format, expanding ML-KEM-768 keypair\n");
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk_out, sk_out, priv_bytes + 2) != 0)
        {
            OS_printf("APQS PEM: keypair_derand failed\n");
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
    }
    else if (priv_len > 2 && priv_bytes[0] == 0x30)
    {
        /* "both" CHOICE (draft-ietf-lamps-kyber-certificates, written by OpenSSL >= 3.5):
         * SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } - use the seed */
        const unsigned char* seq;
        int seq_len;
        const unsigned char* seed;
        int seed_len;
        if (unwrap_der_tlv(priv_bytes, priv_len, 0x30, &seq, &seq_len) < 0 ||
            unwrap_der_tlv(seq, seq_len, 0x04, &seed, &seed_len) < 0)
        {
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
        if (seed_len != ML_KEM_768_SEED_LENGTH)
        {
            OS_printf("APQS PEM: seed length %d in both-format, expected %d\n", seed_len, ML_KEM_768_SEED_LENGTH);
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
        OS_printf("APQS PEM: both-format (seed+expanded), expanding ML-KEM-768 keypair from seed\n");
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk_out, sk_out, seed) != 0)
        {
            OS_printf("APQS PEM: keypair_derand failed\n");
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
    }
    else if (priv_len > ML_KEM_768_SK_LENGTH)
    {
        const unsigned char* inner;
        int inner_len;
        if (unwrap_der_tlv(priv_bytes, priv_len, 0x04, &inner, &inner_len) < 0)
        {
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
        if (inner_len != ML_KEM_768_SK_LENGTH)
        {
            OS_printf("APQS PEM: inner key length %d, expected %d\n", inner_len, ML_KEM_768_SK_LENGTH);
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            return -1;
        }
        OS_printf("APQS PEM: expanded format, copying %d-byte secret key\n", inner_len);
        memcpy(sk_out, inner, ML_KEM_768_SK_LENGTH);
        memcpy(pk_out, sk_out + KYBER_INDCPA_SECRETKEYBYTES, ML_KEM_768_PK_LENGTH);
    }
    else
    {
        OS_printf("APQS PEM: unexpected privateKey size %d\n", priv_len);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return -1;
    }

    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return 0;
}

int pem_load_public_key(const char* pem_path, uint8_t* pk_out)
{
    BIO* bio = BIO_new_file(pem_path, "r");
    if (!bio)
    {
        OS_printf("APQS PEM: BIO_new_file failed for %s\n", pem_path);
        return -1;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert)
    {
        OS_printf("APQS PEM: no CERTIFICATE block in %s\n", pem_path);
        return -1;
    }

    const unsigned char* pk_bytes = NULL;
    int pk_len = 0;

    if (X509_PUBKEY_get0_param(NULL, &pk_bytes, &pk_len, NULL, X509_get_X509_PUBKEY(cert)) != 1 || pk_bytes == NULL)
    {
        OS_printf("APQS PEM: X509_PUBKEY_get0_param failed\n");
        X509_free(cert);
        return -1;
    }

    if (pk_len != ML_KEM_768_PK_LENGTH)
    {
        OS_printf("APQS PEM: cert public key length %d, expected %d\n", pk_len, ML_KEM_768_PK_LENGTH);
        X509_free(cert);
        return -1;
    }

    memcpy(pk_out, pk_bytes, ML_KEM_768_PK_LENGTH);
    X509_free(cert);
    return 0;
}

int pem_load_identity(const char* pem_path, uint8_t* identity_out, uint32_t* identity_len)
{
    BIO* bio = BIO_new_file(pem_path, "r");
    if (!bio)
    {
        OS_printf("APQS PEM: BIO_new_file failed for %s\n", pem_path);
        return -1;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert)
    {
        OS_printf("APQS PEM: no CERTIFICATE block in %s\n", pem_path);
        return -1;
    }

    X509_NAME* subj = X509_get_subject_name(cert);
    if (!subj)
    {
        OS_printf("APQS PEM: X509_get_subject_name failed for %s\n", pem_path);
        X509_free(cert);
        return -1;
    }

    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem)
    {
        OS_printf("APQS PEM: BIO_new(BIO_s_mem) failed\n");
        X509_free(cert);
        return -1;
    }

    if (X509_NAME_print_ex(mem, subj, 0, XN_FLAG_RFC2253) < 0)
    {
        OS_printf("APQS PEM: X509_NAME_print_ex failed for %s\n", pem_path);
        BIO_free(mem);
        X509_free(cert);
        return -1;
    }

    char* dn_ptr;
    long dn_len = BIO_get_mem_data(mem, &dn_ptr);

    if (dn_len <= 0 || dn_len >= APQS_MAX_IDENTITY_LENGTH)
    {
        OS_printf("APQS PEM: subject DN length %ld out of range for %s\n", dn_len, pem_path);
        BIO_free(mem);
        X509_free(cert);
        return -1;
    }

    memcpy(identity_out, dn_ptr, (uint32_t)dn_len);
    *identity_len = (uint32_t)dn_len;

    BIO_free(mem);
    X509_free(cert);
    return 0;
}

X509* pem_load_cert_x509(const char* pem_path)
{
    BIO* bio = BIO_new_file(pem_path, "r");
    if (!bio)
    {
        OS_printf("APQS PEM: BIO_new_file failed for %s\n", pem_path);
        return NULL;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert)
        OS_printf("APQS PEM: no CERTIFICATE block in %s\n", pem_path);

    return cert;
}

X509* pem_load_ca_cert_x509(const char* pem_path)
{
    BIO* bio = BIO_new_file(pem_path, "r");
    if (!bio)
    {
        OS_printf("APQS PEM: BIO_new_file failed for %s\n", pem_path);
        return NULL;
    }

    /* Scan all CERTIFICATE blocks and return the first one that is a CA.
     * This handles both a combined PEM (private key + cert + CA) and a
     * file containing only the CA certificate. */
    X509* cert = NULL;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL)
    {
        BASIC_CONSTRAINTS* bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
        if (bc && bc->ca)
        {
            BASIC_CONSTRAINTS_free(bc);
            BIO_free(bio);
            return cert;
        }
        if (bc) BASIC_CONSTRAINTS_free(bc);
        X509_free(cert);
    }

    BIO_free(bio);
    OS_printf("APQS PEM: no CA CERTIFICATE block in %s\n", pem_path);
    return NULL;
}

/*
** Crypto.Ver_Cert_PKCA — verify an entity certificate against the CA certificate.
** Issuer DN and signature are hard failures; an out-of-range validity period
** only warns, mirroring the OCSP timestamp policy below. Caller owns both certs.
*/
int pem_verify_cert_against_ca_x509(X509* cert, X509* ca_cert)
{
    if (X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(ca_cert)) != 0)
    {
        OS_printf("APQS CERTVER: certificate issuer does not match CA subject\n");
        return -1;
    }

    EVP_PKEY* ca_pkey = X509_get_pubkey(ca_cert);
    if (!ca_pkey)
    {
        OS_printf("APQS CERTVER: X509_get_pubkey failed for CA cert\n");
        return -1;
    }

    int verify_status = X509_verify(cert, ca_pkey);
    EVP_PKEY_free(ca_pkey);

    if (verify_status != 1)
    {
        OS_printf("APQS CERTVER: certificate signature verification failed\n");
        return -1;
    }

    if (X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert)) <= 0)
    {
        OS_printf("APQS CERTVER: certificate validity period out of range (warning only)\n");
    }

    return 0;
}

int pem_verify_cert_against_ca(const char* cert_path, const char* ca_path)
{
    X509* cert = pem_load_cert_x509(cert_path);
    if (!cert)
        return -1;

    X509* ca_cert = pem_load_ca_cert_x509(ca_path);
    if (!ca_cert)
    {
        X509_free(cert);
        return -1;
    }

    int status = pem_verify_cert_against_ca_x509(cert, ca_cert);

    X509_free(ca_cert);
    X509_free(cert);
    return status;
}

static void ocsp_verify_response_cleanup(OCSP_RESPONSE* ocsp_resp, OCSP_BASICRESP* basic, X509* entity_cert, X509* ca_cert, OCSP_CERTID* cert_id, X509_STORE* store)
{
    if (store) X509_STORE_free(store);
    if (cert_id) OCSP_CERTID_free(cert_id);
    if (ca_cert) X509_free(ca_cert);
    if (entity_cert) X509_free(entity_cert);
    if (basic) OCSP_BASICRESP_free(basic);
    if (ocsp_resp) OCSP_RESPONSE_free(ocsp_resp);
}

/* Core verification; entity_cert and ca_cert are caller-owned and not freed here */
int ocsp_verify_response_x509(const uint8_t* ocsp_der, size_t ocsp_len, X509* entity_cert, X509* ca_cert)
{
    if (!entity_cert || !ca_cert)
    {
        OS_printf("APQS OCSP: entity or CA certificate missing\n");
        return -1;
    }

    // cleanup vars
    OCSP_RESPONSE* ocsp_resp = NULL;
    OCSP_BASICRESP* basic = NULL;
    OCSP_CERTID* cert_id = NULL;
    X509_STORE* store = NULL;

    // 1. Parse DER-encoded OCSP response
    const unsigned char* p = ocsp_der;
    ocsp_resp = d2i_OCSP_RESPONSE(NULL, &p, (long)ocsp_len);
    if (!ocsp_resp)
    {
        OS_printf("APQS OCSP: d2i_OCSP_RESPONSE failed\n");
        return -1;
    }

    // 2. Check top-level response status
    int resp_status = OCSP_response_status(ocsp_resp);
    if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
        OS_printf("APQS OCSP: response status %d (expected SUCCESSFUL)\n", resp_status);
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }

    // 3. Extract BasicOCSPResponse
    basic = OCSP_response_get1_basic(ocsp_resp);
    if (!basic)
    {
        OS_printf("APQS OCSP: OCSP_response_get1_basic failed\n");
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }

    // 4. Build cert ID with matching hash algorithm.
    int cert_status = -1;
    int reason = 0;
    ASN1_GENERALIZEDTIME* this_update = NULL;
    ASN1_GENERALIZEDTIME* next_update = NULL;
    ASN1_GENERALIZEDTIME* rev_time = NULL;
    int status_found = 0;

    cert_id = OCSP_cert_to_id(EVP_sha256(), entity_cert, ca_cert);
    if (cert_id)
    {
        status_found = OCSP_resp_find_status(basic, cert_id, &cert_status, &reason, &rev_time, &this_update, &next_update);
        OS_printf("APQS OCSP: SHA-256 cert ID lookup: %s\n", status_found == 1 ? "found" : "not found");
    }

    // 5. Hard fail if serial not found
    if (status_found != 1)
    {
        OS_printf("APQS OCSP: serial number not found in OCSP response\n");
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }

    // 6. Timestamp check — warn only (mirrors Python behavior)
    if (OCSP_check_validity(this_update, next_update, OCSP_VALIDITY_TOLERANCE_SEC, -1) != 1)
        OS_printf("APQS OCSP: OCSP response timestamps invalid (warning only)\n");

    // 7. Certificate status must be GOOD — hard fail otherwise
    if (cert_status != V_OCSP_CERTSTATUS_GOOD)
    {
        OS_printf("APQS OCSP: certificate status is not GOOD (%d)\n", cert_status);
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }

    // 8. Verify OCSP signature using CA public key.
    store = X509_STORE_new();
    if (!store)
    {
        OS_printf("APQS OCSP: X509_STORE_new failed\n");
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }
    if (X509_STORE_add_cert(store, ca_cert) != 1)
    {
        OS_printf("APQS OCSP: X509_STORE_add_cert failed\n");
        ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
        return -1;
    }

    if (OCSP_basic_verify(basic, NULL, store, OCSP_NOCHAIN) == 1)
    {
        OS_printf("APQS OCSP: signature verified via OCSP_basic_verify\n");
    }
    else
    {
        OS_printf("APQS OCSP: OCSP_basic_verify failed, trying manual verification\n");
        ERR_clear_error();

        EVP_PKEY* ca_pkey = X509_get_pubkey(ca_cert);
        if (!ca_pkey)
        {
            OS_printf("APQS OCSP: X509_get_pubkey failed\n");
            ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
            return -1;
        }

        const OCSP_RESPDATA* respdata = OCSP_resp_get0_respdata(basic);
        unsigned char* tbs_der = NULL;
        int tbs_len = i2d_OCSP_RESPDATA(respdata, &tbs_der);

        const ASN1_OCTET_STRING* sig = OCSP_resp_get0_signature(basic);

        int verify_ok = -1;
        if (tbs_len > 0 && tbs_der != NULL && sig != NULL && sig->data != NULL)
        {
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            if (md_ctx != NULL)
            {
                if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, ca_pkey) == 1 && EVP_DigestVerify(md_ctx, sig->data, (size_t)sig->length, tbs_der, (size_t)tbs_len) == 1)
                {
                    verify_ok = 0;
                    OS_printf("APQS OCSP: manual signature verification succeeded\n");
                }
                else
                {
                    OS_printf("APQS OCSP: manual signature verification failed\n");
                }
                EVP_MD_CTX_free(md_ctx);
            }
        }
        else
        {
            OS_printf("APQS OCSP: failed to extract TBS or signature for manual verification\n");
        }

        if (tbs_der)
            OPENSSL_free(tbs_der);
        EVP_PKEY_free(ca_pkey);

        if (verify_ok != 0)
        {
            ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
            return -1;
        }
    }

    ocsp_verify_response_cleanup(ocsp_resp, basic, NULL, NULL, cert_id, store);
    return 0;
}

int ocsp_verify_response(const uint8_t* ocsp_der, size_t ocsp_len, const char* entity_cert_path, const char* ca_cert_path)
{
    X509* entity_cert = pem_load_cert_x509(entity_cert_path);
    if (!entity_cert)
    {
        OS_printf("APQS OCSP: failed to load entity cert from %s\n", entity_cert_path);
        return -1;
    }

    X509* ca_cert = pem_load_ca_cert_x509(ca_cert_path);
    if (!ca_cert)
    {
        OS_printf("APQS OCSP: failed to load CA cert from %s\n", ca_cert_path);
        X509_free(entity_cert);
        return -1;
    }

    int status = ocsp_verify_response_x509(ocsp_der, ocsp_len, entity_cert, ca_cert);

    X509_free(ca_cert);
    X509_free(entity_cert);
    return status;
}
