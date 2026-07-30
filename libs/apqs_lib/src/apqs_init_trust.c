#include "apqs_app_init_trust.h"
#include "apqs_app_pki.h"
#include "apqs_app_pem.h"
#include "apqs_event.h"

#include "cfe.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

void init_trust_handle(pki_InitTrust* init_trust)
{
    const unsigned char* p = init_trust->cert_ca.bytes;
    X509* ca_cert = d2i_X509(NULL, &p, (long)init_trust->cert_ca.size);
    if (!ca_cert)
    {
        apqs_event_send(APQS_PKI_INIT_TRUST_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: init_trust CA cert does not parse");
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_VALIDATION, "ca cert parse failed");
        return;
    }

    BASIC_CONSTRAINTS* bc = X509_get_ext_d2i(ca_cert, NID_basic_constraints, NULL, NULL);
    bool is_ca = (bc && bc->ca);
    if (bc) BASIC_CONSTRAINTS_free(bc);
    if (!is_ca)
    {
        apqs_event_send(APQS_PKI_INIT_TRUST_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: init_trust cert is not a CA");
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_VALIDATION, "not a CA cert");
        X509_free(ca_cert);
        return;
    }

    if (pem_verify_cert_against_ca_x509(ca_cert, ca_cert) != 0)
    {
        apqs_event_send(APQS_PKI_INIT_TRUST_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: init_trust CA self-signature invalid");
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_VALIDATION, "ca self-signature invalid");
        X509_free(ca_cert);
        return;
    }

    if (init_trust->pss_sat.size < PKI_PSS_MIN_LENGTH)
    {
        apqs_event_send(APQS_PKI_INIT_TRUST_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: init_trust PSS too short (%u bytes)", (unsigned)init_trust->pss_sat.size);
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_VALIDATION, "pss too short");
        X509_free(ca_cert);
        return;
    }

    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem || PEM_write_bio_X509(mem, ca_cert) != 1)
    {
        apqs_event_send(APQS_PKI_INIT_TRUST_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: init_trust CA PEM conversion failed");
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_STORE, "pem conversion failed");
        if (mem) BIO_free(mem);
        X509_free(ca_cert);
        return;
    }

    char* pem_ptr;
    long pem_len = BIO_get_mem_data(mem, &pem_ptr);
    int store_status = pki_store_write_atomic(PKI_VPATH_CA_CERT, pem_ptr, (size_t)pem_len);
    BIO_free(mem);
    X509_free(ca_cert);

    if (store_status != 0)
    {
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_STORE, "ca store failed");
        return;
    }

    if (pki_store_save_pss(init_trust->pss_sat.bytes, init_trust->pss_sat.size) != 0)
    {
        pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_ERR_STORE, "pss store failed");
        return;
    }

    apqs_event_send(APQS_PKI_INIT_TRUST_INF_EID, APQS_EVENT_INFO, "APQS PKI: init_trust complete - CA and PSS installed");
    pki_send_status(pki_PkiMessage_init_trust_tag, PKI_STATUS_OK, "trust installed");
}
