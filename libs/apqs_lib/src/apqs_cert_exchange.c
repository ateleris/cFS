#include "apqs_cert.h"

/* EXCHANGE */
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <pb_encode.h>
#include <string.h>

#include "apqs_errors.h"
#include "apqs_event.h"
#include "apqs_pem.h"
#include "apqs_handshake.h"

#define PKI_CERT_SAT_FILE_PATH "/cf/PKI_CERT_SAT.pbin"

/*
** Load the active SAT certificate from the store and send it to the
** ground as a CertSat message (PKI_CERT_SAT.pbin).
*/
static int cert_exchange_send_sat_cert(X509* sat_cert, uint32_t op)
{
    // TODO move loading to app
    //X509* sat_cert = pem_load_cert_x509(pki_path_sat());
    //if (!sat_cert)
    //{
    //    apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: active SAT certificate not loadable");
    //    pki_send_status(op, PKI_STATUS_ERR_STORE, "sat cert not loadable");
    //    return -1;
    //}
    if (!sat_cert)
    {
        return APQS_SAT_CERT_NULL;
    }

    static pki_PkiMessage reply_msg;
    reply_msg = (pki_PkiMessage)pki_PkiMessage_init_zero;
    reply_msg.which_payload = pki_PkiMessage_cert_sat_tag;

    unsigned char* out = reply_msg.payload.cert_sat.cert_sat.bytes;
    int der_len = i2d_X509(sat_cert, NULL);
    if (der_len <= 0 || der_len > (int)sizeof(reply_msg.payload.cert_sat.cert_sat.bytes))
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: SAT cert DER length %d out of range", der_len);
        pki_send_status(op, PKI_STATUS_ERR_STORE, "sat cert der encode failed");
        X509_free(sat_cert);
        return -1;
    }
    i2d_X509(sat_cert, &out);
    reply_msg.payload.cert_sat.cert_sat.size = (pb_size_t)der_len;
    X509_free(sat_cert);

    static uint8_t encode_buf[pki_CertSat_size + 16];
    pb_ostream_t stream = pb_ostream_from_buffer(encode_buf, sizeof(encode_buf));
    if (!pb_encode(&stream, pki_PkiMessage_fields, &reply_msg))
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: CertSat encode failed");
        pki_send_status(op, PKI_STATUS_ERR_STORE, "cert sat encode failed");
        return -1;
    }

    if (pki_store_write_atomic(PKI_CERT_SAT_FILE_PATH, encode_buf, stream.bytes_written) != 0)
    {
        pki_send_status(op, PKI_STATUS_ERR_STORE, "cert sat write failed");
        return -1;
    }

    send_file_via_cfdp(PKI_CERT_SAT_FILE_PATH, "PKI_CERT_SAT.pbin");
    apqs_event_send(APQS_PKI_CERT_SAT_SENT_INF_EID, APQS_EVENT_INFO, "APQS PKI: SAT certificate sent to ground (%d bytes DER)", der_len);
    return 0;
}

static void cert_exchange_handle_cleanup(X509* mcs_cert, X509* ca_cert, BIO* mem)
{
    if (mem) BIO_free(mem);
    if (ca_cert) X509_free(ca_cert);
    if (mcs_cert) X509_free(mcs_cert);
}

/*
** Certificate exchange: verify and store the MCS certificate (chain + OCSP),
** then reply with the SAT certificate.
*/
void cert_exchange_handle(pki_CertExchange* cert_exchange)
{
    X509* mcs_cert = NULL;
    X509* ca_cert = NULL;
    BIO* mem = NULL;

    /* 1. Parse the MCS certificate (DER) */
    const unsigned char* p = cert_exchange->cert_mcs.bytes;
    mcs_cert = d2i_X509(NULL, &p, (long)cert_exchange->cert_mcs.size);
    if (!mcs_cert)
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: MCS certificate does not parse");
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_ERR_VALIDATION, "cert parse failed");
        cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
        return;
    }

    /* 2. Chain verification against the trusted CA (Ver_Cert_PKCA) */
    ca_cert = pem_load_ca_cert_x509(pki_path_ca());
    if (!ca_cert || pem_verify_cert_against_ca_x509(mcs_cert, ca_cert) != 0)
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: MCS certificate failed CA verification");
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_ERR_VALIDATION, "ca verification failed");
        cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
        return;
    }

    /* 3. OCSP status of the received certificate must be GOOD (diagram:
     *    Revoked/Unknown -> send failure to MCS and terminate exchange) */
    if (cert_exchange->ocsp_resp_mcs.size == 0 ||
        ocsp_verify_response_x509(cert_exchange->ocsp_resp_mcs.bytes, cert_exchange->ocsp_resp_mcs.size, mcs_cert, ca_cert) != 0)
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: MCS certificate OCSP verification failed - exchange terminated");
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_ERR_VALIDATION, "ocsp verification failed");
        cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
        return;
    }

    /* 4. Store the new combined mcs.pem (cert + CA) atomically */
    mem = BIO_new(BIO_s_mem());
    if (!mem || PEM_write_bio_X509(mem, mcs_cert) != 1 || PEM_write_bio_X509(mem, ca_cert) != 1)
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_ERR_EID, APQS_EVENT_ERROR, "APQS PKI: MCS certificate PEM conversion failed");
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_ERR_STORE, "pem conversion failed");
        cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
        return;
    }

    char* pem_ptr;
    long pem_len = BIO_get_mem_data(mem, &pem_ptr);
    if (pki_store_write_atomic(PKI_VPATH_MCS_PEM, pem_ptr, (size_t)pem_len) != 0)
    {
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_ERR_STORE, "mcs cert store failed");
        cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
        return;
    }

    apqs_event_send(APQS_PKI_CERT_XCHG_INF_EID, APQS_EVENT_INFO, "APQS PKI: MCS certificate verified (chain + OCSP) and stored");

    /* 5. Reply with the SAT certificate (best effort). On cold start no SAT
     * cert exists until renewal runs - that must not fail the exchange itself:
     * the OK status gates the ground's key-file commit, and the ground can
     * fetch the certificate later via CertSatRequest. */
    if (!pki_store_vpath_exists(PKI_VPATH_SAT_PEM))
    {
        apqs_event_send(APQS_PKI_CERT_XCHG_INF_EID, APQS_EVENT_INFO, "APQS PKI: no SAT certificate yet - skipping cert reply (run renewal)");
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_OK, "exchange ok, no sat cert yet");
    }
    else if (cert_exchange_send_sat_cert(pki_PkiMessage_cert_exchange_tag) == 0)
    {
        pki_send_status(pki_PkiMessage_cert_exchange_tag, PKI_STATUS_OK, "exchange complete");
    }

    cert_exchange_handle_cleanup(mcs_cert, ca_cert, mem);
}

/*
** Standalone request for the SAT certificate
*/
void cert_exchange_handle_cert_request(pki_CertSatRequest* request)
{
    (void)request;
    cert_exchange_send_sat_cert(pki_PkiMessage_cert_sat_request_tag);
}
