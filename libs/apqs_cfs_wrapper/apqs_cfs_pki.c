#include "apqs_cfs_pki.h"

#include <apqs/pki.h>
#include <apqs/handshake.h>
#include <apqs/pki_store.h>

/*
** The schema, for the one _Static_assert below and nothing else.
**
** Included directly because the APQS public headers no longer name protobuf types
** and so no longer drag it in - which is the point of them. nanopb stays PRIVATE to
** this module, so the wire format still cannot leak out to applications.
*/
#include <pki.pb.h>

/*
** Forwarders onto the framework-free core, as in apqs_cfs_api.c. Thin by
** design: name translation only, and keeping the module's symbol surface
** self-contained.
**
** No protobuf in the signatures. The library decodes and encodes internally, so
** this layer moves bytes and status codes and nothing else.
*/

apqs_status_t APQS_CFS_HandshakeHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                              size_t *reply_len)
{
    return apqs_handshake_handle_message(msg, msg_len, reply, reply_cap, reply_len);
}

apqs_status_t APQS_CFS_PkiHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                        size_t *reply_len, uint32_t *op_tag)
{
    return apqs_pki_handle_message(msg, msg_len, reply, reply_cap, reply_len, op_tag);
}

_Static_assert(APQS_CFS_PKI_OP_RENEW_CERT == pki_PkiMessage_renew_cert_tag,
               "APQS_CFS_PKI_OP_RENEW_CERT in apqs_cfs_pki.h no longer matches pki.proto");

apqs_status_t APQS_CFS_PkiEncodeStatus(uint32_t op, apqs_status_t status, uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    /* detail left to the library: the app reports codes it did not produce, and
     * the reason for each already went out as an event. */
    return apqs_pki_status_encode(op, status, NULL, out, out_cap, out_len);
}

apqs_status_t APQS_CFS_HandshakeSetSessionKey(void)
{
    // Straight through: the core reports apqs_status_t now, so there is no
    // HANDSHAKE_SUCCESS to translate from.
    return apqs_handshake_set_session_key();
}

void APQS_CFS_HandshakeResetKeys(bool reset_session_key)
{
    apqs_handshake_reset_keys(reset_session_key);
}

apqs_status_t APQS_CFS_CertRenewalStart(uint8_t *csr_msg, size_t csr_cap, size_t *csr_msg_len)
{
    return apqs_cert_renewal_start(csr_msg, csr_cap, csr_msg_len);
}

void APQS_CFS_CertRenewalConfirmNewKey(void)
{
    apqs_cert_renewal_confirm_new_key();
}
