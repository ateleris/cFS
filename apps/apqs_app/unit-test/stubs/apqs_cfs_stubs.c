/**
 * @file
 *
 * Stubs for the APQS binding layer that apqs_app calls into.
 *
 * The app reaches the APQS core only through the APQS_CFS_* forwarders in
 * libs/apqs_cfs_wrapper. At runtime those resolve out of apqs_lib.so; under
 * test they resolve here, so a case can decide what the library returned
 * without linking any of it.
 *
 * This replaces the old handshake_*/pki_store_* stubs. The app used to call six
 * library entry points plus nanopb and OpenSSL directly; it now calls three
 * forwarders and does no decoding of its own, which is why those stubs went
 * away rather than being renamed.
 */

#include "apqs_cfs_pki.h"
#include "utgenstub.h"

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_HandshakeHandleMessage()
 * ----------------------------------------------------
 */
apqs_status_t APQS_CFS_HandshakeHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                              size_t *reply_len)
{
    UT_GenStub_SetupReturnBuffer(APQS_CFS_HandshakeHandleMessage, apqs_status_t);

    UT_GenStub_AddParam(APQS_CFS_HandshakeHandleMessage, const uint8_t *, msg);
    UT_GenStub_AddParam(APQS_CFS_HandshakeHandleMessage, size_t, msg_len);
    UT_GenStub_AddParam(APQS_CFS_HandshakeHandleMessage, uint8_t *, reply);
    UT_GenStub_AddParam(APQS_CFS_HandshakeHandleMessage, size_t, reply_cap);
    UT_GenStub_AddParam(APQS_CFS_HandshakeHandleMessage, size_t *, reply_len);

    UT_GenStub_Execute(APQS_CFS_HandshakeHandleMessage, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_CFS_HandshakeHandleMessage, apqs_status_t);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_PkiHandleMessage()
 * ----------------------------------------------------
 */
apqs_status_t APQS_CFS_PkiHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                        size_t *reply_len, uint32_t *op_tag)
{
    UT_GenStub_SetupReturnBuffer(APQS_CFS_PkiHandleMessage, apqs_status_t);

    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, const uint8_t *, msg);
    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, size_t, msg_len);
    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, uint8_t *, reply);
    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, size_t, reply_cap);
    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, size_t *, reply_len);
    UT_GenStub_AddParam(APQS_CFS_PkiHandleMessage, uint32_t *, op_tag);

    UT_GenStub_Execute(APQS_CFS_PkiHandleMessage, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_CFS_PkiHandleMessage, apqs_status_t);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_PkiEncodeStatus()
 * ----------------------------------------------------
 */
apqs_status_t APQS_CFS_PkiEncodeStatus(uint32_t op, apqs_status_t status, uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    UT_GenStub_SetupReturnBuffer(APQS_CFS_PkiEncodeStatus, apqs_status_t);

    UT_GenStub_AddParam(APQS_CFS_PkiEncodeStatus, uint32_t, op);
    UT_GenStub_AddParam(APQS_CFS_PkiEncodeStatus, apqs_status_t, status);
    UT_GenStub_AddParam(APQS_CFS_PkiEncodeStatus, uint8_t *, out);
    UT_GenStub_AddParam(APQS_CFS_PkiEncodeStatus, size_t, out_cap);
    UT_GenStub_AddParam(APQS_CFS_PkiEncodeStatus, size_t *, out_len);

    UT_GenStub_Execute(APQS_CFS_PkiEncodeStatus, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_CFS_PkiEncodeStatus, apqs_status_t);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_CertRenewalStart()
 * ----------------------------------------------------
 */
apqs_status_t APQS_CFS_CertRenewalStart(uint8_t *csr_msg, size_t csr_cap, size_t *csr_msg_len)
{
    UT_GenStub_SetupReturnBuffer(APQS_CFS_CertRenewalStart, apqs_status_t);

    UT_GenStub_AddParam(APQS_CFS_CertRenewalStart, uint8_t *, csr_msg);
    UT_GenStub_AddParam(APQS_CFS_CertRenewalStart, size_t, csr_cap);
    UT_GenStub_AddParam(APQS_CFS_CertRenewalStart, size_t *, csr_msg_len);

    UT_GenStub_Execute(APQS_CFS_CertRenewalStart, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_CFS_CertRenewalStart, apqs_status_t);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_HandshakeSetSessionKey()
 * ----------------------------------------------------
 */
apqs_status_t APQS_CFS_HandshakeSetSessionKey(void)
{
    UT_GenStub_SetupReturnBuffer(APQS_CFS_HandshakeSetSessionKey, apqs_status_t);
    UT_GenStub_Execute(APQS_CFS_HandshakeSetSessionKey, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_CFS_HandshakeSetSessionKey, apqs_status_t);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_HandshakeResetKeys()
 * ----------------------------------------------------
 */
void APQS_CFS_HandshakeResetKeys(bool reset_session_key)
{
    UT_GenStub_AddParam(APQS_CFS_HandshakeResetKeys, bool, reset_session_key);

    UT_GenStub_Execute(APQS_CFS_HandshakeResetKeys, Basic, NULL);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_CFS_CertRenewalConfirmNewKey()
 * ----------------------------------------------------
 */
void APQS_CFS_CertRenewalConfirmNewKey(void)
{
    UT_GenStub_Execute(APQS_CFS_CertRenewalConfirmNewKey, Basic, NULL);
}
