#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <apqs/errors.h>
#include <apqs/sizes.h>

/*
** cFS-facing PKI and handshake surface, used by apqs_app.
**
** Separate from apqs_cfs_api.h so ci_lab and to_lab, which only need the SDLS
** entry points, do not pull this in with them.
**
** Everything here takes and returns bytes. The library decodes and encodes the
** protobuf wire format internally and knows nothing about how a message arrived
** or how a reply leaves - CFDP, the software bus, files, receive directories
** and CF command construction all live in the application.
**
** Outcomes come back as apqs_status_t (see <apqs/errors.h>). The library used to
** answer the ground with a PkiStatus of its own; it no longer does, so deciding
** what to report is the caller's.
**
** Same contract as apqs_cfs_api.h: these are defined in a translation unit
** compiled straight into apqs_lib.so, so ES can resolve them at load time
** without whole-archive linkage against the core.
*/

// Buffer sizes for the reply arguments below.
#define APQS_CFS_HS_RESPONSE_BUFFER_SIZE APQS_HS_RESPONSE_BUFFER_SIZE
#define APQS_CFS_PKI_REPLY_BUFFER_SIZE   APQS_PKI_REPLY_BUFFER_SIZE
#define APQS_CFS_CSR_BUFFER_SIZE         APQS_CSR_BUFFER_SIZE
#define APQS_CFS_PKI_STATUS_BUFFER_SIZE  APQS_PKI_STATUS_BUFFER_SIZE

// No store-init entry point. The keystore backend is installed and any
// interrupted key swap repaired by lib_apqs_init, before the first app starts.

/*
** Handle an encoded handshake.HandshakeMessage, whatever carried it.
**
** A rekey (M1) leaves the encoded M2 in reply, which must be
** APQS_CFS_HS_RESPONSE_BUFFER_SIZE bytes. Key confirmation (M3) produces no
** reply and leaves *reply_len at 0.
*/
apqs_status_t APQS_CFS_HandshakeHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                              size_t *reply_len);

/*
** Handle an encoded pki.PkiMessage. reply must be
** APQS_CFS_PKI_REPLY_BUFFER_SIZE bytes; most flows leave *reply_len at 0.
**
** op_tag receives the PkiMessage oneof tag that was decoded (NULL if not
** wanted), so the outcome can be reported against the operation it belongs to.
*/
apqs_status_t APQS_CFS_PkiHandleMessage(const uint8_t *msg, size_t msg_len, uint8_t *reply, size_t reply_cap,
                                        size_t *reply_len, uint32_t *op_tag);

/*
** Encode a pki.PkiStatus for operation op with the outcome status, into out
** (APQS_CFS_PKI_STATUS_BUFFER_SIZE bytes). This is how the app answers the
** ground now that the library does not: the library still owns the wire format,
** the app owns the decision to report and the packet that carries it.
*/
apqs_status_t APQS_CFS_PkiEncodeStatus(uint32_t op, apqs_status_t status, uint8_t *out, size_t out_cap,
                                       size_t *out_len);

/*
** The one PkiMessage oneof tag a caller needs to name for itself: renewal can
** also be started locally, by command, and the resulting status still has to say
** which operation it reports on. Every other op comes back from
** APQS_CFS_PkiHandleMessage() and needs no constant here. Tied to the schema by
** a _Static_assert in apqs_cfs_pki.c.
*/
#define APQS_CFS_PKI_OP_RENEW_CERT 2

// Session key management around the handshake.
apqs_status_t APQS_CFS_HandshakeSetSessionKey(void);
void          APQS_CFS_HandshakeResetKeys(bool reset_session_key);

/*
** Start certificate renewal: onboard keygen, then a MACed CSR encoded into
** csr_msg (APQS_CFS_CSR_BUFFER_SIZE bytes) for the caller to deliver.
*/
apqs_status_t APQS_CFS_CertRenewalStart(uint8_t *csr_msg, size_t csr_cap, size_t *csr_msg_len);

// Called after a successful handshake: the new key is proven, drop the rollback copy.
void APQS_CFS_CertRenewalConfirmNewKey(void);
