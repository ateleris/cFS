#pragma once

#include <pki.pb.h>

// "Certificate Exchange" scenario (e2eqss_master_pki diagram): receive the
// MCS certificate with its stapled OCSP response, verify chain + OCSP status,
// store it, and return the SAT certificate.

// Verify (Ver_Cert_PKCA + OCSP GOOD) and store the MCS certificate, then
// reply with the SAT certificate. Any verification failure terminates the
// exchange with a failure PkiStatus and leaves the store untouched.
void cert_exchange_handle(pki_CertExchange* cert_exchange);

// Standalone reply with the active SAT certificate (PKI_CERT_SAT.pbin).
void cert_exchange_handle_cert_request(pki_CertSatRequest* request);

// "Renew certificate for SAT" scenario (e2eqss_master_pki diagram).
//
// Async, reboot-safe flow:
//   IDLE --trigger--> keygen, seed persisted, CSR+MAC sent --> CSR_PENDING
//   CSR_PENDING --valid certificate received--> atomic swap --> IDLE
// A renewed trigger while CSR_PENDING regenerates (new seed, new CSR).
// The previous key/cert is kept as /cf/pki/sat_old.pem until the next
// SDLS handshake completes with the new certificate.

// Trigger: onboard ML-KEM-768 keygen, build unsigned CSR (RFC 2986
// CertificationRequestInfo), MAC with PSS_sat, send PKI_CSR.pbin to ground.
void cert_renewal_start(void);

// Install the CA-signed certificate answering the pending CSR.
void cert_renewal_handle_new_certificate(pki_NewCertificate *new_cert);

// Called after a successful SDLS handshake: the new key is proven to work,
// the rollback copy (sat_old.pem) can be discarded.
void cert_renewal_confirm_new_key(void);
