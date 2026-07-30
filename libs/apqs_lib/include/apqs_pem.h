#pragma once

#include <stdint.h>
#include <stddef.h>

#include <openssl/types.h>

#define ML_KEM_768_PK_LENGTH 1184
#define ML_KEM_768_SK_LENGTH 2400
#define ML_KEM_768_SEED_LENGTH 64
#define APQS_MAX_IDENTITY_LENGTH 1024

// SAT (own) key material — all point to the same file when using a combined PEM
#define APQS_SAT_SECRET_PATH "keys/sat.pem" // PRIVATE KEY block
#define APQS_SAT_PUBLIC_PATH "keys/sat.pem" // CERTIFICATE block
#define APQS_SAT_CA_PATH     "keys/sat.pem" // CA CERTIFICATE block

// MCS (remote) key material — all point to the same file when using a combined PEM
#define APQS_MCS_PUBLIC_PATH "keys/mcs.pem" // CERTIFICATE block (public key + identity)
#define APQS_MCS_CA_PATH     "keys/mcs.pem" // CA CERTIFICATE block

int pem_load_sat_secret_key(const char* pem_path, uint8_t* pk_out, uint8_t* sk_out);
int pem_load_public_key(const char* pem_path, uint8_t* pk_out);
int pem_load_identity(const char* pem_path, uint8_t* identity_out, uint32_t* identity_len);

// caller owns the returned X509 (X509_free)
X509* pem_load_cert_x509(const char* pem_path);
X509* pem_load_ca_cert_x509(const char* pem_path);

// Crypto.Ver_Cert_PKCA: issuer DN + signature against CA (hard fail), validity period (warn only)
int pem_verify_cert_against_ca_x509(X509* cert, X509* ca_cert);
int pem_verify_cert_against_ca(const char* cert_path, const char* ca_path);

int ocsp_verify_response_x509(const uint8_t* ocsp_der, size_t ocsp_len, X509* entity_cert, X509* ca_cert);
int ocsp_verify_response(const uint8_t *ocsp_der, size_t ocsp_len, const char *entity_cert_path, const char *ca_cert_path);
