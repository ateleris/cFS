#pragma once

#include <stdint.h>
#include <stddef.h>

/*
** SPKI (SubjectPublicKeyInfo per RFC 5280 §4.1.2.7) encode/decode
** ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2, no params — pyasn1 omits NULL):
**     30 0B 06 09 60 86 48 01 65 03 04 04 02
** X25519 (OID 1.3.101.110, no params per RFC 8410):
**     30 05 06 03 2B 65 6E
*/

#define ML_KEM_768_RAW_LEN (1184)
#define ML_KEM_768_ALGID_LEN (13)
#define ML_KEM_768_SPKI_SIZE (1206)

#define X25519_RAW_LEN (32)
#define X25519_ALGID_LEN (7)
#define X25519_SPKI_HEADER_LEN (2 + X25519_ALGID_LEN + 3)
#define X25519_SPKI_SIZE (X25519_SPKI_HEADER_LEN + X25519_RAW_LEN)

int spki_decode_ml_kem_768(const uint8_t* spki, size_t spki_len, uint8_t* raw_pk, size_t raw_pk_max);
int spki_decode_x25519(const uint8_t* spki, size_t spki_len, uint8_t* raw_pk, size_t raw_pk_max);
int spki_encode_x25519(const uint8_t* raw_pk, size_t raw_pk_len, uint8_t* spki_out, size_t spki_out_max);
