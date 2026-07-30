#include "apqs_app_spki.h"
#include <string.h>

/*
** ML-KEM-768 AlgorithmIdentifier DER:
**   SEQUENCE {
**     OID 2.16.840.1.101.3.4.4.2
**   }
*/
static const uint8_t ML_KEM_768_ALGID[] = {
    0x30, // Tag for sequence
    0x0B, // length

    0x06, // Tag for OID 
    0x09, // length
    0x60, // 2.16
    0x86, 0x48, // 840
    0x01, // 1
    0x65, // 101
    0x03, // 3
    0x04, // 4
    0x04, // 4
    0x02  // 2
};

/*
** X25519 AlgorithmIdentifier DER (no parameters per RFC 8410):
**   SEQUENCE {
**     OID 1.3.101.110
**   }
*/
static const uint8_t X25519_ALGID[] = {
    0x30, // Tag for sequence
    0x05, // length

    0x06, // Tag for OID
    0x03, // length
    0x2B, // 1.3
    0x65, // 101
    0x6E  // 110
};

/*
** X25519 SPKI full header (outer SEQUENCE + AlgId + BIT STRING tag/length/padding):
**   30 2A           -- SEQUENCE, length 42
**   30 05           -- AlgorithmIdentifier SEQUENCE, length 5
**   06 03 2B 65 6E  -- OID 1.3.101.110
**   03 21           -- BIT STRING, length 33
**   00              -- 0 unused bits
** Followed by 32 bytes of raw key → total 44 bytes.
*/
static const uint8_t X25519_SPKI_HEADER[] = {
    0x30, 0x2A,
    0x30, 0x05,
    0x06, 0x03, 0x2B, 0x65, 0x6E,
    0x03, 0x21,
    0x00
};

/*
** Parse a DER length field at *p, advance *p, write result to *out_len.
** Supports short form (< 0x80) and long form with 1 or 2 length bytes.
** Returns 0 on success, -1 on parse error.
*/
static int der_parse_length(const uint8_t** p, const uint8_t* end, size_t* out_len)
{
    if (*p >= end)
        return -1;

    uint8_t first = **p;
    (*p)++;

    if (first < 0x80)
    {
        *out_len = first;
        return 0;
    }
    else if (first == 0x81)
    {
        if (*p + 1 > end)
            return -1;
        *out_len = (*p)[0];
        (*p)++;
        return 0;
    }
    else if (first == 0x82)
    {
        if (*p + 2 > end)
            return -1;
        *out_len = ((size_t)(*p)[0] << 8) | (*p)[1];
        (*p) += 2;
        return 0;
    }

    // Lengths requiring >2 bytes are not expected for these key types
    return -1;
}

int spki_decode_ml_kem_768(const uint8_t* spki, size_t spki_len, uint8_t* raw_pk, size_t raw_pk_max)
{
    if (!spki || !raw_pk || raw_pk_max < ML_KEM_768_RAW_LEN)
        return -1;
    if (spki_len < ML_KEM_768_SPKI_SIZE)
        return -1;

    const uint8_t* p = spki;
    const uint8_t* end = spki + spki_len;

    /* Outer SEQUENCE tag */
    if (*p != 0x30)
        return -1;
    p++;

    size_t seq_len;
    if (der_parse_length(&p, end, &seq_len) != 0)
        return -1;
    if (p + seq_len > end)
        return -1;

    /* AlgorithmIdentifier — must match the hardcoded ML-KEM-768 template */
    if ((size_t)(end - p) < ML_KEM_768_ALGID_LEN)
        return -1;
    if (memcmp(p, ML_KEM_768_ALGID, ML_KEM_768_ALGID_LEN) != 0)
        return -1;
    p += ML_KEM_768_ALGID_LEN;

    /* BIT STRING tag */
    if (p >= end || *p != 0x03)
        return -1;
    p++;

    size_t bs_len;
    if (der_parse_length(&p, end, &bs_len) != 0)
        return -1;

    /* BIT STRING length must be exactly raw key length + 1 padding byte */
    if (bs_len != (ML_KEM_768_RAW_LEN + 1))
        return -1;

    /* Padding bits must be zero */
    if (p >= end || *p != 0x00)
        return -1;
    p++;

    if ((size_t)(end - p) < ML_KEM_768_RAW_LEN)
        return -1;

    memcpy(raw_pk, p, ML_KEM_768_RAW_LEN);
    return 0;
}

int spki_decode_x25519(const uint8_t* spki, size_t spki_len, uint8_t* raw_pk, size_t raw_pk_max)
{
    if (!spki || !raw_pk || raw_pk_max < X25519_RAW_LEN)
        return -1;
    if (spki_len < X25519_SPKI_SIZE)
        return -1;

    const uint8_t* p = spki;
    const uint8_t* end = spki + spki_len;

    // Outer SEQUENCE tag
    if (*p != 0x30)
        return -1;
    p++;

    size_t seq_len;
    if (der_parse_length(&p, end, &seq_len) != 0)
        return -1;
    if (p + seq_len > end)
        return -1;

    // AlgorithmIdentifier — must match the hardcoded X25519 template
    if ((size_t)(end - p) < X25519_ALGID_LEN)
        return -1;
    if (memcmp(p, X25519_ALGID, X25519_ALGID_LEN) != 0)
        return -1;
    p += X25519_ALGID_LEN;

    // BIT STRING tag
    if (p >= end || *p != 0x03)
        return -1;
    p++;

    size_t bs_len;
    if (der_parse_length(&p, end, &bs_len) != 0)
        return -1;

    // BIT STRING length must be exactly raw key length + 1 padding byte
    if (bs_len != (X25519_RAW_LEN + 1))
        return -1;

    // Padding bits must be zero
    if (p >= end || *p != 0x00)
        return -1;
    p++;

    if ((size_t)(end - p) < X25519_RAW_LEN)
        return -1;

    memcpy(raw_pk, p, X25519_RAW_LEN);
    return 0;
}

int spki_encode_x25519(const uint8_t* raw_pk, size_t raw_pk_len, uint8_t* spki_out, size_t spki_out_max)
{
    if (!raw_pk || raw_pk_len != X25519_RAW_LEN)
        return -1;
    if (!spki_out || spki_out_max < X25519_SPKI_SIZE)
        return -1;

    memcpy(spki_out, X25519_SPKI_HEADER, X25519_SPKI_HEADER_LEN);
    memcpy(spki_out + X25519_SPKI_HEADER_LEN, raw_pk, X25519_RAW_LEN);
    return X25519_SPKI_SIZE;
}
