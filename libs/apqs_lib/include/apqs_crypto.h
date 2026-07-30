#pragma once

#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA3_384_TAG_LENGTH 48

typedef struct
{
    const uint8_t* data;
    size_t         len;
} hmac_part_t;

// HMAC-SHA3-384 over the concatenation of parts; tag_out must hold
// HMAC_SHA3_384_TAG_LENGTH bytes. Returns 0 on success, -1 on error.
int hmac_sha3_384(const uint8_t* key, size_t key_len, const hmac_part_t* parts, size_t num_parts, uint8_t* tag_out);
