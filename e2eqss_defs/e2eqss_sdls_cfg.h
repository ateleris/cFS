#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct
{
    uint8_t  tfvn;
    uint16_t scid;
    uint8_t  vcid;
} E2EQSS_SdlsGvcid_t;

static const E2EQSS_SdlsGvcid_t E2EQSS_SDLS_GVCIDS[] = {
    {0xFF, 0xFFFF, 0xFF}, // sentinel - not a real GVCID
    {0, 0x0003, 2}, // tfvn, scid, vcid
};

/** Return true if the given GVCID carries an SDLS security header. */
static inline bool E2EQSS_Gvcid_Has_Sdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    size_t n = sizeof(E2EQSS_SDLS_GVCIDS) / sizeof(E2EQSS_SDLS_GVCIDS[0]);
    for (size_t i = 0; i < n; i++)
    {
        if (E2EQSS_SDLS_GVCIDS[i].tfvn == tfvn && E2EQSS_SDLS_GVCIDS[i].scid == scid &&
            E2EQSS_SDLS_GVCIDS[i].vcid == vcid)
        {
            return true;
        }
    }
    return false;
}
