/**
 * @file
 * E2EQSS per-GVCID SDLS gate (mission configuration).
 *
 * Single source of truth for which GVCIDs (tfvn / scid / vcid) carry an SDLS
 * security header and must therefore be routed through CryptoLib. Any GVCID that
 * is NOT listed here is treated as a "clear" (plain CCSDS) channel: CI_LAB and
 * TO_LAB bypass CryptoLib for it.
 *
 * In CCSDS SDLS the presence of the security header is a static per-GVCID /
 * mission property (not per-frame), so this belongs in the mission defs.
 *
 * The lookup key is (tfvn, scid, vcid) only: the ground applies SDLS per
 * (scid, vcid) regardless of TC/TM direction, so the TC and TM channels on the
 * same VCID share one entry.
 *
 * The handshake bootstrap channel (tfvn=0, scid=3, vcid=0) is intentionally
 * absent => clear. Add data-channel GVCIDs to the table below when SDLS is
 * enabled for them.
 */
#ifndef E2EQSS_SDLS_CFG_H
#define E2EQSS_SDLS_CFG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct
{
    uint8_t  tfvn;
    uint16_t scid;
    uint8_t  vcid;
} E2EQSS_SdlsGvcid_t;

/*
 * GVCIDs that ARE SDLS-protected. The first entry is an inert sentinel
 * ({0xFF,0xFFFF,0xFF} can never match a real frame: tfvn<=3, scid<=0x3FF,
 * vcid<=0x3F). It keeps the array non-empty (avoids a zero-length-array
 * extension); insert real SDLS GVCIDs alongside it.
 */
static const E2EQSS_SdlsGvcid_t E2EQSS_SDLS_GVCIDS[] = {
    {0xFF, 0xFFFF, 0xFF}, /* sentinel - not a real GVCID */
    /* { tfvn, scid, vcid },  <-- add SDLS-protected channels here */
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

#endif /* E2EQSS_SDLS_CFG_H */
