#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
** CryptoLib types appear in the signatures below, so consumers need them. They
** are included directly rather than through the core's apqs_sdls_types.h so the
** core's include directory stays off the applications' compile line: apps see
** this header and CryptoLib, nothing else of APQS.
*/
#include "crypto_structs.h"
#include "crypto_config_structs.h"
#include "sa_interface.h"
#include "key_interface.h"

/*
** cFS-facing APQS surface.
**
** This is the only APQS header cFS applications include. Everything here
** forwards to the framework-free core in apqs_lib/, which the apps never link
** against directly: ES resolves these symbols out of apqs_lib.so at load time,
** and because they are defined in a translation unit compiled straight into
** that module they are always present.
**
** Keeping the apps on this header rather than the core's apqs_api.h means the
** core API can be reshaped without touching ci_lab or to_lab, and gives type
** translation somewhere to live if the CryptoLib types below ever become
** opaque.
*/

// Success return shared by the forwarders that report CryptoLib status.
#define APQS_CFS_SUCCESS (0)

// Managed-parameter tables. The returned arrays are owned by the core.
TCGvcidManagedParameters_t *APQS_CFS_GetTcManagedParametersArray(void);
TMGvcidManagedParameters_t *APQS_CFS_GetTmManagedParametersArray(void);

int32_t APQS_CFS_GetTcManagedParametersForGvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                TCGvcidManagedParameters_t *managed_parameters_in,
                                                TCGvcidManagedParameters_t *managed_parameters_out);

int32_t APQS_CFS_GetTmManagedParametersForGvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                TMGvcidManagedParameters_t *managed_parameters_in,
                                                TMGvcidManagedParameters_t *managed_parameters_out);

// CI_LAB: uplink
int32_t APQS_CFS_GetSdlsEpReply(uint8_t *buffer, uint16_t *length);
int32_t APQS_CFS_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame);
int32_t APQS_CFS_ProcessClearTcEp(uint8_t *frame, int len);

/*
** Segmentation-header flag for the TC frame most recently handled by
** APQS_CFS_TC_ProcessSecurity. Replaces a direct extern on CryptoLib's
** tc_current_managed_parameters_struct, which reached past both this wrapper
** and the core and only linked by accident of what else got pulled in.
*/
bool APQS_CFS_TC_CurrentFrameHasSegmentHdr(void);

// TO_LAB: downlink
uint16_t APQS_CFS_CalcFecf(const uint8_t *ingest, int len_ingest);
int32_t  APQS_CFS_TM_ApplySecurity(uint8_t *pTfBuffer, uint16_t len_ingest);
SaInterface APQS_CFS_GetSaInterface(void);

/*
** Per-link SDLS gates. The TC and TM VCID spaces are independent, so each link
** checks its own list (CI_LAB -> TC, TO_LAB -> TM).
*/
bool APQS_CFS_TC_GvcidHasSdls(uint8_t tfvn, uint16_t scid, uint8_t vcid);
bool APQS_CFS_TM_GvcidHasSdls(uint8_t tfvn, uint16_t scid, uint8_t vcid);
