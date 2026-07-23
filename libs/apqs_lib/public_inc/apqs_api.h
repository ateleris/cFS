#pragma once

// TODO add that only this hdr is needed
//#include "apqs_sdls_types.h"

#include <stdint.h>
#include <stdbool.h>

#include "apqs_sdls_types.h"

#define CRYPTO_LIB_SUCCESS (0) // TODO do this better

const char* apqs_lib_version(void);
int32_t apqs_lib_init(void);

// SHARED HELPER
GvcidManagedParameters_t* apqs_get_gvcid_managed_parameters_array(void);
int apqs_get_gvcid_counter(void);


// CI_LAB
int32_t apqs_Get_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t frame_type,
    GvcidManagedParameters_t *managed_parameters_in, GvcidManagedParameters_t *managed_parameters_out);

int32_t apqs_Get_Sdls_Ep_Reply(uint8_t *buffer, uint16_t *length);

int32_t apqs_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame);

int32_t apqs_Process_Clear_TC_EP(uint8_t *frame, int len);


// TO_LAB
uint16_t apqs_Calc_FECF(const uint8_t *ingest, int len_ingest);

int32_t apqs_TM_ApplySecurity(uint8_t *pTfBuffer, uint16_t len_ingest);

SaInterface apqs_get_sa_if(void);

// APQS
KeyInterface apqs_get_key_interface_internal(void);

// E2EQSS SDLS CFG
bool E2EQSS_Gvcid_Has_Sdls(uint8_t tfvn, uint16_t scid, uint8_t vcid);
