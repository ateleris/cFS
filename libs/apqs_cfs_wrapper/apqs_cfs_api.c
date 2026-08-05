#include "apqs_cfs_api.h"

#include <apqs/api.h>

/*
** Forwarders onto the framework-free core. Deliberately thin: no logic lives
** here, only the name translation that keeps the core's API free to change.
**
** These definitions are also what makes the module self-contained. Every
** symbol ci_lab and to_lab resolve at load time is defined in this file, so
** the linker has no archive member to prune and the wrapper does not need
** whole-archive linkage against libapqs.a.
*/

TCGvcidManagedParameters_t *APQS_CFS_GetTcManagedParametersArray(void)
{
    return apqs_get_tc_gvcid_managed_parameters_array();
}

TMGvcidManagedParameters_t *APQS_CFS_GetTmManagedParametersArray(void)
{
    return apqs_get_tm_gvcid_managed_parameters_array();
}

int32_t APQS_CFS_GetTcManagedParametersForGvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                TCGvcidManagedParameters_t *managed_parameters_in,
                                                TCGvcidManagedParameters_t *managed_parameters_out)
{
    return apqs_Get_TC_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, managed_parameters_in, managed_parameters_out);
}

int32_t APQS_CFS_GetTmManagedParametersForGvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                TMGvcidManagedParameters_t *managed_parameters_in,
                                                TMGvcidManagedParameters_t *managed_parameters_out)
{
    return apqs_Get_TM_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, managed_parameters_in, managed_parameters_out);
}

int32_t APQS_CFS_GetSdlsEpReply(uint8_t *buffer, uint16_t *length)
{
    return apqs_Get_Sdls_Ep_Reply(buffer, length);
}

int32_t APQS_CFS_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame)
{
    return apqs_TC_ProcessSecurity(ingest, len_ingest, tc_sdls_processed_frame);
}

int32_t APQS_CFS_ProcessClearTcEp(uint8_t *frame, int len)
{
    return apqs_Process_Clear_TC_EP(frame, len);
}

bool APQS_CFS_TC_CurrentFrameHasSegmentHdr(void)
{
    return apqs_tc_current_frame_has_segment_hdr();
}

uint16_t APQS_CFS_CalcFecf(const uint8_t *ingest, int len_ingest)
{
    return apqs_Calc_FECF(ingest, len_ingest);
}

int32_t APQS_CFS_TM_ApplySecurity(uint8_t *pTfBuffer, uint16_t len_ingest)
{
    return apqs_TM_ApplySecurity(pTfBuffer, len_ingest);
}

SaInterface APQS_CFS_GetSaInterface(void)
{
    return apqs_get_sa_if();
}

bool APQS_CFS_TC_GvcidHasSdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    return apqs_TC_Gvcid_Has_Sdls(tfvn, scid, vcid);
}

bool APQS_CFS_TM_GvcidHasSdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    return apqs_TM_Gvcid_Has_Sdls(tfvn, scid, vcid);
}
