#include "apqs_api.h"

#include <assert.h>
#include <string.h>

#include "crypto.h"
#include "crypto_error.h"


// CRYPTOLIB HELPERS FROM CI_LAB
static void CI_LAB_Crypto_ClearSAs(void)
{
    SecurityAssociation_t *sa = NULL;

    for (uint16_t spi = 0; spi < NUM_SA; spi++)
    {
        sa_if->sa_get_from_spi(spi, &sa);
        if (sa != NULL)
        {
            memset(sa, 0, sizeof(*sa));
            sa->spi      = spi;
            sa->sa_state = SA_NONE;
        }
    }
}

static void CI_LAB_Crypto_PopulateSAs(void)
{
    SecurityAssociation_t *sa = NULL;

    // SA 0 - TC CLEAR MODE (Operational)
    sa_if->sa_get_from_spi(0, &sa);
    sa->spi             = 0;
    sa->sa_state        = SA_OPERATIONAL;
    sa->est             = 0;
    sa->ast             = 0;
    sa->shivf_len       = 12;
    sa->iv_len          = 12;
    sa->shsnf_len       = 0;
    sa->arsnw           = 5;
    sa->arsnw_len       = 1;
    sa->arsn_len        = 0;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = SCID & 0x3FF;
    sa->gvcid_blk.vcid  = 0;
    sa->gvcid_blk.mapid = 0;
}

static void CI_LAB_CryptoLib_Init(void)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // with segment headers
    GvcidManagedParameters_t seg_tc_params = {
        0, // tfvn
        3, // scid
        0, // vcid
        TC_HAS_FECF,
        AOS_FHEC_NA,
        AOS_IZ_NA,
        0, // aos_iz_len
        TC_HAS_SEGMENT_HDRS,
        1024, // max frame size
        TC_OCF_NA,
        1 // set flag
    };
    Crypto_Config_Add_Gvcid_Managed_Parameters(seg_tc_params);
    seg_tc_params.vcid = 2;
    Crypto_Config_Add_Gvcid_Managed_Parameters(seg_tc_params);

    GvcidManagedParameters_t seg_tm_params = {
        0, // tfvn
        3, // scid
        0, // vcid
        TM_HAS_FECF,
        AOS_FHEC_NA,
        AOS_IZ_NA,
        0, // aos_iz_len
        TM_SEGMENT_HDRS_NA,
        1786, // max frame size
        TM_HAS_OCF,
        1 // set flag
    };
    Crypto_Config_Add_Gvcid_Managed_Parameters(seg_tm_params);
    seg_tm_params.vcid = 2;
    Crypto_Config_Add_Gvcid_Managed_Parameters(seg_tm_params);

    int status = Crypto_Init();
    assert(CRYPTO_LIB_SUCCESS == status);

    // Override CryptoLib's default SAs with the e2eqss configuration
    CI_LAB_Crypto_ClearSAs();
    CI_LAB_Crypto_PopulateSAs();

    // needs CFS header - TODO custom logger
    //CFE_EVS_SendEvent(CI_LAB_INIT_INF_EID, CFE_EVS_EventType_INFORMATION, "CI Lab Crypto Lib Initialized.");
}

/* Header Impl */
const char* apqs_lib_version(void)
{
    return "1.0"; // TODO get the correct version according to latest review
}

int32_t apqs_lib_init(void) 
{
    int32_t initRetVal = Crypto_SC_Init();
    CI_LAB_CryptoLib_Init();

    return initRetVal;
}

/* REROUTE OF CRYPTOLIB CALLS */

// SHARED HELPER
GvcidManagedParameters_t* apqs_get_gvcid_managed_parameters_array(void)
{
    return gvcid_managed_parameters_array;
}

int apqs_get_gvcid_counter(void)
{
    return gvcid_counter;
}

// CI_LAB
int32_t apqs_Get_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t frame_type,
    GvcidManagedParameters_t* managed_parameters_in,
    GvcidManagedParameters_t* managed_parameters_out)
{
    return Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, frame_type, managed_parameters_in, managed_parameters_out);
}

int32_t apqs_Get_Sdls_Ep_Reply(uint8_t* buffer, uint16_t* length)
{
    return Crypto_Get_Sdls_Ep_Reply(buffer, length);
}

int32_t apqs_TC_ProcessSecurity(uint8_t* ingest, int* len_ingest, TC_t* tc_sdls_processed_frame) 
{
    return Crypto_TC_ProcessSecurity(ingest, len_ingest, tc_sdls_processed_frame);
}

int32_t apqs_Process_Clear_TC_EP(uint8_t *frame, int len)
{
    return Crypto_Process_Clear_TC_EP(frame, len);
}

typedef struct
{
    uint8_t  tfvn;
    uint16_t scid;
    uint8_t  vcid;
} E2EQSS_SdlsGvcid_t;

static const E2EQSS_SdlsGvcid_t E2EQSS_SDLS_GVCIDS[] = {
    {0xFF, 0xFFFF, 0xFF}, // sentinel - not a real GVCID
    {0, 0x0003, 2},       // tfvn, scid, vcid
};

bool E2EQSS_Gvcid_Has_Sdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
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

// TO_LAB
uint16_t apqs_Calc_FECF(const uint8_t* ingest, int len_ingest) 
{
    return Crypto_Calc_FECF(ingest, len_ingest);
}

int32_t apqs_TM_ApplySecurity(uint8_t* pTfBuffer, uint16_t len_ingest)
{
    return Crypto_TM_ApplySecurity(pTfBuffer, len_ingest);
}

SaInterfaceStruct* apqs_get_sa_if(void)
{
    return sa_if;
}

// APQS App
KeyInterface apqs_get_key_interface_internal(void)
{
    return get_key_interface_internal();
}