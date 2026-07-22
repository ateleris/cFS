#include "apsq_api.h"

#include <assert.h>
#include <string.h>
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"

const char *apqs_lib_version()
{
    return "1.0"; // TODO get the correct version according to latest review
}


// CRYPTOLIB HELPERS FROM CI_LAB
static void CI_LAB_Crypto_ClearSAs(void)
{
    SecurityAssociation_t *sa = NULL;

    for (uint16 spi = 0; spi < NUM_SA; spi++)
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

    CFE_EVS_SendEvent(CI_LAB_INIT_INF_EID, CFE_EVS_EventType_INFORMATION, "CI Lab Crypto Lib Initialized.");
}

