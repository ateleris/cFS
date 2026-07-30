#include "apqs_api.h"

#include "apqs_event.h"

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

static void CI_LAB_Crypto_PopulateGVCIDs(void)
{
    // with segment headers
    TCGvcidManagedParameters_t tc_gvcid_params = {
        0, // tfvn
        3, // scid
        0, // vcid
        TC_HAS_FECF,
        TC_HAS_SEGMENT_HDRS,
        1024, // max frame size
        1     // set flag
    };
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc_gvcid_params);
    tc_gvcid_params.vcid = 1;
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc_gvcid_params);
    tc_gvcid_params.vcid = 2;
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc_gvcid_params);
    tc_gvcid_params.vcid = 3;
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc_gvcid_params);

    TMGvcidManagedParameters_t tm_gvcid_params = {
        0, // tfvn
        4, // scid
        0, // vcid
        TM_HAS_FECF,
        1786, // max frame size
        TM_HAS_OCF,
        1 // set flag
    };
    Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm_gvcid_params);
    tm_gvcid_params.vcid = 1;
    Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm_gvcid_params);
    tm_gvcid_params.vcid = 2;
    Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm_gvcid_params);
    tm_gvcid_params.vcid = 3;
    Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm_gvcid_params);
}

static void CI_LAB_Crypto_PopulateSAs(void)
{
    SecurityAssociation_t *sa = NULL;
    // check crypto_structs.h for SecurityAssociation_t definition

    // TC SDLS EP
    sa_if->sa_get_from_spi(0, &sa);
    sa->spi             = 0;
    sa->sa_state        = SA_OPERATIONAL;
    sa->est             = 1;
    sa->ekid            = 1;
    sa->ast             = 1;
    sa->akid            = 1;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = 3;
    sa->gvcid_blk.vcid  = 0;
    sa->gvcid_blk.mapid = 0;
    sa->shivf_len       = 12;
    sa->shsnf_len       = 0;
    sa->shplf_len       = 0;
    sa->stmacf_len      = 16;
    sa->ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa->ecs_len         = 1;
    sa->iv_len          = 12;
    sa->acs             = 0;
    sa->acs_len         = 0;
    sa->abm_len         = 20;
    memset(sa->abm, 0xFF, sa->abm_len);
    sa->arsn_len  = 0;
    sa->arsnw_len = 1;
    sa->arsnw     = 16;

    // TC CLEAR MODE
    sa_if->sa_get_from_spi(1, &sa);
    sa->spi             = 1;
    sa->sa_state        = SA_OPERATIONAL;
    sa->est             = 0;
    sa->ekid            = 0;
    sa->ast             = 0;
    sa->akid            = 0;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = 3;
    sa->gvcid_blk.vcid  = 1;
    sa->gvcid_blk.mapid = 0;
    sa->shivf_len       = 0;
    sa->shsnf_len       = 0;
    sa->shplf_len       = 0;
    sa->stmacf_len      = 0;
    sa->ecs             = 0;
    sa->ecs_len         = 0;
    sa->iv_len          = 0;
    sa->acs             = 0;
    sa->acs_len         = 0;
    sa->abm_len         = 0;
    sa->arsn_len        = 0;
    sa->arsnw_len       = 0;
    sa->arsnw           = 0;

    // TM SDLS EP
    sa_if->sa_get_from_spi(10, &sa);
    sa->spi             = 10;
    sa->sa_state        = SA_OPERATIONAL;
    sa->est             = 1;
    sa->ekid            = 2;
    sa->ast             = 1;
    sa->akid            = 2;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = 4;
    sa->gvcid_blk.vcid  = 0;
    sa->gvcid_blk.mapid = 0;
    sa->shivf_len       = 12;
    sa->shsnf_len       = 0;
    sa->shplf_len       = 0;
    sa->stmacf_len      = 16;
    sa->ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa->ecs_len         = 1;
    sa->iv_len          = 12;
    sa->acs             = 0;
    sa->acs_len         = 0;
    sa->abm_len         = 20;
    memset(sa->abm, 0xFF, sa->abm_len);
    sa->arsn_len  = 0;
    sa->arsnw_len = 1;
    sa->arsnw     = 16;

    // TM CLEAR MODE
    sa_if->sa_get_from_spi(11, &sa);
    sa->spi             = 11;
    sa->sa_state        = SA_OPERATIONAL;
    sa->est             = 0;
    sa->ekid            = 0;
    sa->ast             = 0;
    sa->akid            = 0;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = 4;
    sa->gvcid_blk.vcid  = 1;
    sa->gvcid_blk.mapid = 0;
    sa->shivf_len       = 0;
    sa->shsnf_len       = 0;
    sa->shplf_len       = 0;
    sa->stmacf_len      = 0;
    sa->ecs             = 0;
    sa->ecs_len         = 0;
    sa->iv_len          = 0;
    sa->acs             = 0;
    sa->acs_len         = 0;
    sa->abm_len         = 0;
    sa->arsn_len        = 0;
    sa->arsnw_len       = 0;
    sa->arsnw           = 0;
}

static int32_t CI_LAB_CryptoLib_Init(void)
{
    // Setup & Initialize CryptoLib (v1.5.0 split config: global + per-protocol)
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_NO_PUS_HDR, TC_IGNORE_ANTI_REPLAY_FALSE,
                     TC_IGNORE_SA_STATE_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_TM(CRYPTO_TM_CREATE_FECF_TRUE, TM_IGNORE_ANTI_REPLAY_FALSE, TM_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Must run before Crypto_Init: it rejects an empty managed-parameter table
    // (CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE)
    CI_LAB_Crypto_PopulateGVCIDs();

    int32_t status = Crypto_Init();
    assert(CRYPTO_LIB_SUCCESS == status);

    // Override CryptoLib's default SAs with the e2eqss configuration
    CI_LAB_Crypto_ClearSAs();
    CI_LAB_Crypto_PopulateSAs();

    // Under cFS this runs during library init, before any app registers with
    // EVS, so the event may be dropped by the event service itself
    apqs_event_send(APQS_LIB_INIT_INF_EID, APQS_EVENT_INFO, "APQS: CryptoLib initialized");

    return status;
}

/* Header Impl */
const char* apqs_lib_version(void)
{
    return "1.0"; // TODO get the correct version according to latest review
}

int32_t apqs_lib_init(void)
{
    // Crypto_SC_Init() is intentionally NOT called: since CryptoLib v1.5.0 it is
    // a NOS3 demo init that registers its own GVCIDs and demo SAs/keys, which
    // would conflict with the e2eqss configuration below.
    return CI_LAB_CryptoLib_Init();
}

/* REROUTE OF CRYPTOLIB CALLS */

// SHARED HELPER
TCGvcidManagedParameters_t* apqs_get_tc_gvcid_managed_parameters_array(void)
{
    return tc_gvcid_managed_parameters_array;
}

int apqs_get_tc_gvcid_counter(void)
{
    return tc_gvcid_counter;
}

TMGvcidManagedParameters_t* apqs_get_tm_gvcid_managed_parameters_array(void)
{
    return tm_gvcid_managed_parameters_array;
}

int apqs_get_tm_gvcid_counter(void)
{
    return tm_gvcid_counter;
}

// CI_LAB
int32_t apqs_Get_TC_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
    TCGvcidManagedParameters_t* managed_parameters_in,
    TCGvcidManagedParameters_t* managed_parameters_out)
{
    return Crypto_Get_TC_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, managed_parameters_in, managed_parameters_out);
}

// TO_LAB
int32_t apqs_Get_TM_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
    TMGvcidManagedParameters_t* managed_parameters_in,
    TMGvcidManagedParameters_t* managed_parameters_out)
{
    return Crypto_Get_TM_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, managed_parameters_in, managed_parameters_out);
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
} SdlsGvcid_t;

static const SdlsGvcid_t SDLS_TC_GVCIDS[] = {
    {0xFF, 0xFFFF, 0xFF}, // sentinel - not a real GVCID
    {0, 3, 0},            // SDLS EP commands (SPI 0)
    {0, 3, 1},            // TC clear mode (SPI 1)
    {0, 3, 2},            // TC post-handshake (SPI 2, EP-created)
};

static const SdlsGvcid_t SDLS_TM_GVCIDS[] = {
    {0xFF, 0xFFFF, 0xFF}, // sentinel - not a real GVCID
    {0, 4, 0},            // SDLS EP responses (SPI 10)
    {0, 4, 1},            // TM clear mode (SPI 11)
    {0, 4, 2},            // TM post-handshake (SPI 12, EP-created)
};

static bool Gvcid_In_List(const SdlsGvcid_t *list, size_t n, uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    for (size_t i = 0; i < n; i++)
    {
        if (list[i].tfvn == tfvn && list[i].scid == scid && list[i].vcid == vcid)
        {
            return true;
        }
    }
    return false;
}

bool TC_Gvcid_Has_Sdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    return Gvcid_In_List(SDLS_TC_GVCIDS, sizeof(SDLS_TC_GVCIDS) / sizeof(SDLS_TC_GVCIDS[0]), tfvn, scid, vcid);
}

bool TM_Gvcid_Has_Sdls(uint8_t tfvn, uint16_t scid, uint8_t vcid)
{
    return Gvcid_In_List(SDLS_TM_GVCIDS, sizeof(SDLS_TM_GVCIDS) / sizeof(SDLS_TM_GVCIDS[0]), tfvn, scid, vcid);
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