#pragma once

#include "cfe.h"
#include "cfe_error.h"
#include "cfe_evs.h"
#include "cfe_sb.h"
#include "cfe_es.h"

#include "apqs_app_msgids.h"
#include "apqs_app_msg.h"

#define APQS_PIPE_DEPTH 32

typedef struct
{
    APQS_TM_Mirror_t MirrorTlm;
    APQS_TM_LongMirror_t LongMirrorTlm;
    APQS_TM_HS_Response_t HSResponseTlm;
    APQS_TM_PkiStatus_t PkiStatusTlm;
    APQS_TM_PerfHk_t PerfHkTlm;

    // Periodic performance HK enable state (driven by ground enable/disable TCs)
    bool HkEnabled;

    // Run Status variable used in the main processing loop
    uint32 RunStatus;
    CFE_SB_PipeId_t    CommandPipe;
    char     PipeName[16];
    uint16   PipeDepth;
} APQS_AppData_t;

void  APQS_AppMain(void);
int32 APQS_AppInit(void);
void  APQS_ProcessCommandPacket(CFE_SB_Buffer_t* SBBufPtr);
void  APQS_ProcessGroundCommand(CFE_SB_Buffer_t* SBBufPtr);
void  APQS_ProcessCfEot(CFE_SB_Buffer_t* SBBufPtr);
void  APQS_UpdatePerfData(void);
void  APQS_SendPerfHk(void);
