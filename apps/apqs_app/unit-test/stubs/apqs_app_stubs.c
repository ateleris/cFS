/**
 * @file
 *
 * Auto-Generated stub implementations for functions defined in apqs_app header
 */

#include "apqs_app.h"
#include "utgenstub.h"


/*
 * ----------------------------------------------------
 * Generated stub function for APQS_AppInit()
 * ----------------------------------------------------
 */
int32 APQS_AppInit(void)
{
    UT_GenStub_SetupReturnBuffer(APQS_AppInit, int32);
    UT_GenStub_Execute(APQS_AppInit, Basic, NULL);

    return UT_GenStub_GetReturnValue(APQS_AppInit, int32);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_AppMain()
 * ----------------------------------------------------
 */
void APQS_AppMain(void)
{
    UT_GenStub_Execute(APQS_AppMain, Basic, NULL);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_ProcessCfEot()
 * ----------------------------------------------------
 */
void APQS_ProcessCfEot(CFE_SB_Buffer_t* SBBufPtr)
{
    UT_GenStub_AddParam(APQS_ProcessCfEot, CFE_SB_Buffer_t* , SBBufPtr);
    UT_GenStub_Execute(APQS_ProcessCfEot, Basic, NULL);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_ProcessCommandPacket()
 * ----------------------------------------------------
 */
void APQS_ProcessCommandPacket(CFE_SB_Buffer_t* SBBufPtr)
{
    UT_GenStub_AddParam(APQS_ProcessCommandPacket, CFE_SB_Buffer_t* , SBBufPtr);
    UT_GenStub_Execute(APQS_ProcessCommandPacket, Basic, NULL); 
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_ProcessGroundCommand()
 * ----------------------------------------------------
 */
void APQS_ProcessGroundCommand(CFE_SB_Buffer_t* SBBufPtr)
{
    UT_GenStub_AddParam(APQS_ProcessGroundCommand, CFE_SB_Buffer_t* , SBBufPtr);
    UT_GenStub_Execute(APQS_ProcessGroundCommand, Basic, NULL);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_SendPerfHk()
 * ----------------------------------------------------
 */
void APQS_SendPerfHk(void)
{
    UT_GenStub_Execute(APQS_SendPerfHk, Basic, NULL);
}

/*
 * ----------------------------------------------------
 * Generated stub function for APQS_UpdatePerfData()
 * ----------------------------------------------------
 */
void APQS_UpdatePerfData(void)
{
    UT_GenStub_Execute(APQS_UpdatePerfData, Basic, NULL);
}
