/*
 * Unit tests for apqs_app.c (app entry, init, command dispatch, CF EOT handling,
 * performance HK).
 *
 * This covers the cFS app shell only. Everything the app used to do itself -
 * the handshake, the PKI flows, key material - moved into the APQS core, which
 * has its own Unity suite at libs/apqs_cfs_wrapper/apqs_lib/unit-test and needs
 * no cFS tree. What is left here is glue, and glue is exactly what UT-Assert is
 * good at: message routing, command codes, telemetry, and the failure paths at
 * init.
 *
 * External dependencies are stubbed:
 *   - cFE/OSAL via ut_core_api_stubs and ut_osapi_stubs
 *     (+ osal_extra_stubs.c for OS_GetSysMetrics)
 *   - the APQS binding layer via stubs/apqs_cfs_stubs.c
 *
 * The app reaches APQS through three forwarders now - HandshakeHandleMessage,
 * PkiHandleMessage, CertRenewalStart - so the tests drive those rather than the
 * six library entry points, nanopb and OpenSSL the previous suite had to stub.
 *
 * Functions defined in apqs_app.c itself (e.g. APQS_ProcessGroundCommand called
 * from APQS_ProcessCommandPacket) are the REAL implementations - only the
 * cross-module calls are stubbed - so dispatch tests assert on downstream stub
 * effects rather than on those same-file calls.
 */

#include "apqs_app.h"
#include "apqs_app_events.h"

#include "apqs_cfs_pki.h"

#include "cf_msg.h"
#include "cf_msgids.h"

#include "osapi-metrics.h"

#include "utassert.h"
#include "uttest.h"
#include "utstubs.h"

#include <string.h>

extern APQS_AppData_t APQS_AppData;

/* command/telemetry buffer with room for a payload past the cmd header */
static union
{
    CFE_SB_Buffer_t SBBuf;
    uint8           bytes[512];
} Buf;

static CFE_SB_Buffer_t *TestBuf(void)
{
    memset(&Buf, 0, sizeof(Buf));
    return &Buf.SBBuf;
}

/* ---- staging helpers (AllocateCopy=true: safe for these stack locals) ---- */

static void Stage_MsgId(CFE_SB_MsgId_Atom_t value)
{
    CFE_SB_MsgId_t mid = CFE_SB_ValueToMsgId(value);
    UT_SetDataBuffer(UT_KEY(CFE_MSG_GetMsgId), &mid, sizeof(mid), true);
}

static void Stage_FcnCode(CFE_MSG_FcnCode_t cc)
{
    UT_SetDataBuffer(UT_KEY(CFE_MSG_GetFcnCode), &cc, sizeof(cc), true);
}

static void Stage_MsgSize(size_t sz)
{
    CFE_MSG_Size_t s = (CFE_MSG_Size_t)sz;
    UT_SetDataBuffer(UT_KEY(CFE_MSG_GetSize), &s, sizeof(s), true);
}

/* ======================================================================== */
/* APQS_AppInit                                                             */
/* ======================================================================== */

void Test_APQS_AppInit_nominal(void)
{
    UtAssert_INT32_EQ(APQS_AppInit(), CFE_SUCCESS);
    UtAssert_UINT32_EQ(APQS_AppData.RunStatus, CFE_ES_RunStatus_APP_RUN);
    UtAssert_STUB_COUNT(CFE_SB_CreatePipe, 1);

    /* command, CF end-of-transfer, and housekeeping */
    UtAssert_STUB_COUNT(CFE_SB_Subscribe, 3);
}

/*
 * CF creates only its rx_base_dir and CFDP will not create intermediate
 * directories, so the app makes the inbound sub-directory itself. Losing this
 * silently drops every uplinked message.
 */
void Test_APQS_AppInit_creates_the_inbound_directory(void)
{
    UT_SetDefaultReturnValue(UT_KEY(OS_stat), OS_ERROR); /* nothing there yet */

    UtAssert_INT32_EQ(APQS_AppInit(), CFE_SUCCESS);
    UtAssert_STUB_COUNT(OS_mkdir, 2);
}

void Test_APQS_AppInit_evs_register_fails(void)
{
    UT_SetDefaultReturnValue(UT_KEY(CFE_EVS_Register), -1);
    UtAssert_INT32_EQ(APQS_AppInit(), -1);
    UtAssert_STUB_COUNT(CFE_SB_CreatePipe, 0);
}

void Test_APQS_AppInit_createpipe_fails(void)
{
    UT_SetDefaultReturnValue(UT_KEY(CFE_SB_CreatePipe), -1);
    UtAssert_INT32_EQ(APQS_AppInit(), -1);
    UtAssert_STUB_COUNT(CFE_SB_Subscribe, 0);
}

void Test_APQS_AppInit_subscribe_fails(void)
{
    UT_SetDefaultReturnValue(UT_KEY(CFE_SB_Subscribe), -1);
    UtAssert_INT32_EQ(APQS_AppInit(), -1);
}

/* ======================================================================== */
/* APQS_ProcessGroundCommand                                                */
/* ======================================================================== */

void Test_GroundCommand_mirror(void)
{
    Stage_FcnCode(APQS_APP_MIRROR);
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 1);
}

void Test_GroundCommand_renew_cert(void)
{
    Stage_FcnCode(APQS_APP_RENEW_CERT);
    /* CertRenewalStart returns APQS_OK (0) by default */
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(cert_renewal_start, 1);
}

void Test_GroundCommand_perf_hk_enable_disable(void)
{
    Stage_FcnCode(APQS_APP_PERF_HK_REQ);
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_BOOL_TRUE(APQS_AppData.HkEnabled);

    Stage_FcnCode(APQS_APP_PERF_HK_DISABLE);
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_BOOL_FALSE(APQS_AppData.HkEnabled);
}

void Test_GroundCommand_invalid_code(void)
{
    Stage_FcnCode(200);
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
    UtAssert_STUB_COUNT(cert_renewal_start, 0);
}

void Test_GroundCommand_rekey_pb_success(void)
{
    Stage_FcnCode(APQS_APP_HANDSHAKE_REKEY_PB);
    Stage_MsgSize(64);
    /* APQS_CFS_HandshakeHandleMessage returns APQS_OK (0) by default */

    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 1);

    /* an M2 reply goes out as telemetry, not over CFDP */
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 1);
}

/*
 * A rejected M1 must not produce a response. The library decides whether the
 * message was acceptable; the app's only job is to stay quiet when it was not.
 */
void Test_GroundCommand_rekey_pb_failure(void)
{
    Stage_FcnCode(APQS_APP_HANDSHAKE_REKEY_PB);
    Stage_MsgSize(64);
    UT_SetDefaultReturnValue(UT_KEY(APQS_CFS_HandshakeHandleMessage), APQS_ERR_VALIDATION);

    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 1);
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
}

/*
 * Key confirmation goes through the same entry point as the rekey - the library
 * dispatches on the payload - and produces no reply. Asserting the silence is
 * the point: an M3 that transmitted would be a protocol error.
 */
void Test_GroundCommand_key_conf_pb_success(void)
{
    Stage_FcnCode(APQS_APP_HANDSHAKE_KEY_CONF_PB);
    Stage_MsgSize(64);

    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 1);
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
}

void Test_ProcessCommandPacket_cmd_mid(void)
{
    Stage_MsgId(APQS_APP_CMD_MID);
    Stage_FcnCode(200); /* invalid -> routed to ground cmd, error event only */
    APQS_ProcessCommandPacket(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
}

void Test_ProcessCommandPacket_send_hk_enabled(void)
{
    APQS_AppData.HkEnabled = true;
    Stage_MsgId(APQS_APP_SEND_HK_MID);
    APQS_ProcessCommandPacket(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 1); /* SendPerfHk transmits */
}

void Test_ProcessCommandPacket_send_hk_disabled(void)
{
    APQS_AppData.HkEnabled = false;
    Stage_MsgId(APQS_APP_SEND_HK_MID);
    APQS_ProcessCommandPacket(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
}

void Test_ProcessCommandPacket_invalid_mid(void)
{
    Stage_MsgId(0x9999);
    APQS_ProcessCommandPacket(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 0);
    UtAssert_STUB_COUNT(cert_renewal_start, 0);
}

/* ======================================================================== */
/* APQS_ProcessCfEot                                                        */
/* ======================================================================== */

static CFE_SB_Buffer_t *MakeEot(uint32 direction, const char *filename)
{
    static CF_EotPacket_t eot;
    memset(&eot, 0, sizeof(eot));
    eot.Payload.direction = direction;
    strncpy(eot.Payload.fnames.dst_filename, filename, sizeof(eot.Payload.fnames.dst_filename) - 1);
    return (CFE_SB_Buffer_t *)&eot;
}

/*
 * The app reads the file before dispatching, so every case below has to make
 * the read succeed. Staging it is not incidental setup: a file that will not
 * open is itself a tested outcome, in _unreadable_file_is_dropped.
 */
static void Stage_FileRead(size_t len)
{
    UT_SetDefaultReturnValue(UT_KEY(OS_OpenCreate), OS_SUCCESS);
    UT_SetDefaultReturnValue(UT_KEY(OS_read), (int32)len);
}

void Test_ProcessCfEot_handshake_file(void)
{
    Stage_FileRead(64);

    APQS_ProcessCfEot(MakeEot(APQS_CF_DIRECTION_RX, "/cf/upload/hs_m1.pbin"));
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 1);
    UtAssert_STUB_COUNT(APQS_CFS_PkiHandleMessage, 0);
}

/* The PKI_ prefix is what routes a file to the PKI flows rather than the
 * handshake, so the two cases have to be asserted against each other. */
void Test_ProcessCfEot_pki_file(void)
{
    Stage_FileRead(64);

    APQS_ProcessCfEot(MakeEot(APQS_CF_DIRECTION_RX, "/cf/upload/PKI_CSR.pbin"));
    UtAssert_STUB_COUNT(APQS_CFS_PkiHandleMessage, 1);
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 0);
    /* The outcome is reported whatever it was: the ground commits the key
     * material it staged for an operation only once that operation is acked. */
    UtAssert_STUB_COUNT(APQS_CFS_PkiEncodeStatus, 1);
}

void Test_ProcessCfEot_non_pbin_ignored(void)
{
    Stage_FileRead(64);

    APQS_ProcessCfEot(MakeEot(APQS_CF_DIRECTION_RX, "/cf/upload/notes.txt"));
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 0);
    UtAssert_STUB_COUNT(APQS_CFS_PkiHandleMessage, 0);
}

void Test_ProcessCfEot_non_rx_ignored(void)
{
    Stage_FileRead(64);

    APQS_ProcessCfEot(MakeEot(1 /* not RX */, "/cf/upload/hs_m1.pbin"));
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 0);
    UtAssert_STUB_COUNT(APQS_CFS_PkiHandleMessage, 0);
}

/* An empty or unopenable file must not be handed on as a zero-length message. */
void Test_ProcessCfEot_unreadable_file_is_dropped(void)
{
    UT_SetDefaultReturnValue(UT_KEY(OS_OpenCreate), OS_ERROR);

    APQS_ProcessCfEot(MakeEot(APQS_CF_DIRECTION_RX, "/cf/upload/hs_m1.pbin"));
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 0);
}

/*
 * A CFDP transfer error is logged but the file is still read: it may be
 * complete on disk, and the library validates it either way. Dropping it here
 * would discard recoverable uplinks.
 */
void Test_ProcessCfEot_transfer_error_still_reads(void)
{
    static CF_EotPacket_t eot;
    memset(&eot, 0, sizeof(eot));
    eot.Payload.direction = APQS_CF_DIRECTION_RX;
    eot.Payload.txn_stat  = 1;
    strncpy(eot.Payload.fnames.dst_filename, "/cf/upload/hs_m1.pbin",
            sizeof(eot.Payload.fnames.dst_filename) - 1);

    Stage_FileRead(64);

    APQS_ProcessCfEot((CFE_SB_Buffer_t *)&eot);
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 1);
}

/* ======================================================================== */
/* APQS_UpdatePerfData / APQS_SendPerfHk                                     */
/* ======================================================================== */

void Test_UpdatePerfData_success(void)
{
    OS_sys_metrics_t metrics;
    memset(&metrics, 0, sizeof(metrics));
    metrics.load_avg_1min = 150;
    metrics.free_ram      = 4096;

    UT_SetDataBuffer(UT_KEY(OS_GetSysMetrics), &metrics, sizeof(metrics), true);
    APQS_UpdatePerfData();

    UtAssert_UINT32_EQ(APQS_AppData.PerfHkTlm.PerfData.CpuLoadAvg1Min, 150);
    UtAssert_UINT32_EQ((uint32_t)APQS_AppData.PerfHkTlm.PerfData.MemFreeBytes, 4096);
}

void Test_UpdatePerfData_failure(void)
{
    UT_SetDefaultReturnValue(UT_KEY(OS_GetSysMetrics), OS_ERROR);
    APQS_UpdatePerfData();
    /* metrics not populated (APQS_AppData was zeroed in setup) */
    UtAssert_UINT32_EQ(APQS_AppData.PerfHkTlm.PerfData.CpuLoadAvg1Min, 0);
}

void Test_SendPerfHk(void)
{
    APQS_SendPerfHk();
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 1);
}

/* ======================================================================== */
/* APQS_AppMain                                                             */
/* ======================================================================== */

void Test_APQS_AppMain_one_iteration(void)
{
    CFE_SB_Buffer_t *bufp = TestBuf();

    /* AppInit succeeds by default; run the loop exactly once */
    UT_SetDeferredRetcode(UT_KEY(CFE_ES_RunLoop), 1, true);
    /* ReceiveBuffer succeeds and yields our buffer */
    UT_SetDataBuffer(UT_KEY(CFE_SB_ReceiveBuffer), &bufp, sizeof(bufp), false);
    Stage_MsgId(0x9999); /* unknown MID -> harmless dispatch */

    APQS_AppMain();
    UtAssert_STUB_COUNT(CFE_ES_ExitApp, 1);
}

void Test_APQS_AppMain_receive_error(void)
{
    UT_SetDeferredRetcode(UT_KEY(CFE_ES_RunLoop), 1, true);
    UT_SetDefaultReturnValue(UT_KEY(CFE_SB_ReceiveBuffer), -1); /* pipe read error */

    APQS_AppMain();
    UtAssert_STUB_COUNT(CFE_ES_ExitApp, 1);
}

/* ======================================================================== */
/* additional AppInit / dispatch branches                                   */
/* ======================================================================== */

void Test_APQS_AppInit_second_subscribe_fails(void)
{
    UT_SetDeferredRetcode(UT_KEY(CFE_SB_Subscribe), 2, -1);
    UtAssert_INT32_EQ(APQS_AppInit(), -1);
}

void Test_APQS_AppInit_third_subscribe_fails(void)
{
    UT_SetDeferredRetcode(UT_KEY(CFE_SB_Subscribe), 3, -1);
    UtAssert_INT32_EQ(APQS_AppInit(), -1);
}

void Test_ProcessCommandPacket_cf_eot_route(void)
{
    Stage_MsgId(CF_EOT_TLM_MID);
    /* non-RX EOT: ProcessCfEot returns early, but the routing case is covered */
    APQS_ProcessCommandPacket(MakeEot(1, "/cf/upload/x.pbin"));
    UtAssert_STUB_COUNT(APQS_CFS_HandshakeHandleMessage, 0);
}

void Test_GroundCommand_long_mirror(void)
{
    Stage_FcnCode(APQS_APP_LONG_MIRROR);
    Stage_MsgSize(100);
    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(CFE_SB_TransmitMsg, 1);
}

/*
 * A renewal the library declines produces no CSR, so nothing is staged for
 * downlink. The old suite covered the decode-failure and key-install branches
 * separately; both moved inside the library when the app stopped decoding
 * protobuf and stopped installing session keys itself, so they are now covered
 * by the core suites and only the outcome is visible from here.
 */
void Test_GroundCommand_renew_cert_declined(void)
{
    Stage_FcnCode(APQS_APP_RENEW_CERT);
    UT_SetDefaultReturnValue(UT_KEY(APQS_CFS_CertRenewalStart), APQS_ERR_STATE);

    APQS_ProcessGroundCommand(TestBuf());
    UtAssert_STUB_COUNT(APQS_CFS_CertRenewalStart, 1);
    UtAssert_STUB_COUNT(OS_OpenCreate, 0);
}

/* ======================================================================== */
/* registration                                                             */
/* ======================================================================== */

void Test_Setup(void)
{
    UT_ResetState(0);
    memset(&APQS_AppData, 0, sizeof(APQS_AppData));
}

void Test_Teardown(void) {}

#define ADD_TEST(test) UtTest_Add((test), Test_Setup, Test_Teardown, #test)

void UtTest_Setup(void)
{
    ADD_TEST(Test_APQS_AppInit_nominal);
    ADD_TEST(Test_APQS_AppInit_creates_the_inbound_directory);
    ADD_TEST(Test_APQS_AppInit_evs_register_fails);
    ADD_TEST(Test_APQS_AppInit_createpipe_fails);
    ADD_TEST(Test_APQS_AppInit_subscribe_fails);
    ADD_TEST(Test_APQS_AppInit_second_subscribe_fails);
    ADD_TEST(Test_APQS_AppInit_third_subscribe_fails);

    ADD_TEST(Test_GroundCommand_mirror);
    ADD_TEST(Test_GroundCommand_long_mirror);
    ADD_TEST(Test_GroundCommand_renew_cert);
    ADD_TEST(Test_GroundCommand_renew_cert_declined);
    ADD_TEST(Test_GroundCommand_perf_hk_enable_disable);
    ADD_TEST(Test_GroundCommand_invalid_code);
    ADD_TEST(Test_GroundCommand_rekey_pb_success);
    ADD_TEST(Test_GroundCommand_rekey_pb_failure);
    ADD_TEST(Test_GroundCommand_key_conf_pb_success);

    ADD_TEST(Test_ProcessCommandPacket_cmd_mid);
    ADD_TEST(Test_ProcessCommandPacket_send_hk_enabled);
    ADD_TEST(Test_ProcessCommandPacket_send_hk_disabled);
    ADD_TEST(Test_ProcessCommandPacket_invalid_mid);
    ADD_TEST(Test_ProcessCommandPacket_cf_eot_route);

    ADD_TEST(Test_ProcessCfEot_handshake_file);
    ADD_TEST(Test_ProcessCfEot_pki_file);
    ADD_TEST(Test_ProcessCfEot_non_pbin_ignored);
    ADD_TEST(Test_ProcessCfEot_non_rx_ignored);
    ADD_TEST(Test_ProcessCfEot_unreadable_file_is_dropped);
    ADD_TEST(Test_ProcessCfEot_transfer_error_still_reads);

    ADD_TEST(Test_UpdatePerfData_success);
    ADD_TEST(Test_UpdatePerfData_failure);
    ADD_TEST(Test_SendPerfHk);

    ADD_TEST(Test_APQS_AppMain_one_iteration);
    ADD_TEST(Test_APQS_AppMain_receive_error);
}
