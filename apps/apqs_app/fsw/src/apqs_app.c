#include "apqs_app_events.h"
#include "apqs_app_version.h"
#include "apqs_app.h"

#include "apqs_cfs_pki.h"

#include "cf_msg.h"
#include "cf_msgids.h"
#include "cf_msgdefs.h"
#include "cf_msgstruct.h"
#include "cf_fcncodes.h"

#include <string.h>

#define APQS_CMD_PAYLOAD_OFFSET 8 /* CCSDS primary (6) + cmd secondary (2) header bytes */

/* CFDP-received APQS protocol messages */
#define APQS_MSG_FILE_EXT    ".pbin"
#define APQS_CF_DIRECTION_RX 0 /* CF_Direction_RX (cf_cfdp_types.h, CF-internal) */

/*
 * CFDP configuration and file layout.
 *
 * All of this used to live inside the APQS library, which meant a protocol
 * implementation knew about CF message IDs, CFDP classes, entity IDs and the
 * /cf mount. It belongs here: the library takes and returns bytes, and this app
 * decides how they cross the link.
 */
#define APQS_CFDP_GROUND_EID 1

/* Receive root must match the CF config table's rx_base_dir
 * (apps/cf/fsw/tables/cf_def_config.c). The ground delivers handshake messages
 * as "handshake/M1.pbin" relative to it; CFDP does not create intermediate
 * directories, so the sub-dir is created at init. */
#define APQS_CF_RX_BASE_DIR "/cf/upload"
#define APQS_HS_INBOUND_DIR "/cf/upload/handshake"

/* Staging files for outbound replies, and the names the ground expects. */
#define APQS_M2_STAGING_PATH  "/cf/M2.pbin"
#define APQS_M2_DEST_NAME     "handshake/M2.pbin"
#define APQS_PKI_STAGING_PATH "/cf/PKI_REPLY.pbin"
#define APQS_PKI_DEST_NAME    "PKI_REPLY.pbin"
#define APQS_CSR_STAGING_PATH "/cf/PKI_CSR.pbin"
#define APQS_CSR_DEST_NAME    "PKI_CSR.pbin"

/* Which handler an inbound file goes to, decided by its basename. This is an
 * agreement between the ground and this app about how to label a transfer, so
 * it lives here with the rest of the naming. The library is handed bytes and
 * told which flow they belong to by the call that is made; it never sees a
 * filename and has no opinion about one. */
#define APQS_PKI_MSG_FILE_PREFIX "PKI_"

APQS_AppData_t APQS_AppData;

/*
 * Ask CF to ship a file to the ground.
 *
 * Class 1 (unacknowledged): the ground entity's class-2 response PDUs are
 * rejected by CF ("invalid destination eid"), ending acknowledged transfers in
 * ACK/NAK limit + delayed delivery on ground.
 */
static CFE_Status_t APQS_SendFileViaCfdp(const char* src_path, const char* dst_name)
{
    CF_TxFileCmd_t txCmd;

    memset(&txCmd, 0, sizeof(txCmd));

    CFE_MSG_Init(CFE_MSG_PTR(txCmd.CommandHeader), CFE_SB_ValueToMsgId(CF_CMD_MID), sizeof(CF_TxFileCmd_t));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(txCmd.CommandHeader), CF_TX_FILE_CC);

    txCmd.Payload.cfdp_class = CF_CFDP_CLASS_1;
    txCmd.Payload.keep       = 0;
    txCmd.Payload.chan_num   = 0;
    txCmd.Payload.priority   = 0;
    txCmd.Payload.dest_id    = APQS_CFDP_GROUND_EID;

    strncpy(txCmd.Payload.src_filename, src_path, sizeof(txCmd.Payload.src_filename) - 1);
    strncpy(txCmd.Payload.dst_filename, dst_name, sizeof(txCmd.Payload.dst_filename) - 1);

    CFE_SB_TimeStampMsg(CFE_MSG_PTR(txCmd.CommandHeader));
    return CFE_SB_TransmitMsg(CFE_MSG_PTR(txCmd.CommandHeader), true);
}

/* Stage a reply produced by the library, then hand it to CF. */
static void APQS_DeliverReply(const char* staging_path, const char* dst_name, const uint8_t* buf, size_t len)
{
    osal_id_t fd;

    if (OS_OpenCreate(&fd, staging_path, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY) != OS_SUCCESS)
    {
        CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
            "APQS: could not create %s for reply", staging_path);
        return;
    }

    int32 written = OS_write(fd, buf, len);
    OS_close(fd);

    if (written != (int32)len)
    {
        CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
            "APQS: short write staging %s (%ld of %lu)", staging_path, (long)written, (unsigned long)len);
        return;
    }

    if (APQS_SendFileViaCfdp(staging_path, dst_name) != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
            "APQS: CF TX FILE cmd failed for %s", staging_path);
    }
}

/*
 * Report the outcome of a PKI operation to the ground.
 *
 * The library stopped answering the ground with a PkiStatus of its own and left
 * the decision here (see apqs_cfs_pki.h). It is reported on every PKI operation,
 * including the two that also send a file: the ground commits the key material it
 * staged for an operation only once that operation is acked, and for init_trust
 * and new_certificate there is nothing else on the wire to ack them.
 *
 * A status is a handful of bytes, so it goes as telemetry rather than as a CFDP
 * file: no staging file, no CF transfer, and it does not queue behind the
 * certificate transfers on channel 0.
 */
static void APQS_SendPkiStatus(uint32_t op, apqs_status_t status)
{
    size_t status_len = 0;

    if (APQS_CFS_PkiEncodeStatus(op, status, APQS_AppData.PkiStatusTlm.StatusMsg,
                                 sizeof(APQS_AppData.PkiStatusTlm.StatusMsg), &status_len) != APQS_OK ||
        status_len == 0)
    {
        CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
            "APQS: could not encode PKI status for op %lu", (unsigned long)op);
        return;
    }

    /* Trim to the encoded status: the ground parses the payload as protobuf and
     * would read the struct's trailing pad bytes as field number 0. */
    CFE_MSG_SetSize(CFE_MSG_PTR(APQS_AppData.PkiStatusTlm.TlmHeader),
                    sizeof(CFE_MSG_TelemetryHeader_t) + status_len);
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(APQS_AppData.PkiStatusTlm.TlmHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(APQS_AppData.PkiStatusTlm.TlmHeader), true);

    CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_INFORMATION,
        "APQS: PKI status sent (op=%lu, code=%d)", (unsigned long)op, (int)status);
}

/* Read a CFDP-delivered file into buf. Returns the byte count, 0 on failure. */
static size_t APQS_ReadReceivedFile(const char* filepath, uint8_t* buf, size_t cap)
{
    osal_id_t fd;

    if (OS_OpenCreate(&fd, filepath, OS_FILE_FLAG_NONE, OS_READ_ONLY) != OS_SUCCESS)
    {
        CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
            "APQS: could not open %s", filepath);
        return 0;
    }

    int32 bytes_read = OS_read(fd, buf, cap);
    OS_close(fd);

    return (bytes_read > 0) ? (size_t)bytes_read : 0;
}

void APQS_AppMain(void)
{
    int32            status;
    CFE_SB_Buffer_t* SBBufPtr;

    status = APQS_AppInit();
    if (status != CFE_SUCCESS)
    {
        APQS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&APQS_AppData.RunStatus) == true)
    {
        status = CFE_SB_ReceiveBuffer(&SBBufPtr, APQS_AppData.CommandPipe, CFE_SB_PEND_FOREVER);

        if (status == CFE_SUCCESS)
        {
            APQS_ProcessCommandPacket(SBBufPtr);
        }
        else
        {
            CFE_EVS_SendEvent(APQS_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "APQS APP: SB Pipe Read Error, App Will Exit");
            APQS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_ExitApp(APQS_AppData.RunStatus);
}

int32 APQS_AppInit(void)
{
    int32 status;

    APQS_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;
    APQS_AppData.HkEnabled = false;
    APQS_AppData.PipeDepth = APQS_PIPE_DEPTH;
    strncpy(APQS_AppData.PipeName, "APQS_CMD_PIPE", sizeof(APQS_AppData.PipeName));
    APQS_AppData.PipeName[sizeof(APQS_AppData.PipeName) - 1] = 0;

    if ((status = CFE_EVS_Register(NULL, 0, 0)) != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: Error Registering Events, RC = %lu\n", (unsigned long)status);
        return (status);
    }

    /* The ML-DSA availability check moved into apqs_lib: OpenSSL is private to
     * that library now, and it is the code that actually uses ML-DSA. It runs
     * during lib_apqs_init and reports through EVS, so the events still arrive,
     * just from APQS_LIB rather than APQS_APP. */


    /* The PKI store is not touched here. lib_apqs_init installs the keystore
     * backend and repairs any interrupted key swap, and that runs before any
     * app starts - which matters, because ci_lab and to_lab hold references to
     * the same library and start ahead of this one. */

    /* CFDP receive directories. CF creates only its rx_base_dir and CFDP does
     * not create intermediate directories, so the ground-chosen "handshake/"
     * sub-dir is made here. This used to be the library's job, back when it
     * knew what CFDP was. */
    os_fstat_t st;
    if (OS_stat(APQS_CF_RX_BASE_DIR, &st) != OS_SUCCESS)
    {
        OS_mkdir(APQS_CF_RX_BASE_DIR, OS_READ_WRITE);
    }
    if (OS_stat(APQS_HS_INBOUND_DIR, &st) != OS_SUCCESS &&
        OS_mkdir(APQS_HS_INBOUND_DIR, OS_READ_WRITE) != OS_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: could not create %s\n", APQS_HS_INBOUND_DIR);
    }

    CFE_MSG_Init(&APQS_AppData.MirrorTlm.TlmHeader.Msg, CFE_SB_ValueToMsgId(APQS_APP_MIRROR_MID), sizeof(APQS_AppData.MirrorTlm));
    CFE_MSG_Init(&APQS_AppData.LongMirrorTlm.TlmHeader.Msg, CFE_SB_ValueToMsgId(APQS_APP_LONG_MIRROR_TLM_MID), sizeof(APQS_AppData.LongMirrorTlm));
    CFE_MSG_Init(&APQS_AppData.HSResponseTlm.TlmHeader.Msg, CFE_SB_ValueToMsgId(APQS_APP_HS_PB_RESPONSE_MID), sizeof(APQS_AppData.HSResponseTlm));
    CFE_MSG_Init(&APQS_AppData.PkiStatusTlm.TlmHeader.Msg, CFE_SB_ValueToMsgId(APQS_APP_PKI_STATUS_MID), sizeof(APQS_AppData.PkiStatusTlm));
    CFE_MSG_Init(&APQS_AppData.PerfHkTlm.TlmHeader.Msg, CFE_SB_ValueToMsgId(APQS_APP_PERF_HK_TLM_MID), sizeof(APQS_AppData.PerfHkTlm));

    status = CFE_SB_CreatePipe(&APQS_AppData.CommandPipe, APQS_AppData.PipeDepth, APQS_AppData.PipeName);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: Error creating pipe, RC = 0x%08lX\n", (unsigned long)status);
        return (status);
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(APQS_APP_CMD_MID), APQS_AppData.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: Error Subscribing to Command, RC = 0x%08lX\n", (unsigned long)status);
        return (status);
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CF_EOT_TLM_MID), APQS_AppData.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: Error Subscribing to CF_EOT_TLM_MID, RC = 0x%08lX\n", (unsigned long)status);
        return (status);
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(APQS_APP_SEND_HK_MID), APQS_AppData.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("APQS App: Error Subscribing to APQS_APP_SEND_HK_MID, RC = 0x%08lX\n", (unsigned long)status);
        return (status);
    }

    CFE_EVS_SendEvent(APQS_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION, "APQS App Initialized. Version %d.%d.%d.%d", APQS_APP_MAJOR_VERSION, APQS_APP_MINOR_VERSION, APQS_APP_REVISION, APQS_APP_MISSION_REV);
    return (CFE_SUCCESS);
}

void APQS_ProcessCommandPacket(CFE_SB_Buffer_t* SBBufPtr)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
    case APQS_APP_CMD_MID:
        APQS_ProcessGroundCommand(SBBufPtr);
        break;
    case CF_EOT_TLM_MID:
        APQS_ProcessCfEot(SBBufPtr);
        break;
    case APQS_APP_SEND_HK_MID:
        if (APQS_AppData.HkEnabled)
        {
            APQS_SendPerfHk();
        }
        break;
    default:
        CFE_EVS_SendEvent(APQS_INVALID_MSGID_ERR_EID, CFE_EVS_EventType_ERROR,
            "APQS: invalid command packet,MID = 0x%x", CFE_SB_MsgIdToValue(MsgId));
        break;
    }
    return;
}

void APQS_ProcessGroundCommand(CFE_SB_Buffer_t* SBBufPtr)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &CommandCode);

    switch (CommandCode)
    {
    case APQS_APP_MIRROR:
    {
        uint8_t* mirrorPtr = ((uint8_t*)SBBufPtr) + APQS_CMD_PAYLOAD_OFFSET;

        char buf[APQS_MIRROR_MAX_PAYLOAD + 1];
        for (size_t i = 0; i < APQS_MIRROR_MAX_PAYLOAD; i++)
            buf[i] = mirrorPtr[i];
        buf[APQS_MIRROR_MAX_PAYLOAD] = '\0';

        CFE_ES_WriteToSysLog("APQS App: MIRROR received: %s\n", buf);

        APQS_Mirror_t* mirrorResponsePtr = &(APQS_AppData.MirrorTlm.Mirror);
        memcpy(mirrorResponsePtr->Msg, mirrorPtr, sizeof(mirrorResponsePtr->Msg));

        CFE_SB_TimeStampMsg(CFE_MSG_PTR(APQS_AppData.MirrorTlm.TlmHeader));
        CFE_SB_TransmitMsg(CFE_MSG_PTR(APQS_AppData.MirrorTlm.TlmHeader), true);
        break;
    }
    case APQS_APP_LONG_MIRROR:
    {
        size_t msg_size = 0;
        CFE_MSG_GetSize(&SBBufPtr->Msg, &msg_size);

        size_t payload_size = (msg_size > APQS_CMD_PAYLOAD_OFFSET) ? (msg_size - APQS_CMD_PAYLOAD_OFFSET) : 0;
        if (payload_size > APQS_LONG_MIRROR_MAX_PAYLOAD)
            payload_size = APQS_LONG_MIRROR_MAX_PAYLOAD;

        APQS_AppData.LongMirrorTlm.LongMirror.PayloadSize = (uint16_t)payload_size;
        memcpy(APQS_AppData.LongMirrorTlm.LongMirror.Payload, ((uint8_t*)SBBufPtr) + APQS_CMD_PAYLOAD_OFFSET, payload_size);

        CFE_SB_TimeStampMsg(CFE_MSG_PTR(APQS_AppData.LongMirrorTlm.TlmHeader));
        CFE_SB_TransmitMsg(CFE_MSG_PTR(APQS_AppData.LongMirrorTlm.TlmHeader), true);
        break;
    }
    case APQS_APP_HANDSHAKE_REKEY_PB:
        CFE_ES_WriteToSysLog("APQS App: Handshake Protobuf rekey received");

        size_t hs_rekey_msg_size = 0;
        size_t hs_reply_len      = 0;
        CFE_MSG_GetSize(&SBBufPtr->Msg, &hs_rekey_msg_size);

        if (APQS_CFS_HandshakeHandleMessage((uint8_t*)SBBufPtr + APQS_CMD_PAYLOAD_OFFSET,
                                            hs_rekey_msg_size - APQS_CMD_PAYLOAD_OFFSET,
                                            APQS_AppData.HSResponseTlm.ResponseMsg,
                                            sizeof(APQS_AppData.HSResponseTlm.ResponseMsg),
                                            &hs_reply_len) != APQS_OK)
        {
            CFE_ES_WriteToSysLog("APQS App: Calculation of Handshake Protobuf response failed");
            return;
        }

        CFE_SB_TimeStampMsg(CFE_MSG_PTR(APQS_AppData.HSResponseTlm.TlmHeader));
        CFE_SB_TransmitMsg(CFE_MSG_PTR(APQS_AppData.HSResponseTlm.TlmHeader), true);
        CFE_ES_WriteToSysLog("APQS App: Handshake Protobuf response sent");
        break;
    case APQS_APP_HANDSHAKE_KEY_CONF_PB:
        CFE_ES_WriteToSysLog("APQS App: Handshake Protobuf key confirmation received");

        size_t hs_key_conf_msg_size = 0;
        size_t kc_reply_len         = 0;
        static uint8_t kc_reply[APQS_CFS_HS_RESPONSE_BUFFER_SIZE];
        CFE_MSG_GetSize(&SBBufPtr->Msg, &hs_key_conf_msg_size);

        /* Same entry point as the rekey above: the library dispatches on the
         * message payload. Key confirmation produces no reply, and the session
         * key install and renewal confirmation happen inside it. */
        if (APQS_CFS_HandshakeHandleMessage((uint8_t*)SBBufPtr + APQS_CMD_PAYLOAD_OFFSET,
                                            hs_key_conf_msg_size - APQS_CMD_PAYLOAD_OFFSET,
                                            kc_reply, sizeof(kc_reply), &kc_reply_len) != APQS_OK)
        {
            CFE_ES_WriteToSysLog("APQS App: Handshake key confirmation failed");
            return;
        }
        break;
    case APQS_APP_RENEW_CERT:
        CFE_ES_WriteToSysLog("APQS App: Certificate renewal trigger received (test command)");
        {
            static uint8_t csr_msg[APQS_CFS_CSR_BUFFER_SIZE];
            size_t         csr_len = 0;

            apqs_status_t renewal_status = APQS_CFS_CertRenewalStart(csr_msg, sizeof(csr_msg), &csr_len);
            if (renewal_status == APQS_OK && csr_len > 0)
            {
                APQS_DeliverReply(APQS_CSR_STAGING_PATH, APQS_CSR_DEST_NAME, csr_msg, csr_len);
            }
            /* Reported as renew_cert, the same operation the CFDP trigger names:
             * the ground sees one outcome for a renewal however it was started. */
            APQS_SendPkiStatus(APQS_CFS_PKI_OP_RENEW_CERT, renewal_status);
        }
        break;
    case APQS_APP_PERF_HK_REQ:
        APQS_AppData.HkEnabled = true;
        CFE_ES_WriteToSysLog("APQS App: Performance HK enabled\n");
        break;
    case APQS_APP_PERF_HK_DISABLE:
        APQS_AppData.HkEnabled = false;
        CFE_ES_WriteToSysLog("APQS App: Performance HK disabled\n");
        break;
    default:
        CFE_EVS_SendEvent(APQS_COMMAND_ERR_EID, CFE_EVS_EventType_ERROR, "Invalid ground command code: CC = %d",
            CommandCode);
        break;
    }
    return;
}

void APQS_ProcessCfEot(CFE_SB_Buffer_t* SBBufPtr)
{
    CF_EotPacket_t* EotPtr = (CF_EotPacket_t*)SBBufPtr;

    CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_INFORMATION,
        "APQS: CF EOT dir=%lu stat=%lu file=%s (size=%lu, src_eid=%lu, seq=%lu)",
        (unsigned long)EotPtr->Payload.direction,
        (unsigned long)EotPtr->Payload.txn_stat,
        EotPtr->Payload.fnames.dst_filename,
        (unsigned long)EotPtr->Payload.fsize,
        (unsigned long)EotPtr->Payload.src_eid,
        (unsigned long)EotPtr->Payload.seq_num);

    if (EotPtr->Payload.direction == APQS_CF_DIRECTION_RX)
    {
        const char* filepath = EotPtr->Payload.fnames.dst_filename;

        /* Only .pbin files are APQS protocol messages */
        const char* ext = strrchr(filepath, '.');
        if (ext == NULL || strcmp(ext, APQS_MSG_FILE_EXT) != 0)
            return;

        /* PKI_-prefixed files carry pki.PkiMessage payloads, everything else is a handshake
           message (basename: RX files land under /cf/upload) */
        const char* slash = strrchr(filepath, '/');
        const char* basename = (slash != NULL) ? slash + 1 : filepath;
        /* Read it here: the library takes bytes, not paths. Attempt the read
         * even when txn_stat reports a transfer error - the file may still be
         * complete on disk, and the library validates it either way. */
        if (EotPtr->Payload.txn_stat != 0)
        {
            CFE_EVS_SendEvent(APQS_CF_FILE_RECV_INF_EID, CFE_EVS_EventType_ERROR,
                "APQS: CFDP transfer error for %s (stat=%lu), reading anyway",
                filepath, (unsigned long)EotPtr->Payload.txn_stat);
        }

        static uint8_t msg_buf[APQS_CFS_PKI_REPLY_BUFFER_SIZE];
        static uint8_t reply_buf[APQS_CFS_PKI_REPLY_BUFFER_SIZE];
        size_t         reply_len = 0;

        size_t msg_len = APQS_ReadReceivedFile(filepath, msg_buf, sizeof(msg_buf));
        if (msg_len == 0)
        {
            return;
        }

        if (strncmp(basename, APQS_PKI_MSG_FILE_PREFIX, sizeof(APQS_PKI_MSG_FILE_PREFIX) - 1) == 0)
        {
            uint32_t      pki_op     = 0;
            apqs_status_t pki_status = APQS_CFS_PkiHandleMessage(msg_buf, msg_len, reply_buf, sizeof(reply_buf),
                                                                 &reply_len, &pki_op);
            if (reply_len > 0)
            {
                APQS_DeliverReply(APQS_PKI_STAGING_PATH, APQS_PKI_DEST_NAME, reply_buf, reply_len);
            }
            APQS_SendPkiStatus(pki_op, pki_status);
        }
        else
        {
            APQS_CFS_HandshakeHandleMessage(msg_buf, msg_len, reply_buf, sizeof(reply_buf), &reply_len);
            if (reply_len > 0)
            {
                APQS_DeliverReply(APQS_M2_STAGING_PATH, APQS_M2_DEST_NAME, reply_buf, reply_len);
            }
        }

        /* the raw message may hold secrets (PSS) - wipe once handled */
        memset(msg_buf, 0, sizeof(msg_buf));
    }
}

void APQS_UpdatePerfData(void)
{
    /*
     * Populate the system performance HK payload (OBS-PERF-01).
     * CPU load and memory come from the OSAL metrics call.
     * TODO (next increment): populate HandshakeLatencyUs from perf markers.
     */
    OS_sys_metrics_t metrics;
    int32            os_status;

    os_status = OS_GetSysMetrics(&metrics);
    if (os_status == OS_SUCCESS)
    {
        APQS_AppData.PerfHkTlm.PerfData.CpuLoadAvg1Min  = metrics.load_avg_1min;
        APQS_AppData.PerfHkTlm.PerfData.CpuLoadAvg5Min  = metrics.load_avg_5min;
        APQS_AppData.PerfHkTlm.PerfData.CpuLoadAvg15Min = metrics.load_avg_15min;
        APQS_AppData.PerfHkTlm.PerfData.MemTotalBytes   = metrics.total_ram;
        APQS_AppData.PerfHkTlm.PerfData.MemFreeBytes    = metrics.free_ram;
    }
    else
    {
        CFE_ES_WriteToSysLog("APQS App: OS_GetSysMetrics failed, RC = %ld\n", (long)os_status);
    }
}

void APQS_SendPerfHk(void)
{
    APQS_UpdatePerfData();

    CFE_SB_TimeStampMsg(CFE_MSG_PTR(APQS_AppData.PerfHkTlm.TlmHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(APQS_AppData.PerfHkTlm.TlmHeader), true);
}
