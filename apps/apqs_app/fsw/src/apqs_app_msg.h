#pragma once

#include "apqs_cfs_pki.h"

#define APQS_APP_MIRROR 44
#define APQS_APP_LONG_MIRROR 46

#define APQS_APP_HANDSHAKE_REKEY_PB 61
#define APQS_APP_HANDSHAKE_KEY_CONF_PB 63
/* test-only trigger for the certificate renewal scenario (operational trigger is RenewCertCommand via CFDP) */
#define APQS_APP_RENEW_CERT 65

#define APQS_APP_PERF_HK_REQ 70      
#define APQS_APP_PERF_HK_DISABLE 71  

#define APQS_MIRROR_MAX_PAYLOAD 4
#define APQS_LONG_MIRROR_MAX_PAYLOAD 2100

typedef struct
{
    uint8_t Msg[APQS_MIRROR_MAX_PAYLOAD];
} APQS_Mirror_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    APQS_Mirror_t Mirror;
} APQS_TM_Mirror_t;

typedef struct
{
    uint16_t PayloadSize;
    uint8_t Payload[APQS_LONG_MIRROR_MAX_PAYLOAD];
} APQS_LongMirror_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    APQS_LongMirror_t LongMirror;
} APQS_TM_LongMirror_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    /* Sized by the library, re-exported through apqs_cfs_pki.h, so this packet
     * follows handshake.proto without this file knowing the schema. */
    uint8_t ResponseMsg[APQS_CFS_HS_RESPONSE_BUFFER_SIZE];
} APQS_TM_HS_Response_t;

/*
 * Outcome of a PKI operation, as an encoded pki.PkiMessage carrying a PkiStatus.
 *
 * Same arrangement as the handshake response above: the library sizes and
 * encodes it, this file only says which packet it rides in. Sent short - the
 * transmitted length is trimmed to the encoded status, because a receiver
 * decoding protobuf would read trailing pad bytes as field number 0.
 */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8_t StatusMsg[APQS_CFS_PKI_STATUS_BUFFER_SIZE];
} APQS_TM_PkiStatus_t;

typedef struct
{
    uint32_t CpuLoadAvg1Min;      /* 1-minute load average, hundredths (150 = 1.50) */
    uint32_t CpuLoadAvg5Min;      /* 5-minute load average, hundredths */
    uint32_t CpuLoadAvg15Min;     /* 15-minute load average, hundredths */
    uint64_t MemTotalBytes;       /* Total system RAM, bytes */
    uint64_t MemFreeBytes;        /* Free system RAM, bytes */
    uint32_t HandshakeLatencyUs;  /* Last handshake procedure latency, microseconds */
} APQS_PerfData_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    APQS_PerfData_t PerfData;
} APQS_TM_PerfHk_t;
