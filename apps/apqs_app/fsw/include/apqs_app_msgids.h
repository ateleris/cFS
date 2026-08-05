#pragma once

#define APQS_APP_CMD_MID 0x1842

#define APQS_APP_SEND_HK_MID 0x1843

#define APQS_APP_MIRROR_MID 0X0844
#define APQS_APP_LONG_MIRROR_TLM_MID 0x0845
#define APQS_APP_HS_PB_RESPONSE_MID 0x0862
/* PKI operation outcome (pki.PkiStatus). A status is an ack, not a payload, so
 * it goes out as one telemetry packet; the bulk PKI replies (CSR, certificate)
 * still travel as CFDP files. */
#define APQS_APP_PKI_STATUS_MID 0x0863
#define APQS_APP_PERF_HK_TLM_MID 0x0846
