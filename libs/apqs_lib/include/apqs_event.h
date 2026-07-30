#pragma once

#include <stdint.h>

/*
** APQS event facade.
**
** The library reports events through apqs_event_send() rather than calling into
** a specific flight-software framework. The integrating system installs one
** handler with apqs_event_set_handler() and forwards the events to whatever
** event service it uses; under cFS that is CFE_EVS_SendEvent (see the adapter
** in apqs_cfs_init.c).
**
** With no handler installed events are dropped silently - the library must not
** assume a console exists on the target.
*/

/*
** Event severity. The values mirror the cFE CFE_EVS_EventType_* numbering so a
** host following those conventions sees no surprises, but handlers should still
** translate explicitly instead of casting.
*/
typedef enum
{
    APQS_EVENT_DEBUG    = 1,
    APQS_EVENT_INFO     = 2,
    APQS_EVENT_ERROR    = 3,
    APQS_EVENT_CRITICAL = 4,
} apqs_event_type_t;

/*
** Formatted message buffer size, NUL included. Matches the cFE default for
** CFE_MISSION_EVS_MAX_MESSAGE_LENGTH so a message is not truncated twice.
*/
#define APQS_EVENT_MAX_MSG_LEN 122

/*
** Library-owned event IDs.
**
** The library emits its events from the context of the hosting application, so
** an event service such as cFE EVS attributes them to that application and the
** two share one ID space. 100-199 is therefore reserved for the library; the
** hosting application must keep its own IDs outside that range.
*/
#define APQS_LIB_INIT_INF_EID 100

/* key material / PEM handling */
#define APQS_PEM_ERR_EID 110
#define APQS_PEM_INF_EID 111

/* certificate verification and OCSP */
#define APQS_CERTVER_ERR_EID 120
#define APQS_CERTVER_INF_EID 121
#define APQS_OCSP_ERR_EID    122
#define APQS_OCSP_INF_EID    123

/* SDLS handshake */
#define APQS_CF_HS_M1_INF_EID       130
#define APQS_CF_HS_M2_SENT_INF_EID  131
#define APQS_CF_HS_M3_OK_INF_EID    132
#define APQS_CF_HS_ERR_EID          133
#define APQS_HS_SESSION_KEY_INF_EID 134

/* PKI: trust initialization */
#define APQS_PKI_INIT_TRUST_INF_EID 140
#define APQS_PKI_INIT_TRUST_ERR_EID 141

/* PKI: certificate renewal */
#define APQS_PKI_CSR_SENT_INF_EID  150
#define APQS_PKI_CERT_SWAP_INF_EID 151
#define APQS_PKI_RENEW_ERR_EID     152

/* PKI: certificate exchange */
#define APQS_PKI_CERT_XCHG_INF_EID     160
#define APQS_PKI_CERT_XCHG_ERR_EID     161
#define APQS_PKI_CERT_SAT_SENT_INF_EID 162

#if defined(__GNUC__)
#define APQS_EVENT_PRINTF_FMT(fmt_idx, args_idx) __attribute__((format(printf, fmt_idx, args_idx)))
#else
#define APQS_EVENT_PRINTF_FMT(fmt_idx, args_idx)
#endif

/*
** Event sink: receives the already formatted message, so a handler never deals
** with varargs. msg is NUL terminated and only valid for the duration of the
** call - copy it if it needs to outlive the handler.
*/
typedef void (*apqs_event_handler_t)(uint16_t event_id, apqs_event_type_t type, const char *msg);

/*
** Install the event sink; last handler wins, NULL detaches. Expected to be
** called once during single-threaded initialization - the handler is read
** without locking on every apqs_event_send().
*/
void apqs_event_set_handler(apqs_event_handler_t handler);

/*
** Format the message and hand it to the installed handler. No-op while no
** handler is installed. Messages longer than APQS_EVENT_MAX_MSG_LEN are
** truncated.
*/
void apqs_event_send(uint16_t event_id, apqs_event_type_t type, const char *fmt, ...) APQS_EVENT_PRINTF_FMT(3, 4);
