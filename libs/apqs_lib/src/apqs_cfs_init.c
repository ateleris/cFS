#include "apqs_cfs_init.h"

#include "apqs_api.h"
#include "apqs_event.h"

/*
** Translate the library's severity into the cFE equivalent. Explicit rather
** than a cast: apqs_event_type_t happens to mirror the CFE_EVS_EventType_*
** numbering, but the library must not depend on that staying true.
*/
static CFE_EVS_EventType_Enum_t apqs_event_type_to_evs(apqs_event_type_t type)
{
    switch (type)
    {
    case APQS_EVENT_DEBUG:
        return CFE_EVS_EventType_DEBUG;
    case APQS_EVENT_INFO:
        return CFE_EVS_EventType_INFORMATION;
    case APQS_EVENT_CRITICAL:
        return CFE_EVS_EventType_CRITICAL;
    case APQS_EVENT_ERROR:
    default:
        return CFE_EVS_EventType_ERROR;
    }
}

/*
** cFS event sink: the message is already formatted, so it is forwarded as a
** plain string. EVS truncates at CFE_MISSION_EVS_MAX_MESSAGE_LENGTH, which
** APQS_EVENT_MAX_MSG_LEN matches.
*/
static void apqs_event_to_evs(uint16_t event_id, apqs_event_type_t type, const char *msg)
{
    CFE_EVS_SendEvent(event_id, apqs_event_type_to_evs(type), "%s", msg);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Library Initialization Routine                                  */
/* cFE requires that a library have an initialization routine      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int32 lib_apqs_init(void)
{
    const char *ver = apqs_lib_version();

    apqs_event_set_handler(apqs_event_to_evs);

    OS_printf("APQS Lib v%s\n", ver);

    apqs_lib_init();

    return CFE_SUCCESS;
}
