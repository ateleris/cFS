#include "apqs_event.h"

#include <stdarg.h>
#include <stdio.h>

static apqs_event_handler_t apqs_event_handler = NULL;

void apqs_event_set_handler(apqs_event_handler_t handler)
{
    apqs_event_handler = handler;
}

void apqs_event_send(uint16_t event_id, apqs_event_type_t type, const char *fmt, ...)
{
    if (apqs_event_handler == NULL)
    {
        return;
    }

    char msg[APQS_EVENT_MAX_MSG_LEN];
    va_list args;

    va_start(args, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    apqs_event_handler(event_id, type, msg);
}
