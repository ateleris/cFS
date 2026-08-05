#include "apqs_cfs_init.h"

#include <apqs/log.h>

/*
** cFS log sink.
**
** INFO and ERROR go to the ES system log, DEBUG to the console.
**
** CFE_ES_WriteToSysLog is a superset of OS_printf: it echoes to the console and
** additionally appends to a circular buffer in the ES reset area, which
** survives a processor reset and is downlinkable (ES housekeeping reports
** SysLogBytesUsed / SysLogEntries, and the buffer can be dumped to a file).
**
** That retention is why the split matters here. apqs_lib loads at startup
** script line 2, while apqs_app does not call CFE_EVS_Register until line 8, so
** anything the core reports during lib_apqs_init and apqs_lib_init is rejected
** by EVS with CFE_EVS_APP_NOT_REGISTERED. Console-only output leaves no trace
** once the terminal scrolls, so an init failure in flight would be invisible
** both live and post-mortem. Routing errors to the system log closes that gap
** at no extra cost, since they reach the console either way.
**
** The system log is bounded and lossy by design (OVERWRITE wraps, DISCARD stops
** when full), which is why DEBUG stays on the console: ~100 per-operation
** diagnostics would evict the startup errors this exists to preserve. INFO is
** admitted because it is a narrow category by construction - a milestone worth
** telling ground about goes out as an event with its own ID instead, so what
** reaches here is only the post-mortem-worthy remainder. Keep it that way; a
** per-frame or per-iteration message is DEBUG no matter how interesting.
*/
static void apqs_log_to_cfs(apqs_log_level_t level, const char *msg)
{
    if (level >= APQS_LOG_INFO)
    {
        CFE_ES_WriteToSysLog("%s", msg);
    }
    else
    {
        OS_printf("%s", msg);
    }
}

void APQS_CFS_LogInit(void)
{
    apqs_log_set_handler(apqs_log_to_cfs);
}
