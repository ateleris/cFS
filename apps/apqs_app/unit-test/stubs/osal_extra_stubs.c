/*
 * Hand-written UT-Assert stubs for OSAL functions that are NOT provided by the
 * standard ut_osapi_stubs library.
 *
 * OS_GetSysMetrics is an e2eqss/OBS-PERF addition (osapi-metrics.h); the cFS
 * unit-test stub set predates it, so apqs_app.c would otherwise fail to link.
 *
 * Default return is OS_SUCCESS; a test stages the reported metrics with
 *   UT_SetDataBuffer(UT_KEY(OS_GetSysMetrics), &m, sizeof(m), false);
 * and forces failure with UT_SetDefaultReturnValue(UT_KEY(OS_GetSysMetrics), OS_ERROR).
 */

#include "osapi-metrics.h"
#include "osapi-error.h"

#include "utstubs.h"

int32 OS_GetSysMetrics(OS_sys_metrics_t *metrics)
{
    UT_Stub_RegisterContext(UT_KEY(OS_GetSysMetrics), metrics);

    int32 status = UT_DEFAULT_IMPL(OS_GetSysMetrics);

    if (status == OS_SUCCESS && metrics != NULL)
    {
        UT_Stub_CopyToLocal(UT_KEY(OS_GetSysMetrics), metrics, sizeof(*metrics));
    }

    return status;
}
