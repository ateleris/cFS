#pragma once

#include "cfe.h"

/**
 * Library initialization routine/entry point
 * cfs needs this
 */
int32 lib_apqs_init(void);

/*
** Facade installers. Each lives in the translation unit holding the cFS calls
** it makes, and lib_apqs_init() runs all of them before the core is touched.
** Split out rather than folded into lib_apqs_init so the cFS dependencies stay
** grouped by concern: EVS, OS_printf, OSAL files.
*/
void APQS_CFS_LogInit(void);
void APQS_CFS_KeystoreInit(void);
void APQS_CFS_EventInit(void);
