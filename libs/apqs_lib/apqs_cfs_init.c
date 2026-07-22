#include "apqs_cfs_init.h"

#include "apqs_api.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Library Initialization Routine                                  */
/* cFE requires that a library have an initialization routine      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int32 lib_apqs_init(void)
{
    const char *ver = apqs_lib_version();

    OS_printf("APQS Lib v%s\n", ver);

    CI_LAB_CryptoLib_Init();

    return CFE_SUCCESS;
}
