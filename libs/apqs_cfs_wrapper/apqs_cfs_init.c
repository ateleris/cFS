#include "apqs_cfs_init.h"

#include <apqs/api.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Library Initialization Routine                                  */
/* cFE requires that a library have an initialization routine      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int32 lib_apqs_init(void)
{
    const char *ver = apqs_lib_version();

    /*
    ** Install every facade before the first call into the core. The core drops
    ** events and logs silently and fails keystore calls while no
    ** handler is installed, so anything the core does before this point would
    ** be invisible.
    */
    APQS_CFS_EventInit();
    APQS_CFS_LogInit();
    APQS_CFS_KeystoreInit();

    OS_printf("APQS Lib v%s\n", ver);

    apqs_lib_init();

    return CFE_SUCCESS;
}
