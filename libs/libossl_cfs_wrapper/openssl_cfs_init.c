
#include "openssl_cfs_init.h"

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Library Initialization Routine                                  */
/* cFE requires that a library have an initialization routine      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int32 lib_openssl_init(void)
{
    const char* ver = OpenSSL_version(OPENSSL_VERSION);
    const char* verBuild = OpenSSL_version(OPENSSL_BUILT_ON);
    const char* verPlatform = OpenSSL_version(OPENSSL_PLATFORM);

    OS_printf("Open SSL v%s\n", ver);
    OS_printf("Open SSL build date: %s\n", verBuild);
    OS_printf("Open SSL platform: %s\n", verPlatform);

    return CFE_SUCCESS;
}
