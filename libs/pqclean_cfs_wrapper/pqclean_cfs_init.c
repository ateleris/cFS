
#include "pqclean_cfs_init.h"
#include "pqclean_fwd.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                                                 */
/* Library Initialization Routine                                  */
/* cFE requires that a library have an initialization routine      */
/*                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int32 lib_pqclean_init(void)
{
    OS_printf("PQClean Post-Quantum Cryptography Library\n");

    uint8_t public_key[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(public_key, secret_key))
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair failed\n");
        return 1;
    }

    uint8_t ciphertext[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key))
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc failed\n");
        return 1;
    }

    uint8_t shared_secret_d[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret_d, ciphertext, secret_key))
    {
        OS_printf("PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec failed\n");
        return 1;
    }

    if (memcmp(shared_secret, shared_secret_d, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES))
    {
        OS_printf("shared secret do not match\n");
        return 1;
    }
    
    OS_printf("PQClean functions successfully initialized and tested\n");
    return CFE_SUCCESS;
}
