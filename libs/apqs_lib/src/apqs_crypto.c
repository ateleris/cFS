#include "apqs_app_crypto.h"

#include "cfe.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <assert.h>

static const char digest_sha3_384[] = "SHA3-384";

static void hmac_ctx_cleanup(OSSL_LIB_CTX* ctx, EVP_MAC* mac, EVP_MAC_CTX* mctx)
{
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(ctx);
}

int hmac_sha3_384(const uint8_t* key, size_t key_len, const hmac_part_t* parts, size_t num_parts, uint8_t* tag_out)
{
    OSSL_LIB_CTX* ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL)
    {
        OS_printf("APQS HMAC: OSSL_LIB_CTX_new failed\n");
        return -1;
    }

    EVP_MAC* mac = EVP_MAC_fetch(ctx, "HMAC", NULL);
    if (mac == NULL)
    {
        OS_printf("APQS HMAC: EVP_MAC_fetch failed\n");
        OSSL_LIB_CTX_free(ctx);
        return -1;
    }

    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
    {
        OS_printf("APQS HMAC: EVP_MAC_CTX_new failed\n");
        EVP_MAC_free(mac);
        OSSL_LIB_CTX_free(ctx);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)digest_sha3_384, sizeof(digest_sha3_384)),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(mctx, key, key_len, params) != 1)
    {
        OS_printf("APQS HMAC: EVP_MAC_init failed\n");
        hmac_ctx_cleanup(ctx, mac, mctx);
        return -1;
    }

    for (size_t i = 0; i < num_parts; i++)
    {
        if (EVP_MAC_update(mctx, parts[i].data, parts[i].len) != 1)
        {
            OS_printf("APQS HMAC: EVP_MAC_update failed\n");
            hmac_ctx_cleanup(ctx, mac, mctx);
            return -1;
        }
    }

    size_t out_len;
    if (EVP_MAC_final(mctx, tag_out, &out_len, HMAC_SHA3_384_TAG_LENGTH) != 1)
    {
        OS_printf("APQS HMAC: EVP_MAC_final failed\n");
        hmac_ctx_cleanup(ctx, mac, mctx);
        return -1;
    }
    assert(out_len == HMAC_SHA3_384_TAG_LENGTH);

    hmac_ctx_cleanup(ctx, mac, mctx);
    return 0;
}
