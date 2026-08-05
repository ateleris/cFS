#include "apqs_cfs_init.h"

#include <apqs/keystore.h>

#include <stdio.h>
#include <string.h>

/*
** OSAL-backed key store for the APQS core.
**
** The core names key material by role; this is where roles become files. The
** layout is the one the app used before the split, so an existing /cf/pki
** carries over unchanged:
**
**   sat.pem             private key + certificate + chain, the active material
**   sat_new.pem         renewal candidate, staged but not yet active
**   sat_old.pem         previous material, retained until the new one is proven
**   mcs.pem             peer certificate + chain
**   ca_cert.pem         trust anchor installed by init_trust
**   pss_sat.bin         pre-shared secret
**   renewal_state.bin   opaque to this file; the core owns its format
**
** Nothing here decides when an item is written or which one becomes active.
** That sequencing, and the recovery that repairs an interrupted swap, is in the
** core (<apqs/keystore.h>) where it is reviewed once instead of per host. What
** this file owes the core is the atomicity those rules assume: after a power
** loss an item is entirely its old value or entirely its new one.
*/

#define APQS_KEYSTORE_DIR "/cf/pki"

// One staging file for every write. Safe because the library is single
// threaded, and it must be short: OS_MAX_FILE_NAME is 20, so "<target>.tmp"
// would overflow for the longer names above.
#define APQS_KEYSTORE_TMP APQS_KEYSTORE_DIR "/apqs.tmp"

static const char *const APQS_CFS_KeystorePaths[APQS_KEY_COUNT] = {
    [APQS_KEY_SAT]           = APQS_KEYSTORE_DIR "/sat.pem",
    [APQS_KEY_SAT_STAGED]    = APQS_KEYSTORE_DIR "/sat_new.pem",
    [APQS_KEY_SAT_ROLLBACK]  = APQS_KEYSTORE_DIR "/sat_old.pem",
    [APQS_KEY_MCS]           = APQS_KEYSTORE_DIR "/mcs.pem",
    [APQS_KEY_CA]            = APQS_KEYSTORE_DIR "/ca_cert.pem",
    [APQS_KEY_PSS]           = APQS_KEYSTORE_DIR "/pss_sat.bin",
    [APQS_KEY_RENEWAL_STATE] = APQS_KEYSTORE_DIR "/renewal_state.bin",
};

static const char *APQS_CFS_KeystorePath(apqs_key_id_t id)
{
    if ((unsigned)id >= APQS_KEY_COUNT)
    {
        return NULL;
    }
    return APQS_CFS_KeystorePaths[id];
}

static bool APQS_CFS_KeystoreVpathExists(const char *vpath)
{
    os_fstat_t st;
    return vpath != NULL && OS_stat(vpath, &st) == OS_SUCCESS;
}

static bool APQS_CFS_KeystoreHas(apqs_key_id_t id)
{
    return APQS_CFS_KeystoreVpathExists(APQS_CFS_KeystorePath(id));
}

static int APQS_CFS_KeystoreGet(apqs_key_id_t id, uint8_t *buf, size_t cap, size_t *out_len)
{
    const char *vpath = APQS_CFS_KeystorePath(id);
    os_fstat_t  st;

    if (vpath == NULL || OS_stat(vpath, &st) != OS_SUCCESS)
    {
        return -1;
    }

    /*
    ** Refuse a short read rather than hand back a truncated certificate. Reading
    ** cap bytes and reporting success would leave the caller parsing a prefix,
    ** which fails somewhere far less obvious than here.
    */
    if ((size_t)OS_FILESTAT_SIZE(st) > cap)
    {
        OS_printf("APQS keystore: %s is %lu bytes, buffer holds %lu\n", vpath, (unsigned long)OS_FILESTAT_SIZE(st),
                  (unsigned long)cap);
        return -1;
    }

    osal_id_t fd;
    if (OS_OpenCreate(&fd, vpath, OS_FILE_FLAG_NONE, OS_READ_ONLY) != OS_SUCCESS)
    {
        return -1;
    }

    int32 bytes_read = OS_read(fd, buf, cap);
    OS_close(fd);

    if (bytes_read < 0)
    {
        OS_printf("APQS keystore: read %s failed (rc=%ld)\n", vpath, (long)bytes_read);
        return -1;
    }

    *out_len = (size_t)bytes_read;
    return 0;
}

// Write to a staging file in the same directory, then rename over the target.
// The rename is the atomic step: readers see the old item until it completes.
static int APQS_CFS_KeystorePut(apqs_key_id_t id, const uint8_t *buf, size_t len)
{
    const char *vpath = APQS_CFS_KeystorePath(id);

    if (vpath == NULL)
    {
        return -1;
    }

    osal_id_t fd;
    if (OS_OpenCreate(&fd, APQS_KEYSTORE_TMP, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY) != OS_SUCCESS)
    {
        OS_printf("APQS keystore: create %s failed\n", APQS_KEYSTORE_TMP);
        return -1;
    }

    int32 written = OS_write(fd, buf, len);
    OS_close(fd);

    if (written != (int32)len)
    {
        OS_printf("APQS keystore: write %s failed (wrote=%ld, expected=%lu)\n", APQS_KEYSTORE_TMP, (long)written,
                  (unsigned long)len);
        OS_remove(APQS_KEYSTORE_TMP);
        return -1;
    }

    if (OS_rename(APQS_KEYSTORE_TMP, vpath) != OS_SUCCESS)
    {
        /*
        ** OS_rename does not replace an existing target on every OSAL port. Drop
        ** it and retry, which costs the atomicity of this one write: a power
        ** loss in the gap leaves the item absent rather than old-or-new. Ports
        ** whose rename overwrites - POSIX and RTEMS, so flight and ground both -
        ** never reach this path.
        */
        OS_remove(vpath);
        if (OS_rename(APQS_KEYSTORE_TMP, vpath) != OS_SUCCESS)
        {
            OS_printf("APQS keystore: rename %s -> %s failed\n", APQS_KEYSTORE_TMP, vpath);
            OS_remove(APQS_KEYSTORE_TMP);
            return -1;
        }
    }

    return 0;
}

static int APQS_CFS_KeystoreErase(apqs_key_id_t id)
{
    const char *vpath = APQS_CFS_KeystorePath(id);
    return (vpath != NULL && OS_remove(vpath) == OS_SUCCESS) ? 0 : -1;
}

static int APQS_CFS_KeystoreMove(apqs_key_id_t from, apqs_key_id_t to)
{
    const char *from_vpath = APQS_CFS_KeystorePath(from);
    const char *to_vpath   = APQS_CFS_KeystorePath(to);

    if (from_vpath == NULL || to_vpath == NULL)
    {
        return -1;
    }

    if (OS_rename(from_vpath, to_vpath) == OS_SUCCESS)
    {
        return 0;
    }

    // Same non-overwriting-rename caveat as the write path above. The core's
    // activation sequence always erases or vacates the destination first, so
    // this fallback is for ports that need it, not for normal operation.
    if (APQS_CFS_KeystoreVpathExists(to_vpath))
    {
        OS_remove(to_vpath);
        if (OS_rename(from_vpath, to_vpath) == OS_SUCCESS)
        {
            return 0;
        }
    }

    OS_printf("APQS keystore: rename %s -> %s failed\n", from_vpath, to_vpath);
    return -1;
}

static const apqs_keystore_ops_t APQS_CFS_KeystoreOps = {
    .get   = APQS_CFS_KeystoreGet,
    .put   = APQS_CFS_KeystorePut,
    .has   = APQS_CFS_KeystoreHas,
    .erase = APQS_CFS_KeystoreErase,
    .move  = APQS_CFS_KeystoreMove,
};

void APQS_CFS_KeystoreInit(void)
{
    /*
    ** Create the directory the table above points into. This is the one piece
    ** of store setup the core cannot do: it knows items by role and has no
    ** concept of a directory to create them in.
    **
    ** A failure here is not fatal on its own - the core reports an empty store
    ** and the app comes up unprovisioned - so the ops are installed either way
    ** and the first real access produces the specific error.
    */
    if (!APQS_CFS_KeystoreVpathExists(APQS_KEYSTORE_DIR))
    {
        int32 status = OS_mkdir(APQS_KEYSTORE_DIR, OS_READ_WRITE);
        if (status != OS_SUCCESS)
        {
            OS_printf("APQS keystore: mkdir %s failed (rc=%ld)\n", APQS_KEYSTORE_DIR, (long)status);
        }
    }

    // A staging file left by a write that lost power is stale by definition:
    // its target either took the rename or never saw it.
    OS_remove(APQS_KEYSTORE_TMP);

    apqs_keystore_set_ops(&APQS_CFS_KeystoreOps);
}
