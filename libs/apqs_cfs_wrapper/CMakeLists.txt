# cFS binding for the framework-free APQS core.
#
# apqs_lib/ builds the `apqs` static library, which has no cFE/cFS knowledge.
# This directory is the only cFS-aware part. It registers the loadable cFE
# library module, provides the lib_apqs_init entry point named in
# cpu1_cfe_es_startup.scr, installs the cFS implementations of the core's
# facades (events, logging, key storage), and exports the cFS-facing
# API that ci_lab and to_lab call.

add_subdirectory(apqs_lib)


# Create the app module. The target name drives the module filename, so it must
# stay apqs_lib to match cpu1_cfe_es_startup.scr.
add_cfe_app(apqs_lib
    apqs_cfs_init.c
    apqs_cfs_api.c
    apqs_cfs_pki.c
    apqs_cfs_event.c
    apqs_cfs_log.c
    apqs_cfs_keystore.c
)

# Public headers: the only APQS headers cFS applications include. apqs_cfs_api.h
# is the SDLS surface (ci_lab, to_lab), apqs_cfs_pki.h the PKI/handshake
# lifecycle (apqs_app). They reach consumers through
# add_cfe_app_dependency(<app> apqs_lib), which copies this target's
# INTERFACE_INCLUDE_DIRECTORIES.
target_sources(apqs_lib
    PUBLIC
        apqs_cfs_api.h
        apqs_cfs_pki.h
    PRIVATE
        apqs_cfs_init.h
)

# PUBLIC: what applications compile against. apqs_cfs_api.h names CryptoLib
# types in its signatures, and apqs_cfs_pki.h re-exports the buffer sizes from
# <apqs/sizes.h>, so both of those directories come along.
#
# The cryptolib entry stays listed explicitly even though the apqs target now
# declares it PUBLIC itself. That covers this module's own compilation, but `apqs`
# is linked PRIVATE below, so nothing it exports reaches applications - and
# apqs_cfs_api.h names CryptoLib types, so applications need the directory too.
#
# That does put the rest of the core's headers within reach of applications,
# which the previous arrangement avoided. It is an acceptable trade because
# include-path hygiene was never the real boundary: exports.map is. A core
# header can be included, but every symbol behind it is local to apqs_lib.so, so
# reaching past apqs_cfs_*.h fails at link or load rather than working quietly.
#
# Every public APQS header now compiles standalone downstream. <apqs/handshake.h>
# and <apqs/pki.h> used to need the protobuf schema that stays PRIVATE below, so
# including either one from an application simply failed; the schema-typed
# declarations moved to apqs_lib/src/*_internal.h.
target_include_directories(apqs_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/apqs_lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/apqs_lib/3rd/cryptolib/include
)

# PRIVATE: nanopb is needed by apqs_cfs_pki.c, which decodes the handshake wire
# format, but by nothing downstream - apqs_cfs_pki.h names no protobuf types and
# gets the M2 buffer size by asking the library. Keeping it off the
# applications' compile line means the wire format cannot leak back into them
# through a stray include.
target_include_directories(apqs_lib PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/apqs_lib/3rd/protobuf
)

# No cFS module dependencies left here. CFDP moved out entirely: the library
# takes and returns bytes, and apqs_app owns reading files, issuing CF_TxFileCmd
# and everything else CF-shaped. There is no OpenSSL module either - it is built
# privately into this one, and its version banner lives in
# apqs_openssl_selftest().

# Make "private" actually private.
#
# Everything this module links is a static archive: libapqs.a, and through it
# OpenSSL, CryptoLib, nanopb and PQClean. Their objects are pulled into
# apqs_lib.so and, by default, their symbols are exported from it. cFE loads
# modules with RTLD_GLOBAL, so ~1300 OpenSSL symbols plus all of CryptoLib and
# the core's own apqs_*/pki_*/handshake_* internals would sit in the
# process-global namespace where any other module could bind to them.
#
# exports.map is the fix and doubles as the module's API contract: everything
# not named there is local.
#
# Chosen over --exclude-libs,ALL for two reasons. It covers symbols from objects
# compiled directly into this module, not only those arriving from archives, so
# a helper added to a wrapper .c file stays private by default. And it fails
# loudly on a toolchain that does not support it, rather than being silently
# ignored and quietly dropping the boundary - which is the right failure mode
# for this, and why there is deliberately no compiler-ID guard here.
#
# LINK_DEPENDS is what makes edits to the map trigger a relink; CMake does not
# track linker scripts as dependencies on its own.
target_link_options(apqs_lib PRIVATE
    "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
set_target_properties(apqs_lib PROPERTIES
    LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/exports.map)

# PRIVATE: the core is an implementation detail of this module. Applications
# link nothing here, they resolve the APQS_CFS_* symbols out of apqs_lib.so at
# load time, and those are all defined in apqs_cfs_api.c above. Every core
# function the module needs is reached through a reference in one of these
# translation units, so the linker retains the archive members on its own and
# no whole-archive linkage is required.
target_link_libraries(apqs_lib PRIVATE apqs)
