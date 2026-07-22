project(apqs_lib C)

# Embed CryptoLib as a private static library. CRYPTOLIB_EMBEDDED makes
# cryptolib's own build produce a static PIC library (nasa_cryptolib) instead
# of registering a separate, globally loadable cFE module via add_cfe_app.
set(CRYPTOLIB_EMBEDDED ON)
add_subdirectory(cryptolib)

# Collect source files
set(APQS_SOURCES
   apqs_api.c
)

# Create the app module
add_cfe_app(apqs_lib
    apqs_cfs_init.c
    ${APQS_SOURCES}
)

# Public headers
target_sources(apqs_lib
    PUBLIC
        public_inc/apqs_api.h
        public_inc/apqs_sdls_types.h
    PRIVATE apqs_cfs_init.h
)

# Export headers to other modules. Only public_inc is exposed: the apqs API
# plus explicitly forwarded CryptoLib types (apqs_sdls_types.h). Exposing
# ${CMAKE_CURRENT_SOURCE_DIR} instead would let consumers reach the embedded
# cryptolib/ subfolder directly.
target_include_directories(apqs_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/public_inc
)

# PRIVATE: CryptoLib headers and symbols are only visible to apqs_lib itself,
# not to modules that link against apqs_lib
target_link_libraries(apqs_lib PRIVATE nasa_cryptolib)
