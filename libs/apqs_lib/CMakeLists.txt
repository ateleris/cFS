project(apqs_lib C)

# Embed CryptoLib as a private static library. CRYPTOLIB_EMBEDDED makes
# cryptolib's own build produce a static PIC library (nasa_cryptolib) instead
# of registering a separate, globally loadable cFE module via add_cfe_app.
set(CRYPTOLIB_EMBEDDED ON)
add_subdirectory(3rd/cryptolib)
add_subdirectory(3rd/protobuf)

# Collect source files
set(APQS_SOURCES
   src/apqs_api.c
   src/apqs_cert_exchange.c
   src/apqs_cert_renewal.c
   src/apqs_crypto.c
   src/apqs_event.c
   src/apqs_handshake.c
   src/apqs_init_trust.c
   src/apqs_pem.c
   src/apqs_spki.c
   
   # TODO add guard - only when CFS is involved
   src/apqs_cfs_init.c
)

# Create the app module
add_cfe_app(apqs_lib ${APQS_SOURCES})

# Public headers
target_sources(apqs_lib
    PUBLIC
        include/apqs_api.h
        include/apqs_event.h
        include/apqs_sdls_types.h
    PRIVATE 
        include/apqs_cfs_init.h
)

target_include_directories(apqs_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_cfe_app_dependency(apqs_lib ossl_lib)

if(NOT TARGET OpenSSL::Crypto)
  find_package(OpenSSL 3.6.3 EXACT REQUIRED)
endif()

# dependencies are only visible to apqs_lib - not to those who link it. problem with headers?
target_link_libraries(apqs_lib PRIVATE nasa_cryptolib apqs_protobuf OpenSSL::SSL OpenSSL::Crypto)
