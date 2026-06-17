include(FetchContent)

# Exactly 3.6.1 — must match the Dockerfile's source-built OpenSSL; older
# system versions (e.g. 3.0.x) lack the ML-DSA/ML-KEM support the PKI needs.
find_package(OpenSSL 3.6.1 EXACT)

if(NOT OpenSSL_FOUND)
  FetchContent_Declare(
    openssl_cmake
    GIT_REPOSITORY	https://github.com/jimmy-park/openssl-cmake.git
    GIT_TAG			3.6.1
  )
  FetchContent_MakeAvailable(openssl_cmake)
endif()

# Create the app module
add_cfe_app(ossl_lib openssl_cfs_init.c)

if(TARGET OpenSSL::SSL)
  target_link_libraries(ossl_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
elseif(OPENSSL_FOUND)
  target_link_libraries(ossl_lib PUBLIC ${OPENSSL_LIBRARIES})
  target_include_directories(ossl_lib PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
