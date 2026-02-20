include(FetchContent)

# Try to use system OpenSSL first
find_package(OpenSSL)

if(NOT OpenSSL_FOUND)
  FetchContent_Declare(
    openssl_cmake
    GIT_REPOSITORY	https://github.com/jimmy-park/openssl-cmake.git
    GIT_TAG			3.6.0
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
