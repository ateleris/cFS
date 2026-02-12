include(FetchContent)

FetchContent_Declare(
  openssl_cmake
  GIT_REPOSITORY	https://github.com/jimmy-park/openssl-cmake.git
  GIT_TAG			3.6.0
)
FetchContent_MakeAvailable(openssl_cmake)

# Create the app module
add_cfe_app(ossl_lib openssl_cfs_init.c)

target_link_libraries(ossl_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
