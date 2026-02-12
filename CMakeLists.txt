cmake_minimum_required(VERSION 3.21)
project(E2EQSS)

enable_testing()

message("call cfe config")
add_subdirectory(cfe)

# Set path to standalone CryptoLib source
set(CRYPTOLIB_ROOT_DIR ${CMAKE_SOURCE_DIR}/libs/cryptolib)
# Set a build directory for standalone CryptoLib
set(CRYPTOLIB_TEST_BUILD_DIR ${CMAKE_BINARY_DIR}/cryptolib_build)
# Path to the external test binary, produced by your custom build target
set(CRYPTOLIB_TEST_EXE "${CRYPTOLIB_TEST_BUILD_DIR}/bin")

file(MAKE_DIRECTORY ${CRYPTOLIB_TEST_BUILD_DIR})

# Custom target to configure and build CryptoLib in standalone mode with tests
add_custom_target(build_cryptolib_tests
    COMMAND ${CMAKE_COMMAND} -S ${CRYPTOLIB_ROOT_DIR} -B ${CRYPTOLIB_TEST_BUILD_DIR} -DTEST=ON
    COMMAND ${CMAKE_COMMAND} --build ${CRYPTOLIB_TEST_BUILD_DIR} --target all
    WORKING_DIRECTORY ${CRYPTOLIB_TEST_BUILD_DIR}
    COMMENT "Building CryptoLib tests in standalone mode"
)

# Custom target to run the tests after building --> only if run as target instead of the test explorer
add_custom_target(run_cryptolib_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --test-dir ${CRYPTOLIB_TEST_BUILD_DIR}
    DEPENDS build_cryptolib_tests
    COMMENT "Running CryptoLib unit tests via CTest"
)

# get all test binaries
set(TEST_BINARIES
    ut_aes_gcm_siv
    ut_aos_apply
    ut_aos_process
    ut_crypto
    ut_crypto_config
    ut_ep_key_mgmt
    ut_ep_mc
    ut_ep_sa_mgmt
    ut_sa_save
    ut_tc_apply
    ut_tc_process
    ut_tm_apply
    ut_tm_process
)

# Register each as a CTest test
foreach(test_bin ${TEST_BINARIES})
    set(TEST_PATH "${CRYPTOLIB_TEST_EXE}/${test_bin}")
    add_test(NAME ${test_bin} COMMAND ${TEST_PATH})
endforeach()
