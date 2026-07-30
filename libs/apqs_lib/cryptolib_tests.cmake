# ---------------------------------------------------------------------------
# Standalone CryptoLib test build + CTest registration.
#
# CryptoLib is embedded in apqs_lib (see CMakeLists.txt in this directory), so
# its test scaffolding lives here too. This file is include()d from the root
# CMakeLists.txt ON PURPOSE: it must run in the root project scope so that the
# custom targets and add_test() registrations are visible to VS26 / IDE Test
# Explorers and a root-level `ctest` run. It would not work from this
# directory's CMakeLists.txt, which is only processed inside the nested
# per-arch build.
# ---------------------------------------------------------------------------

# Set path to standalone CryptoLib source
set(CRYPTOLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/3rd/cryptolib)
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

# Register the standalone test binaries with CTest so they appear in `ctest`
# and IDE Test Explorers. They live outside this (mission) build tree, which is
# why they are re-registered here rather than discovered automatically.
if (ENABLE_UNIT_TESTS)
    set(CRYPTOLIB_TEST_BINARIES
        ut_aes_gcm_siv ut_aos_apply ut_aos_process ut_crypto ut_crypto_config
        ut_ep_key_mgmt ut_ep_mc ut_ep_sa_mgmt ut_sa_save
        ut_tc_apply ut_tc_process ut_tm_apply ut_tm_process
    )
    foreach(test_bin ${CRYPTOLIB_TEST_BINARIES})
        add_test(NAME ${test_bin} COMMAND "${CRYPTOLIB_TEST_EXE}/${test_bin}")
    endforeach()
endif ()
