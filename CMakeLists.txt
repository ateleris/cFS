cmake_minimum_required(VERSION 3.21)
project(E2EQSS)

enable_testing()

message("call cfe config")
add_subdirectory(cfe)

# Standalone CryptoLib test build + CTest registration. Lives next to the
# embedded CryptoLib in apqs_lib, but must be included here so its targets
# and tests are registered in the root project (visible to VS / ctest).
include(${CMAKE_SOURCE_DIR}/libs/apqs_lib/cryptolib_tests.cmake)

# ---------------------------------------------------------------------------
# Register unit-test binaries with CTest so they appear in `ctest` and IDE Test
# Explorers. Only relevant in a unit-test build. These register binaries that
# live outside this (mission) build tree - the nested cFS per-arch build -
# which is why they are re-registered here rather than discovered
# automatically.
# ---------------------------------------------------------------------------
if (ENABLE_UNIT_TESTS)

    # apqs_app UT-Assert coverage testrunners. add_cfe_coverage_test() already
    # registers these, but in the nested per-arch build (native/<cpu>), a tree
    # IDE Test Explorers scanning this tree do not reach - so point at the built
    # testrunner binaries here.
    set(APQS_TEST_BINARIES
        apqs_app_spki apqs_app_pki apqs_app apqs_app_crypto apqs_app_init_trust 
        apqs_app_cert_exchange apqs_app_hs apqs_app_cert_renewal apqs_app_pem
    )
    set(APQS_UT_RUNNER_DIR "${CMAKE_BINARY_DIR}/native/default_cpu1/apps/apqs_app/unit-test")
    foreach(test_bin ${APQS_TEST_BINARIES})
        add_test(NAME ${test_bin}
            COMMAND "${APQS_UT_RUNNER_DIR}/coverage-apqs_app-${test_bin}-testrunner")
    endforeach()

    # -----------------------------------------------------------------------
    # apqs_app code-coverage report (lcov + genhtml).
    #
    # The coverage testrunners are already instrumented (--coverage, via the
    # generic-linux BSP + add_cfe_coverage_test). This target runs them and
    # produces a branch-coverage HTML report scoped to apqs_app's OWN source
    # (vendored nanopb under fsw/src/protobuf is excluded). Build it with:
    #     cmake --build <build> --target apqs_app_coverage
    # then open <build>/apqs_app_coverage/html/index.html
    # -----------------------------------------------------------------------
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)
    if (LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)

        set(APQS_ARCH_DIR "${CMAKE_BINARY_DIR}/native/default_cpu1")
        set(APQS_COV_DIR  "${CMAKE_BINARY_DIR}/apqs_app_coverage")
        set(APQS_GCDA_DIR "${APQS_ARCH_DIR}/apps/apqs_app/unit-test")

        execute_process(COMMAND ${LCOV_EXECUTABLE} --version
            OUTPUT_VARIABLE APQS_LCOV_VERSION_OUT ERROR_QUIET)
        string(REGEX MATCH "([0-9]+)\\.[0-9]+" APQS_LCOV_VERSION "${APQS_LCOV_VERSION_OUT}")
        if (CMAKE_MATCH_1 AND CMAKE_MATCH_1 GREATER_EQUAL 2)
            set(APQS_LCOV_RC --rc branch_coverage=1)
        else ()
            set(APQS_LCOV_RC --rc lcov_branch_coverage=1)
        endif ()

        add_custom_target(apqs_app_coverage
            COMMAND ${CMAKE_COMMAND} -E make_directory ${APQS_COV_DIR}
            # reset counters so each report reflects only this run
            COMMAND ${LCOV_EXECUTABLE} -q --directory ${APQS_GCDA_DIR} --zerocounters
            # run the apqs unit tests (generates .gcda)
            COMMAND ${CMAKE_CTEST_COMMAND} --test-dir ${APQS_ARCH_DIR} -R apqs_app --output-on-failure
            # capture coverage (includes unexecuted lines of the run files - no
            # separate --initial baseline needed since every instrumented unit
            # has a runner that executes)
            COMMAND ${LCOV_EXECUTABLE} -q --capture --directory ${APQS_GCDA_DIR}
                    ${APQS_LCOV_RC} --rc geninfo_unexecuted_blocks=1
                    -o ${APQS_COV_DIR}/total.info
            # keep only apqs_app's own source (vendored nanopb is never instrumented)
            COMMAND ${LCOV_EXECUTABLE} -q ${APQS_LCOV_RC}
                    --extract ${APQS_COV_DIR}/total.info "*/apps/apqs_app/fsw/src/*"
                    -o ${APQS_COV_DIR}/apqs_app.info
            COMMAND ${LCOV_EXECUTABLE} ${APQS_LCOV_RC} --summary ${APQS_COV_DIR}/apqs_app.info
            COMMAND ${GENHTML_EXECUTABLE} -q ${APQS_COV_DIR}/apqs_app.info
                    --branch-coverage -o ${APQS_COV_DIR}/html
            COMMAND ${CMAKE_COMMAND} -E echo "apqs_app coverage report: ${APQS_COV_DIR}/html/index.html"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating apqs_app code-coverage report (lcov)"
            USES_TERMINAL
            VERBATIM
        )

        # Ensure the instrumented testrunners are built/installed first. The
        # runners live in the nested arch build, only reachable here via the
        # mission-install aggregate target.
        if (TARGET mission-install)
            add_dependencies(apqs_app_coverage mission-install)
        endif ()

    else ()
        set(APQS_COV_MISSING "")
        if (NOT LCOV_EXECUTABLE)
            list(APPEND APQS_COV_MISSING "lcov")
        endif ()
        if (NOT GENHTML_EXECUTABLE)
            list(APPEND APQS_COV_MISSING "genhtml")
        endif ()
        string(REPLACE ";" ", " APQS_COV_MISSING "${APQS_COV_MISSING}")
        message(WARNING
            "Code coverage for apqs_app not available: required tool(s) not found on PATH: "
            "${APQS_COV_MISSING}. Install the 'lcov' package (provides both lcov and genhtml) "
            "and re-configure to enable the 'apqs_app_coverage' target.")
    endif ()

endif ()
