cmake_minimum_required(VERSION 3.21)
project(E2EQSS)

enable_testing()

message("call cfe config")
add_subdirectory(cfe)

# ---------------------------------------------------------------------------
# Register unit-test binaries with CTest so they appear in `ctest` and IDE Test
# Explorers. Only relevant in a unit-test build. These register binaries that
# live outside this (mission) build tree - the nested cFS per-arch build -
# which is why they are re-registered here rather than discovered
# automatically.
# ---------------------------------------------------------------------------
if (ENABLE_UNIT_TESTS)

    # Standalone CryptoLib test build + CTest registration. Lives next to the
    # embedded CryptoLib in the APQS core, but is included here so its targets
    # and tests land in the root project scope, where `ctest` and IDE Test
    # Explorers can see them.
    #
    # Inside the guard because it configures a nested CMake project and adds its
    # build to ALL. A cFS build that is not asking for tests should not pay for
    # either.
    include(${CMAKE_SOURCE_DIR}/libs/apqs_cfs_wrapper/apqs_lib/cryptolib_tests.cmake)

    # NOTE: the apqs_app UT-Assert testrunners that used to be registered here
    # are gone. The suite moved to the APQS core with the code it covers, and
    # now runs on Unity + CTest:
    #
    #   cmake --preset linux-gcc-debug   # in libs/apqs_cfs_wrapper/apqs_lib
    #   ctest --preset linux-gcc-debug
    #
    # It builds standalone, without a cFS tree, which is the point. Registering
    # it from here would require the nested per-arch build and put the cFS
    # dependency straight back.

    # -----------------------------------------------------------------------
    # The apqs_app lcov coverage target lived here. It captured .gcda from
    # native/default_cpu1/apps/apqs_app/unit-test and filtered on
    # */apps/apqs_app/fsw/src/*, both of which the move emptied out, so it now
    # reports on nothing.
    #
    # Coverage for the core belongs with the core's own suite. Unity does not
    # bring instrumentation of its own, so it needs --coverage on the apqs
    # target plus an lcov target in libs/apqs_cfs_wrapper/apqs_lib/unit-test.
    # Not yet wired up.
    # -----------------------------------------------------------------------


endif ()
