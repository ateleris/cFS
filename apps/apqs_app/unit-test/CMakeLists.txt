##################################################################
#
# Unit test build recipe for apqs_app.
#
# Follows the same convention as apps/cf: one <src>_tests.c per app
# source file, one <src>_stubs.c per source file under stubs/, wired
# through add_cfe_coverage_stubs / add_cfe_coverage_test.
#
# This covers the cFS app shell only - command dispatch, telemetry and
# the CFDP plumbing. Everything the app used to do itself now lives in
# the APQS core, which has its own Unity + CTest suite at
# libs/apqs_cfs_wrapper/apqs_lib/unit-test and needs no cFS tree.
#
##################################################################

# Stubs for apqs_app's own entry points, so a test can exercise one
# function while the rest of the app is inert. Auto-generatable with:
#   ../../osal/ut_assert/scripts/generate_stubs.pl ./unit-test/stubs fsw/src/*.h
add_cfe_coverage_stubs(apqs_app_internal
  stubs/apqs_app_stubs.c
  stubs/osal_extra_stubs.c

  # The APQS binding layer. At runtime these resolve out of apqs_lib.so; here
  # they let a test say what the library returned without linking any of it.
  stubs/apqs_cfs_stubs.c
)

# add_cfe_coverage_stubs() names the target it creates "coverage-<name>-stubs"
# (see cfe/cmake/arch_build.cmake); the bare module name is not a target, and
# configuring against it fails the whole arch build.
target_include_directories(coverage-apqs_app_internal-stubs PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CFE_APQS_APP_SOURCE_DIR}/fsw/src
  ${CFE_APQS_APP_SOURCE_DIR}/fsw/include

  # apqs_cfs_pki.h, and <apqs/errors.h> + <apqs/sizes.h> which it includes.
  # Headers only - the library itself is never linked into these tests.
  ${MISSION_SOURCE_DIR}/libs/apqs_cfs_wrapper
  ${MISSION_SOURCE_DIR}/libs/apqs_cfs_wrapper/apqs_lib/include
)

add_cfe_coverage_test(apqs_app apqs_app
  "apqs_app_tests.c"
  "${CFE_APQS_APP_SOURCE_DIR}/fsw/src/apqs_app.c"
)

target_link_libraries(coverage-apqs_app-apqs_app-testrunner
  coverage-apqs_app_internal-stubs
  ut_core_api_stubs
  ut_osapi_stubs
)
