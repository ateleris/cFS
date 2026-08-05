project(CFE_APQS_APP C)

# The PKI store and the handshake live in the APQS core, reached through
# apqs_cfs_pki.h. What is left here is the cFS app shell: command dispatch,
# telemetry, and the CFDP plumbing that carries APQS messages over the link.
set(APP_SRC_FILES
  fsw/src/apqs_app.c
)

# Create the app module
add_cfe_app(apqs_app ${APP_SRC_FILES})

target_include_directories(apqs_app PUBLIC fsw/include)
# generated nanopb code includes <pb.h>
#target_include_directories(apqs_app PRIVATE fsw/src/protobuf)

add_cfe_app_dependency(apqs_app cf)
add_cfe_app_dependency(apqs_app apqs_lib)

# No OpenSSL here. It is private to apqs_lib, and everything this app needs from
# it is reached through apqs_cfs_pki.h. Linking it directly used to pull a full
# private copy of libcrypto into apqs_app.so for the sake of one ML-DSA probe at
# startup, which has moved into the library.

# Seed the keystore so a fresh build comes up provisioned.
#
# The destination is the keystore's own directory, not a separate keys/ dir: the
# backend in apqs_cfs_keystore.c reads /cf/pki, and on pc-linux the PSP maps /cf
# to ./cf under the cpu1 exe directory (PSP_CONFIG_CF_VIRTUAL_MAPPING). The
# basenames must stay sat.pem and mcs.pem to match the backend's id-to-path
# table. This used to install to cpu1/keys/, which nothing has read since the
# loaders stopped taking paths.
#
# Note that re-running the install overwrites sat.pem with the factory key. If a
# certificate renewal has been exercised on that target, this discards its
# result - which is the intent for a dev target, but worth knowing before
# blaming the renewal.
install(FILES keys/sat.pem keys/mcs.pem DESTINATION cpu1/cf/pki)

# Unit tests. Only what covers the app shell lives here - command dispatch,
# telemetry, CFDP plumbing - on UT-Assert like apps/cf, because it needs a cFS
# tree to run at all. Everything covering the APQS core moved with the code it
# tests, to libs/apqs_cfs_wrapper/apqs_lib/unit-test, where it runs on Unity +
# CTest with no cFS at all.
#
# The app reaches APQS only through the APQS_CFS_* forwarders, which are stubbed
# in unit-test/stubs/apqs_cfs_stubs.c, so these tests need the wrapper's headers
# but never link the library.
if (ENABLE_UNIT_TESTS)
  add_subdirectory(unit-test)
endif (ENABLE_UNIT_TESTS)
