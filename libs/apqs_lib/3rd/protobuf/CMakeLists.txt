project(apqs_protobuf C)

# nanopb runtime plus the generated message code (.pb.c). Built as a static
# library to be linked privately into the parent module (apqs_lib), so it is
# not loadable on its own. PIC is required because the parent is a
# dynamically loaded cFE module.
set(PROTOBUF_SRC_FILES
    pb_encode.c
    pb_decode.c
    pb_common.c
    handshake.pb.c
    pki.pb.c
)

add_library(apqs_protobuf STATIC ${PROTOBUF_SRC_FILES})
set_target_properties(apqs_protobuf PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

# Headers (pb.h, pb_encode.h, *.pb.h) live next to the sources; PUBLIC so the
# linking parent can include them.
target_include_directories(apqs_protobuf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
