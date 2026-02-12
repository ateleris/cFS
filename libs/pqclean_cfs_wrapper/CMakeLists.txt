# PQClean ML-KEM-768 wrapper for cFS

# Collect ML-KEM-768 source files
set(MLKEM768_SOURCES
    pqclean/ml-kem-768/cbd.c
    pqclean/ml-kem-768/indcpa.c
    pqclean/ml-kem-768/kem.c
    pqclean/ml-kem-768/ntt.c
    pqclean/ml-kem-768/poly.c
    pqclean/ml-kem-768/polyvec.c
    pqclean/ml-kem-768/reduce.c
    pqclean/ml-kem-768/symmetric-shake.c
    pqclean/ml-kem-768/verify.c
)

# Collect common dependencies
set(COMMON_SOURCES
    pqclean/common/fips202.c
    pqclean/common/sha2.c
    pqclean/common/aes.c
    pqclean/common/sp800-185.c
)

# Create the app module
add_cfe_app(pqclean_lib
    pqclean_cfs_init.c
    ${MLKEM768_SOURCES}
    ${COMMON_SOURCES}
)

# We need to provide randombytes implementation
# Check if the system provides one, otherwise use a default implementation
target_sources(pqclean_lib PRIVATE
    pqclean/common/randombytes.c
)

# Add include directories for PQClean
target_include_directories(pqclean_lib PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/ml-kem-768
    ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/common
)

# Public headers
target_sources(pqclean_lib
    PUBLIC pqclean_fwd.h
    PRIVATE pqclean_cfs_init.h
)

# Export headers to other modules
target_include_directories(pqclean_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
