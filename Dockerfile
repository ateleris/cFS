# Multi-stage Dockerfile for cFS (Core Flight System) with Debug configuration
# Based on Ubuntu Noble 24.04 LTS to match WSL environment

# =============================================================================
# Stage 1: deps - Build dependencies including liboqs
# =============================================================================
FROM ubuntu:noble-20250127 AS deps

# Install build dependencies (excluding libssl-dev to avoid conflicts)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libgcrypt-dev \
        ca-certificates \
        perl \
        wget && \
    rm -rf /var/lib/apt/lists/*

# Build OpenSSL 3.6.3 from source. The version MUST match the
# find_package(OpenSSL 3.6.3 EXACT) requirement in the cFS build
# (libs/apqs_cfs_wrapper/apqs_lib, apps/apqs_app, libs/libossl_cfs_wrapper).
#
# A mismatch is not a build failure, which is what makes it easy to miss: the
# EXACT lookup simply fails, libossl_cfs_wrapper falls back to FetchContent and
# rebuilds OpenSSL from source into the build tree as a STATIC library. That
# costs a full OpenSSL build on every clean configure, silently overrides
# OPENSSL_USE_STATIC_LIBS=FALSE below, and links a private copy of libcrypto
# into every module that uses it instead of sharing the one installed here.
#
# Built shared so modules get DT_NEEDED on libcrypto.so.3 and the process holds
# a single copy of OpenSSL's global state (providers, error queue, RNG).
WORKDIR /build
RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-3.6.3/openssl-3.6.3.tar.gz && \
    tar xzf openssl-3.6.3.tar.gz && \
    cd openssl-3.6.3 && \
    ./Configure --prefix=/usr/local --libdir=lib --openssldir=/usr/local/ssl shared && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf openssl-3.6.3 openssl-3.6.3.tar.gz

# Build liboqs against the custom OpenSSL
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DOPENSSL_ROOT_DIR=/usr/local && \
    cmake --build liboqs/build --parallel 8 && \
    cmake --build liboqs/build --target install && \
    ldconfig

# Set OQS installation path for downstream builds
ENV OQS_INSTALL_PATH=/usr/local

# =============================================================================
# Stage 2: builder - Build cFS with Debug configuration
# =============================================================================
FROM deps AS builder

# Copy cFS source tree
WORKDIR /workspace/cFS
COPY . .

# Configure cFS with linux-gcc-debug preset
# Point CMake to use manually-built OpenSSL 3.6.3
ENV OPENSSL_ROOT_DIR=/usr/local
RUN cmake --preset linux-gcc-debug \
    -DOPENSSL_ROOT_DIR=/usr/local \
    -DOPENSSL_USE_STATIC_LIBS=FALSE

# Build the mission-install target
# This builds cFE, OSAL, PSP, all apps, and all libraries including CryptoLib
# Output goes to /root/.vs/cFS/bin/cpu1/ (matches Visual Studio convention)
RUN cmake --build build/linux-gcc-debug --target mission-install --parallel $(nproc)

# =============================================================================
# Stage 3: runtime - Production runtime image
# =============================================================================
FROM ubuntu:noble-20250127 AS runtime

# Install only runtime dependencies (excluding libssl3 - using custom OpenSSL)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgcrypt20 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy custom OpenSSL 3.6.3 libraries from deps stage
COPY --from=deps /usr/local/lib/libssl.so* /usr/local/lib/
COPY --from=deps /usr/local/lib/libcrypto.so* /usr/local/lib/

# Copy liboqs shared library from deps stage
COPY --from=deps /usr/local/lib/liboqs.so* /usr/local/lib/

# Ensure /usr/local/lib is searched before the system multiarch path.
# Minimal ubuntu:noble Docker images may not ship libc-bin's libc.conf
# (which normally adds /usr/local/lib), so we add it explicitly with a
# "00-" prefix so it sorts before x86_64-linux-gnu.conf alphabetically.
# LD_LIBRARY_PATH provides an additional runtime guarantee.
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-usr-local.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

# Create CF (CFDP) filestore directories for file transfer
RUN mkdir -p /cf/cf_tmp /cf/cf_fail /cf/upload

# Copy built cFS artifacts from builder stage
# The CMake install goes to /workspace/cFS/bin/cpu1 based on CMAKE_INSTALL_PREFIX
COPY --from=builder /workspace/cFS/bin/cpu1 /opt/cfs/bin/cpu1

# Set working directory to cFS binary location
WORKDIR /opt/cfs/bin/cpu1

# Expose UDP ports for cFS communication
# 1234: CI_LAB command ingestion port
# 1235: TO_LAB telemetry output port
EXPOSE 1234/udp
EXPOSE 1235/udp

# Run core-cpu1 executable
# This starts cFS with the configuration from cfe_es_startup.scr
CMD ["./core-cpu1"]
