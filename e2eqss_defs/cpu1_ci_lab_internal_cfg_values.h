/**
 * @file
 * Mission override for CI_LAB internal config values.
 *
 * Increases the ingest buffer from the default 4096 bytes to 8192 to
 * accommodate APQS handshake M1 messages (~5847 bytes), which contain
 * ML-KEM-768 key material and a post-quantum OCSP response.
 */
#pragma once

#define CI_LAB_PLATFORM_CFGVAL(x) CPU1_CI_LAB_PLATFORM_##x

/* Increased from default 4096 to fit APQS M1 (~5847 bytes: ML-KEM-768 keys + PQ OCSP response) */
#define CPU1_CI_LAB_PLATFORM_MAX_INGEST      8192

/* All other values match the defaults from default_ci_lab_internal_cfg_values.h */
#define CPU1_CI_LAB_PLATFORM_MAX_INGEST_PKTS         10
#define CPU1_CI_LAB_PLATFORM_SB_RECEIVE_TIMEOUT      500
#define CPU1_CI_LAB_PLATFORM_UPLINK_RECEIVE_TIMEOUT  OS_CHECK
#define CPU1_CI_LAB_PLATFORM_PIPE_DEPTH              32
