#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <handshake.pb.h>

#define HANDSHAKE_SUCCESS 0
#define HANDSHAKE_ERROR 1

#define SHARED_SECRET_LENGTH 32
#define ECDH_KEY_LENGTH 32
#define ML_KEM_768_CIPHER_LENGTH 1088

int handshake_init(void);
int handshake_load_keys(void);
void handshake_reset_keys(bool reset_session_key);

int handshake_rekey_pb(handshake_HandshakeRequest* hs_request, 
    uint8_t* hs_response_msg, 
    size_t* out_encoded_size);

int handshake_key_conf_pb(handshake_HandshakeKeyConfirmation* hs_key_conf);

int handshake_set_session_key(void);
int handshake_simulate_sdls_ep_commands(void);

void handshake_handle_cfdp_file(const char *filepath, uint32_t fsize, uint32_t txn_stat);
void send_file_via_cfdp(const char* src_filename, const char* dst_filename);
