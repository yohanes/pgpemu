#ifndef PGP_CERT_H
#define PGP_CERT_H

#include <stdint.h>

#ifdef ESP_PLATFORM
#include "esp_system.h"
#include "hwcrypto/aes.h"

#define AES_Context esp_aes_context
#define GEN_RANDOM esp_random
#else
#include "aes.h"
#define AES_Context struct AES_ctx
#define GEN_RANDOM rand
#endif

struct main_challenge_data {
	uint8_t bt_addr[6];
	uint8_t key[16];
	uint8_t nonce[16];
	uint8_t encrypted_challenge[16];
	uint8_t encrypted_hash[16];
	uint8_t flash_data[10];
} __attribute__((packed)) ;

struct challenge_data {
	uint8_t state[4];
	uint8_t nonce[16];
	uint8_t encrypted_main_challenge[80];
	uint8_t encrypted_hash[16];
	uint8_t bt_addr[6];
	uint8_t blob[256];
}  __attribute__((packed));


struct next_challenge {
	uint8_t state[4];
	uint8_t nonce[16];
	uint8_t encrypted_challenge[16];
	uint8_t encrypted_hash[16];
} __attribute__((packed)) ;


void hexdump(const char *msg, const uint8_t *data, int len);
void aes_setkey(AES_Context *ctx, const uint8_t *key);

void aes_hash(AES_Context *ctx,
	      const uint8_t *nonce,
	      const uint8_t *data,
	      const int count,
	      uint8_t *output);

void aes_ctr(AES_Context *ctx,
	     const uint8_t *nonce,
	     const uint8_t *data,
	     int count,
	     uint8_t *output);

void encrypt_block(AES_Context *ctx,
		   const uint8_t *nonce_iv,
		   const uint8_t *nonce,
		   uint8_t *output);

void aes_ctr(AES_Context *ctx,
	     const uint8_t *nonce,
	     const uint8_t *data,
	     int count,
	     uint8_t *output);

void generate_nonce(uint8_t *nonce);
void generate_chal_0(const uint8_t *mac,
		     const uint8_t *the_challenge,
		     const uint8_t *main_nonce,
		     const uint8_t *main_key,		     
		     const uint8_t *outer_nonce,
		     struct challenge_data *output);

void generate_next_chal(const uint8_t *data, const uint8_t *key,
			const uint8_t *nonce,
			struct next_challenge *output);

void generate_reconnect_response(const uint8_t *key,
				 const uint8_t *challenge,
				 uint8_t *output);

int decrypt_next(const uint8_t *data, const uint8_t *key, uint8_t *output);
	

#endif
