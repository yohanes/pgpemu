/*** encryption and certification ***/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgp-cert.h"
#include "secrets.h"

#ifdef ESP_PLATFORM

#include "esp_log.h"

void pgp_aes_encrypt(AES_Context *ctx, const uint8_t *inp, uint8_t *out)
{
	esp_aes_crypt_ecb(ctx, ESP_AES_ENCRYPT, inp, out);
}

void aes_setkey(AES_Context *ctx, const uint8_t *key)
{
	esp_aes_init( ctx );
	esp_aes_setkey(ctx, key, 128);
}

#else

#include <assert.h>
#include <stdint.h>



void pgp_aes_encrypt(AES_Context *ctx, const uint8_t *inp, uint8_t *out)
{
	memcpy(out, inp, 16);
	AES_ECB_encrypt(ctx, out);
}

void aes_setkey(AES_Context *ctx, const uint8_t *key)
{
	AES_init_ctx(ctx, key);	
}


#endif


uint8_t flash_data[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};



void hexdump(const char *msg, const uint8_t *data, int len)
{
#ifdef ESP_PLATFORM
        ESP_LOGI("PGPEMU", "%s", msg);	
        esp_log_buffer_hex("PGPEMU", data, len);	
#else	
	if (msg) {
		printf("%s", msg);
	}
	for (int i = 0; i < len; i++) {
		if ((i%16) == 0 && i>0) {
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
#endif	
}


void init_nonce_hash(const uint8_t *inp_nonce,
		     const int datalen,
		     uint8_t *nonce_hash)
{
	memcpy(nonce_hash+1, inp_nonce, 13);

	nonce_hash[0] = 57;
	nonce_hash[14] = (datalen>>8) & 0xff;	
	nonce_hash[15] = datalen & 0xff;
}


/**
 * iv is 16 bytes
 */
void aes_hash(AES_Context *ctx,
	      const uint8_t *nonce,
	      const uint8_t *data,
	      const int count,
	      uint8_t *output)
{
	uint8_t tmp[16];
	uint8_t tmp2[16];
	uint8_t nonce_hash[16];	

	init_nonce_hash(nonce, count, nonce_hash);
	
	pgp_aes_encrypt(ctx, nonce_hash, tmp); //encrypt nonce
	int blocks = count/16;
	const uint8_t *tmpdata = data;
	for (int i =0; i < blocks; i++) {
		for (int j = 0; j < 16; j++) { //xor with input
			tmp[j] ^= tmpdata[j];
		}
		tmpdata += 16;
		memcpy(tmp2, tmp, 16);	//copy to temp
		pgp_aes_encrypt(ctx, tmp2, tmp);

	}
	memcpy(output, tmp, 16);
}

void init_nonce_ctr(const uint8_t *inp_nonce, uint8_t *nonce_ctr)
{
	memcpy(nonce_ctr+1, inp_nonce, 13);
	nonce_ctr[0] = 1;
	nonce_ctr[14] = 0;
	nonce_ctr[15] = 0;
}


void encrypt_block(AES_Context *ctx,
		   const uint8_t *nonce_iv,
		   const uint8_t *nonce,
		   uint8_t *output)
{
	uint8_t tmp[16];

	uint8_t nonce_ctr[16];

	init_nonce_ctr(nonce, nonce_ctr);

	pgp_aes_encrypt(ctx, nonce_ctr, tmp);
	
	for (int i = 0; i < 16; i++) {
		output[i] = tmp[i] ^ nonce_iv[i];
	}
}



void inc_ctr(uint8_t * ctr)
{
	ctr[15]++;
	if (ctr[15] == 0) {
		ctr[14]++;
	}
}


void aes_ctr(AES_Context *ctx, const uint8_t *nonce,
	     const uint8_t *data, int count,
	     uint8_t *output)
{
	uint8_t ctr[16];
	uint8_t ectr[16];

	init_nonce_ctr(nonce, ctr);
	
	int blocks = count/16;
	const uint8_t *tmpdata = data;
	uint8_t *outptr = output;

	for (int i = 0; i < blocks; i++) {
		inc_ctr(ctr);
		pgp_aes_encrypt(ctx, ctr, ectr);
		
		for (int j = 0; j < 16; j++) {
			*outptr = ectr[j] ^ *tmpdata;
			++outptr;
			++tmpdata;
		}
	}
}

void generate_nonce(uint8_t *nonce)
{
	for (int i =0; i < 16; i++) {
		//random quality is not important
		nonce[i] = GEN_RANDOM() & 0xff;
	}
}

void generate_chal_0(const uint8_t *mac,
		     const uint8_t *the_challenge,
		     const uint8_t *main_nonce,
		     const uint8_t *main_key,		     
		     const uint8_t *outer_nonce,
		     struct challenge_data *output)
{
	uint8_t revmac[6];
	uint8_t tmp_hash[16];
	AES_Context ctx;
	
	struct main_challenge_data main_data;
	//mac will be reversed	
	for (int i = 0; i < 6; i++) {
		revmac[i] = mac[5-i];
	}
	memcpy(main_data.bt_addr, revmac, 6);
	memcpy(main_data.key, main_key, 16);
	memcpy(main_data.nonce, main_nonce, 16);
	memcpy(main_data.flash_data, flash_data, 10);
	
	aes_setkey(&ctx, main_key);
	aes_ctr(&ctx, main_data.nonce, the_challenge, 16, 
		main_data.encrypted_challenge);
	aes_hash(&ctx, main_data.nonce, the_challenge, 16, tmp_hash);
	encrypt_block(&ctx, tmp_hash, main_data.nonce, main_data.encrypted_hash);
	
	//outer layer
	memset(output->state, 0, 4);
	memcpy(output->nonce, outer_nonce, 16);
	memcpy(output->bt_addr, revmac, 6);
	memcpy(output->blob, BLOB, 256);

	aes_setkey(&ctx, DEVICE_KEY);
	aes_hash(&ctx, output->nonce, (uint8_t *)&main_data, 80, tmp_hash);
	encrypt_block(&ctx, tmp_hash, output->nonce, output->encrypted_hash);
	aes_ctr(&ctx, output->nonce, (uint8_t *)&main_data, 80, 
		output->encrypted_main_challenge);
	
}

void generate_next_chal(const uint8_t *indata, const uint8_t *key, const uint8_t *nonce, struct next_challenge *output)
{
	AES_Context ctx;	
	uint8_t data[16];
	uint8_t tmp_hash[16];

	if (indata) {
		memcpy(data, indata, 16);
	} else {
		memset(data, 0, 16);
		data[0] = 0xaa;
	}

	memcpy(output->nonce, nonce, 16);

	aes_setkey(&ctx, key);
	aes_ctr(&ctx, output->nonce, data, 16, output->encrypted_challenge);

	aes_hash(&ctx, output->nonce, data, 16, tmp_hash);
	encrypt_block(&ctx, tmp_hash, output->nonce, output->encrypted_hash);	
}


int decrypt_next(const uint8_t *data, const uint8_t *key, uint8_t *output)
{
	AES_Context ctx;

	const struct next_challenge *chal;
	aes_setkey(&ctx, key);
	chal = (const struct next_challenge *)data;
	aes_ctr(&ctx, chal->nonce, chal->encrypted_challenge, 16, output);

	hexdump("CHAL 2:", output, 16); //this is sent to APP
	
	uint8_t enc_nonce[16];
	memset(enc_nonce, 0, 16);	
	encrypt_block(&ctx, chal->encrypted_hash, chal->nonce, enc_nonce);

	hexdump("Enc nonce :", enc_nonce, 16);

	uint8_t hash_1[16];	
	memset(hash_1, 0, 16);
	//test if hash is correct/same
	aes_hash(&ctx, chal->nonce, output, 16, hash_1);

	hexdump("Hash: ", hash_1, 16);
	return memcmp(hash_1, enc_nonce, 16) == 0;
}


void generate_reconnect_response(const uint8_t *key,
				 const uint8_t *challenge,
				 uint8_t *output)
{
	AES_Context ctx;
	aes_setkey(&ctx, key);
	pgp_aes_encrypt(&ctx, challenge, output);
	for (int i = 0; i < 16; i++) {
		output[i] ^= challenge[i+16];
	}
}
