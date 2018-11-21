#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pgp-cert.h"
#include "secrets.h"

#ifndef ESP_PLATFORM


//length must be 378 bytes
void test_decrypt_chal_0(const uint8_t *indata)
{

	printf("--------------- decrypt challenge ------------\n");
	/*

	  Generate main data (80 bytes)

	  Generate 16 bytes random key A
	  Generate 16 bytes challenge C
	  Generate 16 bytes nonce N
	  Generate nonce for AES-CTR (first byte 0, last 2 bytes 0) NE
	  Generate nonce for hashing (first byte 57, last 2 bytes is data length) NH

	  - encrypt the challenge C with the key A and nonce NE using AES-CTR
	  - hash the key using AES then xor with NH
	  
	  - send the key, nonce, encrypted challenge data, and encrypted hash
	 */

	struct challenge_data *challenge;
	struct main_challenge_data main_data;
	
	AES_Context ctx;

	uint8_t hash_1[16];
	uint8_t enc_nonce[16];	
	uint8_t the_challenge[16];

	challenge = (struct challenge_data*)indata;

	memset(&main_data, 0, sizeof(main_data));       
	
	//hexdump(data, 378);

	hexdump("Nonce: ", challenge->nonce, 16);
	hexdump("Enc data: \n", challenge->encrypted_main_challenge, 80);

	hexdump("Enc hash: \n", challenge->encrypted_hash, 16);
	
	aes_setkey(&ctx, DEVICE_KEY);

	aes_ctr(&ctx, challenge->nonce,
		challenge->encrypted_main_challenge,
		80,
		(uint8_t*)&main_data);
	

	//hexdump("Decrypted: ", (uint8_t*)&main_data, 80);
	hexdump("BT MAC: ", main_data.bt_addr, 6);	
	hexdump("Flash data: ", main_data.flash_data, 10);
	hexdump("Key: ", main_data.key, 16);

	memset(enc_nonce, 0, 16);	
	encrypt_block(&ctx, challenge->encrypted_hash, challenge->nonce, enc_nonce);
	hexdump("Encrypted nonce: ", enc_nonce, 16);
	
	memset(hash_1, 0, 16);
	//test if hash is correct/same
	aes_hash(&ctx, challenge->nonce, (uint8_t*)&main_data, 80, hash_1);

	hexdump("Hash: ", hash_1, 16);
      		       
	aes_setkey(&ctx, main_data.key);
	aes_ctr(&ctx, main_data.nonce, main_data.encrypted_challenge, 16, the_challenge);
	hexdump("Final: ", the_challenge, 16); //to be sent to PGP
}


void test_decrypt_chal_next(const uint8_t *data, const uint8_t *key)
{
	const struct next_challenge *chal;
	AES_Context ctx;
	uint8_t the_challenge[16];

	chal = (const struct next_challenge*)data;
	aes_setkey(&ctx, key);
	aes_ctr(&ctx, chal->nonce, chal->encrypted_challenge, 16, the_challenge);
	hexdump("CHAL 1: ", the_challenge, 16);

	uint8_t enc_nonce[16];
	memset(enc_nonce, 0, 16);	
	encrypt_block(&ctx, chal->encrypted_hash, chal->nonce, enc_nonce);
	hexdump("Enc Nonce: ", enc_nonce, 16);

	uint8_t hash_1[16];	
	memset(hash_1, 0, 16);
	//test if hash is correct/same
	aes_hash(&ctx, chal->nonce, the_challenge, 16, hash_1);

	hexdump("Hash: ", hash_1, 16);

	assert(memcmp(hash_1, enc_nonce, 16)==0);
}


void test_generate_chal_0()
{
	struct challenge_data output;
	uint8_t the_challenge[16];
	uint8_t outer_nonce[16];
	uint8_t mac[] = {0x98, 0xb6, 0xe9, 0x11, 0xe1, 0x46 };
	memset(the_challenge, 0x41, 16);

	uint8_t main_nonce[16];

	memset(main_nonce, 0x42, 16);
	
	uint8_t main_key[16];

	memset(main_key, 0x43, 16);	

	memset(outer_nonce, 0x44, 16);	
	
	generate_chal_0(mac, the_challenge, main_nonce, main_key, outer_nonce, &output);
	test_decrypt_chal_0((uint8_t*)&output); //test that this works using known data
	
}

void test_generate_chal_1()
{
	uint8_t nonce[16];
	uint8_t main_key[16];
	struct next_challenge output;

	memset(main_key, 0x43, 16);		
	memset(nonce, 0x42, 16);
	
	generate_next_chal(0, main_key, nonce, &output);
	printf("Test decrypt challenge 1");
	test_decrypt_chal_next((uint8_t*)&output, main_key);
}

int test()
{

	test_generate_chal_0(); //test generate and print output
	test_generate_chal_1();
	

	return 0;
}


int main(int argc, char *argv[])
{
	assert(sizeof(struct main_challenge_data)==80);
	assert(sizeof(struct challenge_data)==378);


	const char expected[] = {0x1b, 0x77, 0xbc, 0x98, 0xad, 0x03, 0x54, 0x7e, 0x00, 0x49, 0xfa, 0x67, 0x5a, 0x10, 0x47, 0xd0};
	uint8_t main_key[16];
	memset(main_key, 0x43, 16);			
	uint8_t reconnect_challenge[32];	
	memset(reconnect_challenge, 0x46, 32);
	uint8_t temp[16];
	generate_reconnect_response(main_key, reconnect_challenge, temp);
	hexdump("Reconnect ", temp, 16);
	assert(memcmp(temp, expected, 16)==0);
	
	return test();
}


#endif
