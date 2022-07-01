#include <stdio.h>
#include "endefile.h"

int main(){

	uint32_t cipher_id =  EDGE_CIPHER_ID_SEED128;
			
	uint8_t key[16] = { 0x00, };
	uint32_t keylength = 16;
					
	uint8_t hex_key[32] = { 0x00, };
	uint32_t hex_key_len = 0;

	int res = 0;

	res = edge_crypto_init(NULL);
	if(res != 0){
		printf("Err Code : %d\n", res);
		return res;
	}

	edge_random_byte(key, keylength);
	
	dataToHex(key, keylength, hex_key, &hex_key_len);
				
	res = EncryptandDecrypt(hex_key, cipher_id);
	if(res != CONVERT_OK){
		printf("Err Code : %d\n", res);
		return res;
	}
						
	edge_crypto_final();	

	return CONVERT_OK;
								
}
