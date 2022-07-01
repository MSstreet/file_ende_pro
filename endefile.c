#include "edge_crypto.h"
#include "endefile.h"

int EncryptandDecrypt(uint8_t* hex_key, uint32_t cipher_id){
	
	int res = 0; 

	uint8_t iv[16] = { 0x00, };   
	uint32_t iv_len = 16;   

	uint8_t key[16] = { 0x00, }; 
	uint32_t key_len = 16;       
	
	uint8_t crypted[FILE_SIZE] = { 0x00, };
	uint32_t crypted_len = 0;
	
	uint32_t crypted_len_total = 0;
	
	uint8_t org[FILE_SIZE] = { 0x00, }; 
	uint32_t org_len = 0;

	uint32_t f_size = 0;
	uint32_t f_check = 0;
	
	uint32_t tmp_len = 0;
	
	FILE* orgFile = fopen("orgFile.txt", "r");
	FILE* encFile = fopen("encFile.txt", "wb");
	
	if(orgFile == NULL || encFile == NULL){
		
		printf("file open error\n");
		return -1;
	
	}
	
	void* ctx =  NULL;
	ctx = edge_ctx_new();
	
	EDGE_CIPHER_PARAMETERS param;	
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));
	
	param.m_mode = EDGE_CIPHER_MODE_CFB;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	
	memcpy(param.m_modeparam.m_iv, iv, iv_len);
	param.m_modeparam.m_ivlength = iv_len;
	
	hexToData(hex_key, 32, key, &key_len);
	
	fseek(orgFile, 0, SEEK_END); 
	f_size = ftell(orgFile);  
	fseek(orgFile, 0, SEEK_SET);  

	res = edge_enc_init(ctx, cipher_id, key, key_len, &param);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}

	while((org_len = fread(org, sizeof(uint8_t), FILE_SIZE, orgFile)) != 0){

		if(FILE_SIZE >= f_size){ //less then 1024 
			
			res = edge_enc_update(ctx, org, org_len, crypted, &crypted_len);
			if(res != 0){
				printf("Error Code : %d\n", res);
				return res;
			}
			
			tmp_len = crypted_len;	

			res = edge_enc_final(ctx, crypted + tmp_len, &crypted_len);
			if(res != 0){
				printf("Error Code : %d\n", res);
				return res;
			}
			
			tmp_len += crypted_len;

			fileWrite(crypted, encFile, tmp_len); 		
			
		}
		
		else{ //more then 1024

			res = edge_enc_update(ctx, org, org_len, crypted, &crypted_len);
			if(res != 0){
				printf("Error Code : %d\n", res);
				return res;
			}
			
			fileWrite(crypted, encFile, crypted_len);

		}

		f_size -= org_len;

		memset(org, 0, FILE_SIZE);
		memset(crypted, 0, FILE_SIZE);	
	}
	
	fclose(orgFile); 
	fclose(encFile);

	encFile = fopen("encFile.txt","rb");  	
	
	fileDec(encFile, &param, ctx, cipher_id, key, key_len); 

	edge_ctx_free(ctx);

	return CONVERT_OK;

}

int fileDec(FILE* encFile, EDGE_CIPHER_PARAMETERS* param, void* ctx, uint32_t cipher_id, uint8_t* key, uint32_t key_len){
	
        FILE* decFile = fopen("decFile.txt", "wa+");

	uint8_t cryped_data[FILE_SIZE] = { 0x00, };
	uint8_t decryped_data[FILE_SIZE] = { 0x00, };
	
	uint8_t Deckey[16] = { 0x00, };
	uint8_t Deckey_len = 16;
	
	uint32_t decrypted_len_total = 0;
	
	uint32_t read_len = 0;
	uint32_t dec_data_len = 0; 	
	uint32_t padding = 0;
	
	uint32_t tmp_len = 0;

	uint32_t f_size = 0;
	
	int res = 0;
	int i = 0;

	if(encFile == NULL || decFile == NULL){
		printf("File open err\n");
		return -1;
	}

	for(; i < key_len; i++){
		Deckey[i] = key[i];
	}

	printf("DecKey at DecFunction : %s\n", Deckey);
		
	res = edge_dec_init(ctx, cipher_id, Deckey, Deckey_len, param);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}

	fseek(encFile, 0, SEEK_END);
	f_size = ftell(encFile);
	fseek(encFile, 0, SEEK_SET);
	
	while((read_len = fread(cryped_data,sizeof(uint8_t), FILE_SIZE, encFile)) != 0 ){

			
		//FILE_SIZE = 1024;
		if(FILE_SIZE >= f_size){ //less then 1024
			
			res = edge_dec_update(ctx, cryped_data, read_len, decryped_data,&dec_data_len);
			if(res != 0){
				printf("Error Code : %d\n", res);
				return res;
			}
			
                       tmp_len = dec_data_len;
			printf("padding at decfunc : %d\n",padding);
		       
		       res = edge_dec_final(ctx,decryped_data,&dec_data_len,&padding);
		       if(res != 0){
		       		printf("Error Code : %d\n", res);
				return res;
		       }
	  	

			printf("padding at decfunc : %d\n",padding); 

			fileWrite(decryped_data,decFile,tmp_len-padding);	       

		}
			
		else{ //more then 1024
					
			res = edge_dec_update(ctx, cryped_data, read_len, decryped_data,&dec_data_len);
			
			fileWrite(decryped_data, decFile, dec_data_len);		

			
		}

		f_size -= read_len;
				
		memset(cryped_data, 0, FILE_SIZE);
		memset(decryped_data, 0, FILE_SIZE);
	
	}

	fclose(encFile);
	fclose(decFile);
	
	return CONVERT_OK;

}

int dataToHex(uint8_t* inData, uint32_t input_len, uint8_t* outHex, uint32_t* out_len){

	if(inData == NULL) return DATA_ERR;

	int i = 0;

	for(; i <= input_len -1; i++){
	
		sprintf(outHex+2*i, "%02x", (unsigned char)*(inData+i));
		
	}
	
	*out_len = strlen(outHex);
	
	return CONVERT_OK; 

}

int hexchrTobin(const char hex, uint8_t* out){

	if (out == NULL)
		return 0;
	
	if (hex >= '0' && hex <= 'F'){
		*out = hex - '0';
	}
	else if (hex >= 'A' && hex <= 'F'){
		*out = hex - 'A' + 10;
	}
	else if (hex >= 'a' && hex <= 'f'){
		*out = hex - 'a' + 10;
	}
	else {
		return DATA_ERR;
	}
}

int hexToData(uint8_t *InHex, uint32_t input_len, uint8_t* outData, uint32_t* out_len){
	
	uint32_t size = input_len / 2 + 1;
	
	char b1;
	char b2;

	int i = 0;
	
	for(i = 0; i < input_len - 1; i++){

		if(!(InHex[i] >= 48 && InHex[i] <= 57)){
			if(!(InHex[i] >= 65 && InHex[i] <= 70)){
				if(!(InHex[i] >= 97 && InHex[i] <= 102)){
					return DATA_ERR;
				}
			}
		}
	
	}

	if(InHex == NULL) return DATA_ERR;
	if(input_len % 2 != 0) return DATA_ERR;

	*out_len = input_len /= 2;

	for(i = 0; i < *out_len; i++){
		if(!hexchrTobin(InHex[i * 2], &b1) || !hexchrTobin(InHex[i * 2 + 1], &b2)) { 
			return DATA_ERR;
		}	
	
		*(outData + i) = (b1 << 4) | b2;
	}
	
	*(outData + size - 1) = '\0';

	return CONVERT_OK;
	

}

int fileWrite (char* data, FILE* fp, int data_len){
	
	fwrite(data, data_len, 1, fp);

	return CONVERT_OK;
}
