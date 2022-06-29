#include "edge_crypto.h"
#include "endefile.h"

int EncryptandDecrypt(uint8_t* hex_key, uint32_t cipher_id){
	
	int res = 0; 

	uint8_t iv[16] = { 0x00, };   
	uint32_t iv_len = 16;   

	uint8_t key[16] = { 0x00, }; 
	uint32_t key_len = 16;       
	
	uint8_t crypted[1024] = { 0x00, };
	uint32_t crypted_len = 0;
	
	uint32_t crypted_len_total = 0;
	
	uint8_t org[1024] = { 0x00, }; 
	uint32_t org_len = 0;
	
	FILE* orgFile = fopen("orgFile.txt", "r");
	FILE* encFile = fopen("encFile.txt", "wb");
	
	if(orgFile == NULL || encFile == NULL){
		
		printf("file open error\n");
		return -1;
	
	}
	
	void* ctx =  NULL;
	ctx = edge_ctx_new();

	EDGE_CIPHER_PARAMETERS param;

	//edge_random_byte(iv, iv_len);

	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = EDGE_CIPHER_MODE_CFB;
	param.m_padding = EDGE_CIPHER_PADDING_PKCS5;

	memcpy(param.m_modeparam.m_iv, iv, iv_len);
	param.m_modeparam.m_ivlength = iv_len;

	hexToData(hex_key, 32, key, &key_len);
	
	printf("key at EnDec Funtion : %s\n",key);

	printf("key len : %d\n",key_len);
		
	res = edge_enc_init(ctx, cipher_id, key, key_len, &param);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}

	while((org_len = fread(org, sizeof(uint8_t), 1024, orgFile)) != 0){
	
		//printf("org contents at EndeFunc : %s", org);

		res = edge_enc_update(ctx, org, org_len,crypted, &crypted_len);
		if(res != 0){
			printf("Error Code : %d\n", res);
			return res;
		}		
			
		fileWrite(crypted, encFile, crypted_len);		
		crypted_len_total += crypted_len;

		memset(org, 0, 1024);
		memset(crypted, 0, 1024);

	}
	printf("crypted_len_total at EndeFunction : %d\n", crypted_len_total);
	printf("crypted_len at EndeFunction : %d\n", crypted_len);	

	//crypted_len_total += crypted_len; /////////////////////////////////////

	res = edge_enc_final(ctx, crypted + org_len, &crypted_len);

//	res = edge_enc_final(ctx, crypted + crypted_len_total, &crypted_len);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}
	
	crypted_len_total += crypted_len;
	
	printf("crypted_len_total at EndeFunction : %d\n", crypted_len_total);
	printf("crypted_len at EndeFunction : %d\n", crypted_len);

	//fileWrite(crypted, encFile,crypted_len);
	fileWrite(crypted + org_len, encFile,crypted_len);
	//fileWrite(crypted + crypted_len_total, encFile,crypted_len);
	
	printf("enc Data at EndeFunc : %s\n", crypted  + org_len);

	fclose(orgFile);
	fclose(encFile);

	encFile = fopen("encFile.txt","rb");

	fileDec(encFile, &param, ctx, cipher_id, key, key_len);	

	printf("sdjkflsjflsjkflsjfklsdjfklsjflksjdlkjsljdflksjdf\n");

	edge_ctx_free(ctx);

	return CONVERT_OK;

}

int fileDec(FILE* encFile, EDGE_CIPHER_PARAMETERS* param, void* ctx, uint32_t cipher_id, uint8_t* key, uint32_t key_len){

	//FILE* encFile = fopen("encFile.txt", "rb");
        FILE* decFile = fopen("decFile.txt", "wa+");

	uint8_t cryped_data[1024] = { 0x00, };
	uint8_t decryped_data[1024] = { 0x00, };
	
	uint8_t Deckey[16] = { 0x00, };
	uint8_t Deckey_len = 16;
	
	uint32_t decrypted_len_total = 0;
	
	uint32_t read_len = 0;
	uint32_t dec_data_len = 0; 	
	uint32_t padding = 0;

	int res = 0;
	int i = 0;

	for(; i < key_len; i++){
		Deckey[i] = key[i];
	}

	printf("DecKey at DecFunction : %s\n", Deckey);
	
	if(encFile == NULL || decFile == NULL){
		printf("File open err\n");
		return -1;
	}
	
	printf("Key at Dec Function : %s\n", key);


	res = edge_dec_init(ctx, cipher_id, Deckey, Deckey_len, param);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}

	printf("======================================================================\n");

	while((read_len = fread(cryped_data,sizeof(uint8_t), 1024, encFile)) != 0){
		
		printf("Enc Contents at Dec Function %s\n",cryped_data);

		res = edge_dec_update(ctx,cryped_data,read_len,decryped_data,&dec_data_len);
		if(res != 0){
			printf("Error Code : %d\n", res);
			return res;
		}
		decrypted_len_total += dec_data_len;

	}
	printf("======================================================================\n");

	printf("decrypted_len_total at decFunction : %d\n", decrypted_len_total);
	printf("dec_data_len at decFunction : %d\n", dec_data_len);

	//decrypted_len_total += dec_data_len;
	
	res = edge_dec_final(ctx, NULL, NULL, &padding);

	//res = edge_dec_final(ctx, decryped_data + decrypted_len_total, &dec_data_len, &padding);
	//res = edge_dec_final(ctx, decryped_data, &dec_data_len, &padding);
	if(res != 0){
		printf("Error Code : %d\n", res);
		return res;
	}

	printf("dec_data_len at decFunction : %d\n", dec_data_len);
	printf("padding at decFunction : %d\n", padding);
	printf("======================================================================\n");

	decrypted_len_total += dec_data_len;

	fileWrite(decryped_data, decFile, decrypted_len_total - padding);

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
