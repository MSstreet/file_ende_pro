#include <stdio.h>                                                                                                    
#include <stdlib.h>                                                                                                   
#include <stdint.h>                                                                                                   
#include <stddef.h>                                                                                                   
#include <string.h>
#include "edge_crypto.h"

#define		FILE_SIZE		1024

#define 	CONVERT_OK		1

#define		ERR			10000
#define		DATA_ERR		(ERR + 1)


int WriteKeyIv(char* key, int key_len, char* iv, int iv_len);
int fileWrite(char* data, FILE* fp, int data_len);
int EncryptandDecrypt(uint8_t* hex_key, uint32_t cipher_id); 
int dataToHex(uint8_t* inData, uint32_t input_len, uint8_t* outHex, uint32_t* out_len);
int hexchrTobin(const char hex, uint8_t *out);
int hexToData(uint8_t *InHex, uint32_t input_len, uint8_t* outData, uint32_t* out_len);
int fileDec(FILE* encFile, EDGE_CIPHER_PARAMETERS* param, void* ctx, uint32_t cipher_id, uint8_t* key, uint32_t key_len);
