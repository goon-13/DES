#ifndef __DEA_H__
#define __DEA_H__

#include<stdint.h>

#define ENCRYPTION 1 /* 加密 */
#define DECRYPTION 0 /* 解密 */
#define DES_KEY_SIZE 8 /* DES 密钥长度 8 bytes */
#define DES_BLOCK_BYTE_NUM 8 /* DES每个分组长8B */
#define TRUE 1
#define FALSE 0

/* 加解密选项的参数，定义为extern */
extern char *key_file_name, *input_file_name, *output_file_name, *byte_padding_way, *mode_name, *initialization_vector_file_name;
extern uint8_t e_or_d;

void generate_key(char* key);
void desProcess();

#endif