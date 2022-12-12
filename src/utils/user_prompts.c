#include<stdio.h>
#include<stdlib.h>
#include<conio.h>

#include "common.h"
#include "user_prompts.h"

/**
  * @brief  用户未输入参数给出提示
  * @param  无
  * @retval y返回1,n返回0
  */
void user_prompt_usage() {
    printf("Usage:\n");
    printf("\t./DES.exe [-g key_file_name]\n");
    printf("\t          [-e key_file_name plaintext_file_name encrypted_ciphertext_file_name] [byte_padding_way] [mode_name] [initialization_vector_file_name]\n");
    printf("\t          [-d key_file_name ciphertext_file_name decrypted_plaintext_file_name] [byte_padding_way] [mode_name] [initialization_vector_file_name]\n");
    printf("\t          [-c file_name]\n");
    printf("Options:\n");
    printf("\t-g key_file_name                                                               Generate the key to the specified file\n\n");
    printf("\t-e key_file_name                                                               Encrypt\n");
    printf("\t   plaintext_file_name                                                          [mode_name]:DES operating mode. If not specified, it defaults to ECB.\n");
    printf("\t   encrypted_ciphertext_file_name                                                   Value can be: ECB(ecb) | CBC(cbc) | OFB(ofb) | CFB(cfb) | CTR(ctr)\n");
    printf("\t   [byte_padding_way]                                                           [byte_padding_way]:Byte padding. If not specified, it defaults to PKCS7.\n");
    printf("\t   [mode_name]                                                                      Value can be: PKCS7(pkcs7,P,p) | ISO10126(iso10126,I,i) | ANSIX923(ansix923,A,a) | ZERO(zero,Z,z)\n");
    printf("\t   [initialiinitization_vector_file_name]\n\n");
    printf("\t-d key_file_name                                                               Decrypt\n");
    printf("\t   ciphertext_file_name                                                         [mode_name]:DES operating mode. If not specified, it defaults to ECB.\n");
    printf("\t   decrypted_plaintext_file_name                                                    Value can be: ECB(ecb) | CBC(cbc) | OFB(ofb) | CFB(cfb) | CTR(ctr)\n");
    printf("\t   [byte_padding_way]                                                           [byte_padding_way]:Byte padding. If not specified, it defaults to PKCS7.\n");
    printf("\t   [mode_name]                                                                      Value can be: PKCS7(pkcs7,P,p) | ISO10126(iso10126,I,i) | ANSIX923(ansix923,A,a) | ZERO(zero,Z,z)\n");
    printf("\t   [initialiinitization_vector_file_name]\n\n");
    printf("\t-c file_name\n");
}


/**
  * @brief  提示输入y(yes)或n(no)
  * @param  无
  * @retval y返回1,n返回0
  */
uint8_t  yes_or_no() {
    char yes_or_no = 'n';
    do {
        printf("::: ");
        yes_or_no = getch();
        printf("%c\n", yes_or_no);
    } while(yes_or_no!='y' && yes_or_no!='n' && yes_or_no!='Y' && yes_or_no!='N');
    if(yes_or_no=='n' || yes_or_no=='N') {
        return 0;
    } 
    return 1;
}

/**
  * @brief  根据文件存在与否来进行用户交互提示
  * @param  file_name 指向文件名字符串
  * @retval 无
  */
void user_prompt_depends_on_existence_of_file(char* file_name) {
    /* 这个函数就是提示用户接下来要操作指定文件，没有则创建有则覆盖，如果用户打字打错了还可以输入 n 直接退出程序 */
    if(file_exist(file_name)) { /* 文件已存在 */
        printf(">>> The file named [%s] already exists. Continuing will overwrite the file content. Do you want to continue? Please enter y(yes) or n(no).\n", file_name);
    } else { /* 文件不存在 */
        printf(">>> The file named [%s] does not exist. Do you want to create it? Please enter y(yes) or n(no).\n", file_name);
    }

    if(yes_or_no() == 0) {
        exit(1); /* 程序直接结束执行了 */
    } 
}

/**
 * @brief  提示用户是否删除临时文件
 * @param  dynamic_mem_alloc 动态分配的内存
 * @retval 无
 */
void user_prompt_delete_tmpfile(char* dynamic_mem_alloc, uint8_t e_or_d) {
    printf(">>> Do you want to keep temporary files generated during encryption and decryption? Please enter y(yes) or n(no).\n");

    if(yes_or_no() == 1) {
        if(e_or_d == ENCRYPTION) {
            /* 释放动态内存，解密的情况在前面已经释放掉了 */
            free(dynamic_mem_alloc);
        }
        exit(1); /* 程序直接结束执行了 */
    } 
}