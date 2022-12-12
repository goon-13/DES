#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <conio.h>

#include "des.h"
#include "getopt.h"
#include "common.h"
#include "user_prompts.h"

extern int optind, opterr, optopt;
extern char *optarg;

/* 加解密选项的参数，定义为extern */
char *key_file_name, *input_file_name, *output_file_name, *byte_padding_way, *mode_name, *initialization_vector_file_name;
uint8_t e_or_d;

/* 
    -g generate key 生成密钥
    -e encrypt 加密
    -d decrypt 解密
    -c console output 把输出也打印到控制台

    [1] ./DES.exe (未输入参数)
    输出:
    Usage:
        ./DES.exe [-g key_file_name]
                  [-e key_file_name plaintext_file_name encrypted_ciphertext_file_name] [byte_padding_way] [mode_name] [initialization_vector_file_name]
                  [-d key_file_name ciphertext_file_name decrypted_plaintext_file_name] [byte_padding_way] [mode_name] [initialization_vector_file_name]
                  [-c file_name]
    Options:
        -g key_file_name                                                               Generate the key to the specified file
        
        -e key_file_name                                                               Encrypt
           plaintext_file_name                                                          DES operating mode. If not specified, it defaults to ECB.
           encrypted_ciphertext_file_name                                                   Value can be: ECB(ecb) | CBC(cbc) | OFB(ofb) | CFB(cfb) | CTR(ctr)
           [byte_padding_way]                                                           Byte padding. If not specified, it defaults to PKCS7.              
           [mode_name]                                                                      Value can be: PKCS7(pkcs7,P,p) | ISO10126(iso10126,I,i) | ANSIX923(ansix923,A,a) | ZERO(zero,Z,z)                 
           [initialiinitization_vector_file_name]                                         

        -d key_file_name                                                               Decrypt
           ciphertext_file_name                                                         DES operating mode. If not specified, it defaults to ECB.
           decrypted_plaintext_file_name                                                    Value can be: ECB(ecb) | CBC(cbc) | OFB(ofb) | CFB(cfb) | CTR(ctr)
           [byte_padding_way]                                                           Byte padding. If not specified, it defaults to PKCS7.              
           [mode_name]                                                                      Value can be: PKCS7(pkcs7,P,p) | ISO10126(iso10126,I,i) | ANSIX923(ansix923,A,a) | ZERO(zero,Z,z)                
           [initialiinitization_vector_file_name]

        -c file_name                                                                   Output the specified file to the console in hexadecimal and binary                                                       

    [2] ./DES.exe -g 
    [3] ./DES.exe -e 工作模式 填充方式
    [4] ./DES.exe -d 
    [5] ./DES.exe -c 将指定的文件以十六进制以及二进制输出到控制台
 */

void get_args(char *argv[]) {
    key_file_name=optarg;
    input_file_name=argv[optind];
    output_file_name=argv[optind+1];
    byte_padding_way=argv[optind+2];
    mode_name=argv[optind+3];
    initialization_vector_file_name=argv[optind+4];
}

int main(int argc, char *argv[]) {
    clock_t start, finish; /* 计时 */
	double time_taken; /* 程序计时 */
    opterr = 0;
    int index = 0;
    int c = 0; /* 用于接收选项 */ 

    if(argc == 1) { /* 一个参数都没输入，提示用户怎么使用 */
        printf(">>> Use - h to view usage.\n");
        return 1;       
    }

    /* 循环处理参数 */
    while(EOF != (c = getopt(argc, argv, "g:e:d:c:h"))) {
        switch(c) {
            case 'g': { /* 生成密钥并存储到文件s */ 
                /* 是否输入了参数 */
                if(optarg == NULL) {
                    printf(">>> Please specify a file. Usage: ./DES.exe -g keyfile.key\n");
                    return 1;
                }
                /* 
                    写入文件逻辑:
                    [1] 文件已存在
                        询问是否覆盖? y = yes; n = no
                    [2] 文件不存在
                        直接新建文件
                */
                FILE *key_file;
                user_prompt_depends_on_existence_of_file(optarg); /* 文件不存在就exit()了 */
                key_file = fopen(optarg, "wb"); /* w:打开只写。如果不存在则新建，如果存在则清空。 b:二进制文件 */
                if(!key_file) { /* 有问题退出 */
                    printf(">>> Could not open file to write key. EXIT.\n");
                    return 1;
                }
                
                /* 使用伪随机数生成函数生成64bit = 8B的密钥 */
                /*
                    生成伪随机数:
                        计算机并不能产生真正的随机数，而是已经编写好的一些无规则排列的数字存储在电脑里，把这些数字划分为若干相等的N份，并为每份加上一个编号。
                        用srand()函数获取这个编号，然后rand()就按顺序获取这些数字，当srand()的参数值固定的时候，rand()获得的数也是固定的，
                        所以一般srand的参数用time(NULL)，因为系统的时间一直在变，所以rand()获得的数，也就一直在变，相当于是随机数了。
                        只要用户或第三方不设置随机种子，那么在默认情况下随机种子来自系统时钟。
                        如果想在一个程序中生成随机数序列，需要至多在生成随机数之前设置一次随机种子。

                    time函数来获得系统时间，它的返回值为从 00:00:00 GMT, January 1, 1970 到现在所持续的秒数。
                    time_t型数据转化为(unsigned)型再传给srand函数，即: srand((unsigned) time(&t)); 
                    还有一个经常用法，不需要定义time_t型t变量,
                    即: srand((unsigned) time(NULL)); 直接传入一个空指针，因为你的程序中往往并不需要经过参数获得的数据。
                */
                unsigned int iseed = (unsigned int)time(NULL);
                /* srand() from <stdlib.h> C库函数 void srand(unsigned int seed) 播种由函数 rand 使用的随机数发生器 */
                srand(iseed); 
                char* des_key = (unsigned char*)calloc(8, sizeof(char)); /* 记得free */
                generate_key(des_key); /* 使用随机数生成密钥 */
                
                /* 	
                    fwrite() from <stdio.h>
                    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
                        把 ptr 所指向的数组中的数据写入到给定流 stream 中。
                        size ==> 这是要被写入的每个元素的大小，以字节为单位。
                        nmemb ==> 这是元素的个数，每个元素的大小为 size 字节。
                    如果成功，该函数返回一个 size_t 对象，表示元素的总数，该对象是一个整型数据类型。
                    如果该数字与 nmemb 参数不同，则会显示一个错误。
                    fread() 与 fwrite() 针对二进制文件，fscanf() 与 fprintf() 针对文本文件。
                */
                /* 记录写入文件的元素的总数 */
                short int bytes_written = fwrite(des_key, 1, DES_KEY_SIZE, key_file);
                if (bytes_written != DES_KEY_SIZE) { 
                    printf(">>> Error occured when writing key to key file.\n");
                    fclose(key_file);
                    free(des_key);
                    return 1;
                }

                free(des_key);
                fclose(key_file);
                break;
            } // end of case 'g'
            case 'e': { /* 加密 */
                e_or_d = ENCRYPTION;
                get_args(argv);
                desProcess();
                break;                    
            } // end of case 'e'
            case 'd': {
                e_or_d = DECRYPTION;
                get_args(argv);
                desProcess();
                break;
            } // end of case 'd'
            case 'c': { /* 以字符，十六进制，二进制在控制台输出文件内容 */ 
                /* 是否输入了参数 */
                if(optarg == NULL) {
                    printf("Please specify a file. Usage: ./DES.exe -c file.txt\n");
                    return 1;
                }
                /* 
                    读取文件逻辑:
                    [1] 文件已存在 读取
                    [2] 文件不存在 提示        
                */
                FILE *file;
                
                if(file_exist(optarg)) { /* 文件已存在 */
                    file = fopen(optarg, "rb");
                    fseek(file, 0L, SEEK_END);
                    unsigned long file_size = ftell(file);
                    fseek(file, 0L, SEEK_SET); /* 移动文件指针到文件开头 */
                    unsigned long number_of_blocks = file_size/DES_BLOCK_BYTE_NUM + ((file_size%DES_BLOCK_BYTE_NUM)?1:0);
                    
                    /* 控制台打印输出文件的每个字符，十六进制，二进制
                        [1] 数据单位为字节，最后一个分组可能不满 8B
                        [2] 打印十六进制
                        [3] 打印二进制
                    */
                    unsigned char* data_block = (unsigned char*)calloc(DES_BLOCK_BYTE_NUM, sizeof(char));
                    unsigned long block_count = 0;
                    printf(">>> Output file in hex:\n");
                    while(fread(data_block, 1, DES_BLOCK_BYTE_NUM, file)) { /* 输出每八个元素换一次行 */
                        block_count++;
                        unsigned long num_of_bytes = DES_BLOCK_BYTE_NUM;
                        if(block_count == number_of_blocks) {
                            num_of_bytes = ((file_size%DES_BLOCK_BYTE_NUM)==0)?DES_BLOCK_BYTE_NUM:(file_size%DES_BLOCK_BYTE_NUM);
                        }
                        for(int i=0; i<num_of_bytes; i++){
                            printf("0x%02x ", data_block[i]);
                        }
                        memset(data_block, '\0', DES_BLOCK_BYTE_NUM);
                        printf("\n");
                    } // end of while of hex

                    printf("\n>>> Output file in binary:\n");
                    fseek(file, 0L, SEEK_SET); //移动文件指针到原来的位置（复原）
                    block_count = 0;
                    while(fread(data_block, 1, DES_BLOCK_BYTE_NUM, file)) { /* 输出每八个元素换一次行 */
                        block_count++;
                        unsigned long num_of_bytes = DES_BLOCK_BYTE_NUM;
                        if(block_count == number_of_blocks) {
                            num_of_bytes = ((file_size%DES_BLOCK_BYTE_NUM)==0)?DES_BLOCK_BYTE_NUM:(file_size%DES_BLOCK_BYTE_NUM);
                        }
                        for(int i=0; i<num_of_bytes; i++){
                            char bits[9] = {0};
                            char_to_bin_8bits(data_block[i], bits);
                            printf("%s ", bits);
                        }
                        memset(data_block, '\0', DES_BLOCK_BYTE_NUM);
                        printf("\n");
                    } // end of while of binary

                    fclose(file);
                } else { /* 文件不存在 */
                    printf(">>> The file does not exist. Please check if the path is correct or there is a spelling error.\n");
                    return 1;
                }
                break;
            } // end of case 'c'
            case 'h': { /* help */
                user_prompt_usage();
                break;
            }
            case '?': { /* 表示选项不支持 */
                switch(optopt) {
                    case 'g': case 'e': case 'd': case 'c': {
                        printf(">>> Missing parameter, please use -h to check usage.\n");
                        break;
                    }
                    default: {
                        printf(">>> Unknow option:[%c].\n", optopt);
                        break;
                    }
                } // end of switch
                break;
            }
        } // end of switch    
    } // end of while 

    return 0;
}