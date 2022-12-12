#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<time.h>
#include<errno.h>

#include "des.h"
#include "common.h"
#include "user_prompts.h"

extern int errno; /* 打印打开文件时错误信息 */

/* 模式和填充方式定义为枚举类型 */
enum MODE_NAME { ECB, CBC, OFB, CFB, CTR };
enum PADDING_WAY { PKCS7, ISO10126, ANSIX923, ZERO  };
const char *mode_table_uppercase[] = {"ECB", "CBC", "OFB", "CFB", "CTR", NULL};
const char *mode_table_lowercase[] = {"ecb", "cbc", "ofb", "cfb", "ctr", NULL};
const char *padding_table_uppercase[] = {"PKCS7", "ISO10126", "ANSIX923", "ZERO", NULL};
const char *padding_table_lowercase[] = {"pkcs7", "iso10126", "ansix923", "zero", NULL};
const char *padding_table_abbr_uppercase[] = {"P", "I", "A", "Z", NULL};
const char *padding_table_abbr_lowercase[] = {"p", "i", "a", "z", NULL};
/* 将枚举类型和输入的字符串进行匹配 */
enum MODE_NAME find_enum_mode(enum MODE_NAME mode, char *sval) {
    mode=ECB; /* value corresponding to TABLE[0] */
    int i=0;
    /* 匹配大写 */
    for(i=0; mode_table_uppercase[i]!=NULL; ++i, ++mode)
        if(strcmp(sval, mode_table_uppercase[i])==0) return mode;
    /* 匹配小写 */
    mode=ECB; /* value corresponding to TABLE[0] */
    for(i=0; mode_table_lowercase[i]!=NULL; ++i, ++mode)
    if(strcmp(sval, mode_table_lowercase[i])==0) return mode;    
    return -1;
}
enum PADDING_WAY find_enum_padding(enum PADDING_WAY padding, char*sval) {
    padding=PKCS7; /* value corresponding to TABLE[0] */
    int i=0;
    /* 匹配大写 */
    for(i=0; padding_table_uppercase[i]!=NULL; ++i, ++padding)
        if(strcmp(sval, padding_table_uppercase[i])==0) return padding;
    /* 匹配小写 */
    padding=PKCS7; /* value corresponding to TABLE[0] */
    for(i=0; padding_table_lowercase[i]!=NULL; ++i, ++padding)
    if(strcmp(sval, padding_table_lowercase[i])==0) return padding;
    /* 匹配缩写大写 */
    padding=PKCS7; /* value corresponding to TABLE[0] */
    for(i=0; padding_table_abbr_uppercase[i]!=NULL; ++i, ++padding)
        if(strcmp(sval, padding_table_abbr_uppercase[i])==0) return padding;
    /* 匹配缩写小写 */
    padding=PKCS7; /* value corresponding to TABLE[0] */
    for(i=0; padding_table_abbr_lowercase[i]!=NULL; ++i, ++padding)
    if(strcmp(sval, padding_table_abbr_lowercase[i])==0) return padding;
    return -1;
}

/*
    本算法并不是实际使用中的 DES 
    是教材中最初的算法 为了区分，称 DEA Data Encryption Algorithm
    DES -- Data Encryption Standard 数据加密标准
    加密流程与解密流程除了 子密钥使用顺序相反外 其余完全相同
    ==(1)== 加密流程
        [1] 初始置换IP
        [2] 16轮迭代
            (1) 单轮变换数学描述:
                L(i) = R(i-1)
                R(i) = L(i-1) ^ F(R(i-1), K(i))
                第16轮 未交换 R(15) 和 L(15)
            (2) 轮函数F
                --1-- 扩展置换E
                --2-- 轮密钥加
                --3-- S盒
                --4-- 置换P
        [3] 初始逆置换IP^(-1)
    ==(2)== 密钥扩展方案
        [1] PC-1置换
        [2] 分组并执行循环左移
        [3] PC-2置换
*/

/* [1] 初始置换IP表-范围:1~64，作下标使用时需要-1 */
unsigned int initial_permutation_table[] = {58, 50, 42, 34, 26, 18, 10, 2,
                                            60, 52, 44, 36, 28, 20, 12, 4,
                                            62, 54, 46, 38, 30, 22, 14, 6,
                                            64, 56, 48, 40, 32, 24, 16, 8,
                                            57, 49, 41, 33, 25, 17,  9, 1,
                                            59, 51, 43, 35, 27, 19, 11, 3,
                                            61, 53, 45, 37, 29, 21, 13, 5,
                                            63, 55, 47, 39, 31, 23, 15, 7};
/* [2] 轮函数F所需的 扩展置换E */
unsigned int extended_permutation_e[] =  {32,  1,  2,  3,  4,  5,
                                           4,  5,  6,  7,  8,  9,
                                           8,  9, 10, 11, 12, 13,
                                           12, 13, 14, 15, 16, 17,
                                           16, 17, 18, 19, 20, 21,
                                           20, 21, 22, 23, 24, 25,
                                           24, 25, 26, 27, 28, 29,
                                           28, 29, 30, 31, 32,  1};
/* [3] 8个S盒 */
unsigned int S1[] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                      15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13};

unsigned int S2[] = {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
                      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
                      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
                      13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12, 0,  5, 14,  9};

unsigned int S3[] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
                    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
                    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
                    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

unsigned int S4[] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
                    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
                    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
                    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

unsigned int S5[] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
                    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
                    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
                    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

unsigned int S6[] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
                    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
                    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
                    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

unsigned int S7[] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
                    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
                    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
                    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};

unsigned int S8[] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
                    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
                    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
                    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};
/* [4] 轮函数 F 的 置换P （P盒置换） */
unsigned int permutation_pbox[] =    {16,  7, 20, 21,
									  29, 12, 28, 17,
									   1, 15, 23, 26,
									   5, 18, 31, 10,
									   2,  8, 24, 14,
									  32, 27,  3,  9,
									  19, 13, 30,  6,
									  22, 11,  4, 25};
/* [5] 种子密钥 长64bit，8B */
char seed_key[8+1];
/* [6] 轮密钥 K(1)~K(16) 存储在字符串数组中 16轮，每轮48bit即6B */
char round_key[16][6+1];
/* [7] 密钥扩展 PC-1 置换表 : 去掉8bit校验位并对剩下56bit打乱重排 */
unsigned int permuted_choice_1[] = {57, 49,  41, 33,  25,  17,  9,
								     1, 58,  50, 42,  34,  26, 18,
                                    10,  2,  59, 51,  43,  35, 27,
                                    19, 11,   3, 60,  52,  44, 36,
                                    63, 55,  47, 39,  31,  23, 15,
                                     7, 62,  54, 46,  38,  30, 22,
                                    14,  6,  61, 53,  45,  37, 29,
                                    21, 13,   5, 28,  20,  12,  4};
/* [8] 密钥扩展 PC-2 置换表 长 48bit */
unsigned int permuted_choice_2[] =    {14, 17, 11, 24,  1,  5,
		       						    3, 28, 15,  6, 21, 10,
                                       23, 19, 12,  4, 26,  8,
                                       16,  7, 27, 20, 13,  2,
                                       41, 52, 31, 37, 47, 55,
                                       30, 40, 51, 45, 33, 48,
                                       44, 49, 39, 56, 34, 53,
                                       46, 42, 50, 36, 29, 32};
/* [9] 每轮循环左移的位数 */
int rotate_left_bit[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
/* [10] 初始逆置换 IP^(-1) */
unsigned int inverse_initial_permutation[] = {40,  8, 48, 16, 56, 24, 64, 32,
                                              39,  7, 47, 15, 55, 23, 63, 31,
                                              38,  6, 46, 14, 54, 22, 62, 30,
                                              37,  5, 45, 13, 53, 21, 61, 29,
                                              36,  4, 44, 12, 52, 20, 60, 28,
                                              35,  3, 43, 11, 51, 19, 59, 27,
                                              34,  2, 42, 10, 50, 18, 58, 26,
                                              33,  1, 41,  9, 49, 17, 57, 25};

/**
  * @brief  生成64bit = 8B的密钥
  * @param  key[] 存储生成的密钥值  
  * @retval 无
  */
void generate_key(char* key) {
	int i;
	for(i=0; i<8; i++) {
		key[i] = rand()%255;
	} // end of for i
} // end of function generate_key

/**
  * @brief  密钥扩展方案 由种子密钥(64bit)生成16轮的轮密钥(48bit)
  * @param  after_permutation[] 置换后结果
  * @retval 无
  */
void key_extension_schedule(char seed_key[], char round_key_array[16][6+1]) {
    unsigned char after_pc1[7+1]; /* 经过PC-1置换后的结果，长56bit即7B */
    /* 每轮需要将56bit分为高位28bit的 c 以及低位28bit的 d ，分别循环左移后再合起来经过PC-2置换
        c 和 d 的 28bit都分配在 char数组的前三个元素（3B = 24bit），以及最后一个字节的高4位
    */
    unsigned char before_pc2[7+1]; /* 存储每轮在PC-2置换前，高位c和低位d拼接成的串，长 56bit = 7B */
    unsigned char key_c[4+1], key_d[4+1], key_d_rotate_left_4bit[4+1]; /* key_d_rotate_left_4bit 用于 c和d 拼串时循环左移4bit使用 */
    memset(after_pc1, 0, 7+1);
    memset(before_pc2, 0, 7+1);
    memset(key_c, 0, 4+1);
    memset(key_d, 0, 4+1);
    memset(key_d_rotate_left_4bit, 0, 4+1);
    /* [1] PC-1置换 */
    permutation(after_pc1, seed_key, permuted_choice_1, 56);
    /* [2] 迭代16轮生成16轮所需轮密钥，存储到 round_key */
    /* =1= 取出 c 和 d
        56bit 分 7B
        数组下标 0~2 前三字节 + 数组下标3的字节的前高位4bit 为 c
        数组下标3的字节的后高位4bit + 数组下标 4~6 后三字节 为 
        28bit都分配在 char数组的前三个元素（3B = 24bit），以及最后一个字节的高4位
    */
    for(int j=0; j<3; j++) {
        key_c[j] = after_pc1[j];
    } // end of for j
    key_c[3] |= after_pc1[3] & 0xF0; /* &0xF0 取出 高四位 ; 再 |= 把高四位赋给c */
    for(int j=0; j<3; j++) {
        key_d[j] |= (after_pc1[j+3] & 0x0F) << 4; /* d 将下半字节和上半字节拼起来成一个字节 */
        key_d[j] |= (after_pc1[j+4] & 0xF0) >> 4;
    } // end of for j
    key_d[3] |= (after_pc1[6] & 0x0F) << 4; /* d 的最后4bit */
    /* 迭代16轮生成16轮所需轮密钥，存储到 round_key */
    for(int i=0; i<16; i++) {
        /* =2= c 和 d 分别进行循环左移， 再按照 c高位 d低位 的位置拼接成串
                c 和 d 字节内每位情况 ('-'表示不是有效数据, 字母代表有效bit)
                abcd efgh ijkl mnop qrst uvwx yzzy ---- 
                循环左移一位需要做到
                bcde fghi jklm nopq rstu vwxy zzya ----
         */
        rotate_left_bits(key_c, rotate_left_bit[i], 28);
        rotate_left_bits(key_d, rotate_left_bit[i], 28);
        /* 以 c高位 d低位 拼成56bit的比特串 */
        /* 【BUG】这里不能用 strcpy : 字符串到结束符 0 就结束了，但是可能只是那个字节真的为 0 
            // strcpy(key_d_rotate_left_4bit, key_d);
        */
        for(int j=0; j<4; j++) {
            key_d_rotate_left_4bit[j] = key_d[j];
            rotate_left_one_byte(&key_d_rotate_left_4bit[j], 4); /* 交换 d 中 高 4 位和 低 4 位 */
        } // end of for j
        memset(before_pc2, 0, 7+1);
        for(int j=0; j<=3; j++) { 
            before_pc2[j] |= key_c[j];
            /* d 不能直接赋给before_pc2，它要左移4位接到 c 的后面 
                先将遍历到的 d 的字节循环左移4bit 使得 高四位 和 低四位 交换
                再将交换后的本字节的低四位赋值给上一字节的低四位
            */
            /* d 串假设初始每一位为
                    abcd efgh
                    ijkl mnop
                    qrst uvwx
                    yzab ----
                   【法1】 每个字节内部 交换高低 4 位
                    efgh abcd ==> d 的 第 1 字节, 低 4 位置位到 before_pc2 的 第 4 字节的低 4 位, 高 4 位 置位到 before_pc2 的 第 5 字节 高4位
                    mnop ijkl ==> d 的 第 2 字节, 低 4 位置位到 before_pc2 的 第 5 字节的低 4 位, 高 4 位 置位到 before_pc2 的 第 6 字节 高4位
                    uvwx qrst ==> d 的 第 3 字节, 低 4 位置位到 before_pc2 的 第 6 字节的低 4 位, 高 4 位 置位到 before_pc2 的 第 7 字节 高4位
                    ---- yzab ==> d 的 第 4 字节, 低 4 位置位到 before_pc2 的 第 7 字节的低 4 位, 高 4 位 脏数据不需要
                        before_pc2 从 c 和 d 发生拼接的 第 4 个元素，逐个 置位 交换过后的 d 的 低 4 位
                        before_pc2 |= 低 4 位的字节 的 下一个字节， |= 高 4 位
                        效果: [cccc] 代表 c 的最后低位 4 bit
                        [cccc] 0000 |= 0000 abcd ==> [cccc] abcd
                        下一个字节 ==> 0000 0000 |= efgh 0000 ==> efgh 0000
                        再下一轮循环:
                        efgh 0000 |= 0000 ijkl ==> efgh ijkl 
                        0000 0000 |= mnop 0000 ==> mnop 0000
                        如此循环直到 before_pc2 的 第 7 字节
                    【法2】
                    d 串 整体循环右移 4 位
                    0000 abcd
                    efgh ijkl
                    mnop qrst
                    uvwx yzab
                    再用 |= 给拼成的串 置位
            */
            before_pc2[j+3] |= (key_d_rotate_left_4bit[j] & 0x0F); // & 0x0F 则仅保留低位四位 
            before_pc2[j+4] |= (key_d_rotate_left_4bit[j] & 0xF0); // & 0x0F 则仅保留低位四位 
        } // end of for j
        
        /* =3= 进行PC-2置换 */
        /* 此处 round_key[i] 是一个变量
            数组变量本身表达地址，如 round_key 就是地址
            但数组的单元表达的是变量，需要用 & 取地址
            字符串数组做参数时，需要指定这个二维数组第二维度的值，即字符串元素的长度
         */
        permutation(&round_key_array[i][0], before_pc2, permuted_choice_2, 48);
    } // end of for i    
} // end of key_extension_schedule()

/**
 * @brief  将 48bit=6B 输入 经过 8个S盒 生成 32bit=4B 输出
 * @param  extended_r[] 48bit=6B 输入
 * @param  r_next[] 32bit=4B 输出
 * @retval 无
 */
void s_box(char extended_r[], char r_next[]) {
    /* =3= S盒
        将 =2= 的 48bit = 6B 压缩为 32bit = 4B 数据
        abcd efgh | ijkl mnop | qrst uvwx | yzab cdef | ghij klmn | opqr stuv
        Oooo oOXx | xxxX Oooo | oOXx xxxX | Oooo oOXx | xxxX Oooo | oOXx xxxX
        每6位（上面的o或x为一组）为一组，对应输入一个S盒，该S盒输出4bit的一组数据
        数据从高位向低位，依次对应 S1, S2, ..., S8
        取出6bit的首和尾两个bit（上面bit串中大写的O或X），组成对应S盒的行号
        6bit的中间4bit对应S盒的列号
        S盒 4 行 16 列，行号 0~3， 列号 0~15
        按照行号 + 列号 找到输出的值，存储为4bit值存入r_next
        因为 取出的位 在char数组中位置分散，且必须经过S1~
        r_next中存储的每一bit情况如下，1表示S1置换结果，以此类推
        1111 2222 | 3333 4444 | 5555 6666 | 7777 8888
    */
    memset(r_next, 0, 4+1); /* 初始化，且每轮都清空下 */
    unsigned char row, column; /* 用于存储取S盒中的行号和列号 */
    /* [1] S1 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* 由=2=结果 的 首字节: abcd efgh 取出a和f位 组成 af 二进制转十进制即为要取得S1值的行号
        a-bcd efgh & 1-000 0000 ==> a-000 0000
        a-000 0000 >> 6 ==> 0000 00-a-0
        */
    row |= (extended_r[0] & 0x80) >> 6; /* 0000 00-0-0 |= 0000 00-a-0 */
    row |= (extended_r[0] & 0x04) >> 2; /* 0000 00a-0 |= 0000 000-f */
    /* 由=2=结果 的 首字节: abcd efgh 取出b, c, d, e位 组成 bcde 二进制转十进制即为要取得S1值的行号-0111 1000 */
    column |= (extended_r[0] & 0x78) >> 3; /* 0000 0000 |= 0000 bcde */
    /* 由行号和列号取出S1的值，一行16个元素 */
    r_next[0] |= S1[row*16 + column] << 4; /* 0000 0000 |= 1111 0000 */

    /* [2] S2 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* extended_r 前两个数组元素 : (0)&(1) ==> abcd efgh | ijkl mnop ==> gl ==> 0000 0010 | 0001 0000 */
    row |= (extended_r[0] & 0x02); /* 0000 00-0-0 |= 0000 00-g-0 */
    row |= (extended_r[1] & 0x10) >> 4; /* 0000 00g-0 |= 0000 000-l */
    /* (0)&(1) ==> abcd efgh | ijkl mnop ==> hijk ==> 0000 0001 | 1110 0000 */
    column |= (extended_r[0] & 0x01) << 3; /* 0000 0-000 |= 0000 h-000 */
    column |= (extended_r[1] & 0xE0) >> 5; /* 0000 h-000 |= 0000 0-ijk */
    r_next[0] |= S2[row*16 + column]; /* 1111 0000 |= 0000 2222 */

    /* [3] S3 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (1)&(2) ==> ijkl mnop | qrst uvwx ==> mr ==> 0000 1000 | 0100 0000 */
    row |= (extended_r[1] & 0x08) >> 2; /* 0000 0000 |= 0000 00-m-0 */
    row |= (extended_r[2] & 0x40) >> 6; /* 0000 00m-0 |= 0000 000-r */
    /* (1)&(2) ==> ijkl mnop | qrst uvwx ==> nopq ==> 0000 0111 | 1000 0000 */
    column |= (extended_r[1] & 0x07) << 1; /* 0000 000-0 |= 0000 nop-0 */
    column |= (extended_r[2] & 0x80) >> 7; /* 0000 nop-0 |= 0000 000-q */
    r_next[1] |= S3[row*16 + column] << 4; /* 0000 0000 |= 3333 0000 */

    /* [4] S4 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (2) ==> qrst uvwx ==> sx ==> 0010 0001 */
    row |= (extended_r[2] & 0x20) >> 4; /* 0000 0000 |= 0000 00-s-0 */
    row |= (extended_r[2] & 0x01); /* 0000 00s-0 |= 0000 000-x */
    /* (2) ==> qrst uvwx ==> tuvw ==> 0001 1110 */
    column |= (extended_r[2] & 0x1E) >> 1; /* 0000 0000 |= 0000 tuvw */
    r_next[1] |= S4[row*16 + column]; /* 3333 0000 |= 0000 4444 */

    /* [5] S5 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (3) ==> yzab cdef ==> yd ==> 1000 0100 */
    row |= (extended_r[3] & 0x80) >> 6; /* 0000 0000 |= 0000 00-y-0 */
    row |= (extended_r[3] & 0x04) >> 2; /* 0000 00y-0 |= 0000 000-d */
    /* (3) ==> yzab cdef ==> zabc ==> 0111 1000 */
    column |= (extended_r[3] & 0x78) >> 3; /* 0000 0000 |= 0000 zabc */
    r_next[2] |= S5[row*16 + column] << 4; /* 0000 0000 |= 5555 0000 */

    /* [6] S6 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (3)&(4) ==> yzab cdef | ghij klmn ==> ej ==> 0000 0010 | 0001 0000 */
    row |= (extended_r[3] & 0x02); /* 0000 0000 |= 0000 00-e-0 */
    row |= (extended_r[4] & 0x10) >> 4; /* 0000 00e-0 |= 0000 000-j */
    /* (3)&(4) ==> yzab cdef | ghij klmn ==> fghi ==> 0000 0001 | 1110 0000 */
    column |= (extended_r[3] & 0x01) << 3; /* 0000 0-000 |= 0000 f-000 */
    column |= (extended_r[4] & 0xE0) >> 5; /* 0000 f-000 |= 0000 0-ghi */
    r_next[2] |= S6[row*16 + column]; /* 5555 0000 |= 0000 6666 */

    /* [7] S7 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (4)&(5) ==> ghij klmn | opqr stuv ==> kp ==> 0000 1000 | 0100 0000 */
    row |= (extended_r[4] & 0x08) >> 2; /* 0000 0000 |= 0000 00-k-0 */
    row |= (extended_r[5] & 0x40) >> 6; /* 0000 00k-0 |= 0000 000-p */
    /* (4)&(5) ==> ghij klmn | opqr stuv ==> lmno ==> 0000 0111 | 1000 0000 */
    column |= (extended_r[4] & 0x07) << 1; /* 0000 000-0 |= 0000 lmn-0 */
    column |= (extended_r[5] & 0x80) >> 7; /* 0000 lmn-0 |= 0000 000-o */
    r_next[3] |= S7[row*16 + column] << 4; /* 0000 0000 |= 7777 0000 */

    /* [8] S8 */
    row = 0; column = 0; /* 初始化行号和列号 */
    /* (5) ==> opqr stuv ==> qv ==> 0010 0001 */
    row |= (extended_r[5] & 0x20) >> 4; /* 0000 0000 |= 0000 00-q-0 */
    row |= (extended_r[5] & 0x01); /* 0000 00q-0 |= 0000 000-v */
    /* (5) ==> opqr stuv ==> rstu ==> 0001 1110 */
    column |= (extended_r[5] & 0x1E) >> 1; /* 0000 0000 |= 0000 rstu */
    r_next[3] |= S8[row*16 + column]; /* 7777 0000 |= 0000 8888 */
} // end of function s_box()

/**
  * @brief  DES 加密&解密
  *         DES 加(解)密64bit长的明(密)文分组， 64bit长度密钥-含8bit校验位，有效长度56bit
  * @param  text[]-输入的内容
  * @param  seed_key[]-种子密钥
  * @param  result_text[]-存储结果 加密则存储密文 解密则存储明文
  * @param  e_or_d-加密还是解密 1 加密 0 解密
  * @retval 无
  */
void des(char text[], char seed_key[], char result_text[], int e_or_d) {
    int key_index = 0; /* 使用的是哪一轮的轮密钥 加密按从小到大顺序用，解密则是完全相反的顺序 */
    /* 64bit文本分组占8B 一个char占1B */
    char after_initial_permutation[8+1]; /* 存储文本分组经过初始置换IP后的结果，长度+1因为要存储字符串结束符 0 */
    char l[4+1], r[4+1]; /* 存储本轮输入 l(i-1), r(i-1) */
    char l_next[4+1], r_next[4+1]; /* 存储本轮输出 l(i), r(i) */
    char extended_r[6+1]; /* 扩展置换E 将r从4B=32bit扩展成6B=48bit */
    char round_function_F_result[4+1]; /* 轮函数F后的结果 */
    char before_inverse_ip[8+1];
    memset(after_initial_permutation, 0, 8+1);
    /* 轮密钥48bit = 6B */
    char round_key[16][6+1];
    for(int i=0; i<16; i++) {
        memset(round_key[i], 0, 6+1);
    }
    memset(l, 0, 4+1);
    memset(r, 0, 4+1);
    memset(l_next, 0, 4+1);
    memset(r_next, 0, 4+1);
    memset(extended_r, 0, 6+1);
    memset(round_function_F_result, 0, 4+1);
    memset(before_inverse_ip, 0, 8+1);
    
    /* (0) 生成轮密钥 */
    key_extension_schedule(seed_key, round_key);

    /* (1) 初始置换IP */
    permutation(after_initial_permutation, text, initial_permutation_table, 64);
    /* (2) 16轮迭代 :
        =1= 单轮变换数学描述:
            L(i) = R(i-1)
            R(i) = L(i-1) ^ F(R(i-1), K(i))
            第16轮 未交换 R(15) 和 L(15)
        =2= 轮函数F
            =1= 扩展置换E
            =2= 轮密钥加
            =3= S盒
            =4= 置换P
    */
    /* [1] 明文分组64bit 分为 左半高位部分32bit l[] 和 右半低位部分32bit r[] */
    for(int i=0; i<4; i++) {
        l[i] = after_initial_permutation[i]; /* l取明文char数组的 0, 1, 2, 3 四个字节 */
        r[i] = after_initial_permutation[i+4]; /* r取明文char数组的 4, 5, 6, 7 四个字节 */
    } // end of for i
    /* [2] 开始16轮循环，第16轮略有不同，不交换l(15) 和 r(15) */ 
    for(int i=0; i<16; i++) {
        /* (1) 计算轮函数 F */
        /* =1= 扩展置换E
            将 r(i-1) 32bit值 经 扩展置换E 成 48bit（4B ==> 6B），才能与48bit的轮密钥 K(i) 进行轮函数 F 的计算
            32bit 分成 8组，每组 4bit 扩展后8组 6bit，每组扩充 2bit
         */
        /* 每次使用 permutation 前，要确认存储的结果 after_permutation 是否需要初始为空，避免上轮的残留数据还在数组中，影响结果 */
        memset(extended_r, 0, 6+1);
        permutation(extended_r, r, extended_permutation_e, 48);
        /* =2= 轮密钥加
            扩展的 r 与 轮密钥 K(i) 异或
            解密与加密流程唯一不同之处 : 子密钥使用顺序相反
         */
        if(e_or_d == ENCRYPTION) { /* 加密模式 */
            key_index = i;
        } else { /* 解密模式 */
            key_index = 15 - i; /* 有16个轮密钥，数组下标 0~15 */
        }
        for(int j=0; j<6; j++) {
            extended_r[j] ^= round_key[key_index][j];
        }
        /* =3= S盒
            将 =2= 的 48bit = 6B 压缩为 32bit = 4B 数据
            abcd efgh | ijkl mnop | qrst uvwx | yzab cdef | ghij klmn | opqr stuv
            Oooo oOXx | xxxX Oooo | oOXx xxxX | Oooo oOXx | xxxX Oooo | oOXx xxxX
            每6位（上面的o或x为一组）为一组，对应输入一个S盒，该S盒输出4bit的一组数据
            数据从高位向低位，依次对应 S1, S2, ..., S8
            取出6bit的首和尾两个bit（上面bit串中大写的O或X），组成对应S盒的行号
            6bit的中间4bit对应S盒的列号
            S盒 4 行 16 列，行号 0~3， 列号 0~15
            按照行号 + 列号 找到输出的值，存储为4bit值存入r_next
            因为 取出的位 在char数组中位置分散，且必须经过S1~
            r_next中存储的每一bit情况如下，1表示S1置换结果，以此类推
            1111 2222 | 3333 4444 | 5555 6666 | 7777 8888
         */
        s_box(extended_r, r_next);
        /* =4= 置换P 轮函数F的最后一步 置换后结果 32bit=4B 存储到 round_function_F_result[] 中 */
        /* 每次使用 permutation 前，要确认存储的结果 after_permutation 是否需要初始为空，避免上轮的残留数据还在数组中，影响结果 */
        memset(round_function_F_result, 0, 4+1);
        permutation(round_function_F_result, r_next, permutation_pbox, 32);

        /* (2) L(i) = R(i-1); R(i) = L(i-1) ^ F(R(i-1), K(i)) */
        /* 【BUG】这里不能用 strcpy : 字符串到结束符 0 就结束了，但是可能只是那个字节真的为 0 
                // strcpy(l_next, r);
        */
        for(int j=0; j<4; j++) {
            l_next[j] = r[j];
        } // end of j
        for(int j=0; j<4; j++) {
            r_next[j] = l[j] ^ round_function_F_result[j]; /* R(i) = L(i-1) ^ F(R(i-1), K(i)) */
        } // end of for j
        /* 把 l 和 r 准备好下一轮迭代 */
        /* 【BUG】这里不能用 strcpy : 字符串到结束符 0 就结束了，但是可能只是那个字节真的为 0 
                // strcpy(l, l_next);
                // strcpy(r, r_next);
        */
        for(int j=0; j<4; j++) {
            l[j] = l_next[j];
            r[j] = r_next[j];
        } // end of j
    } // end of for i 15轮迭代
    /* 第16轮 不需要交换 R(15) 和 L(15)
        故最终结果存入 ciphertext[] 中时存储位置为 : R16 L16
     */
    for(int i=0; i<4; i++) {
        before_inverse_ip[i] = r[i];
        before_inverse_ip[i+4] = l[i];
    }
    /* (3) 初始逆置换 IP^(-1) */
    permutation(result_text, before_inverse_ip, inverse_initial_permutation, 64);
} // end of function des()


void padding_one_block(enum PADDING_WAY padding, char *data_block, uint8_t num_of_bytes_padding) {
    uint8_t last_block_bytes = DES_BLOCK_BYTE_NUM - num_of_bytes_padding; /* 最后一个需要填充的分组的字节数 */
    /* 根据填充方式进行填充 */
    switch(padding) {
        case PKCS7: {   
            for(uint8_t i=last_block_bytes; i<DES_BLOCK_BYTE_NUM; i++) {
                data_block[i] = num_of_bytes_padding; 
            } // end of for
            break;
        }          
        case ISO10126: { /* ISO10126: 最后一个字节是填充的字节数（包括最后一字节）,其他全部填随机数。已是分组的整数倍也要填充一个分组。 */
            unsigned int iseed = (unsigned int)time(NULL);
            srand(iseed); 
            for(uint8_t i=last_block_bytes; i<DES_BLOCK_BYTE_NUM-1; i++) {
                data_block[i] = rand()%255; 
            } // end of for
            data_block[DES_KEY_SIZE-1] = num_of_bytes_padding; /* 最后一个字节记录总共填充了几个字节 */
            break;
        } // end of case ISO10126
        case ANSIX923: { /* ISO10126: 最后一个字节是填充的字节数（包括最后一字节）,其他全部填 0 。已是分组的整数倍也要填充一个分组。 */   
            for(uint8_t i=last_block_bytes; i<DES_BLOCK_BYTE_NUM-1; i++) {
                data_block[i] = 0; 
            } // end of for
            data_block[DES_KEY_SIZE-1] = num_of_bytes_padding; /* 最后一个字节记录总共填充了几个字节 */
            break;
        }
        case ZERO: {
            for(uint8_t i=last_block_bytes; i<DES_BLOCK_BYTE_NUM; i++) {
                data_block[i] = 0; 
            } // end of for
            break;
        }
    } // end of switch(padding)
} // end of function padding_one_block()

void load_one_block_file(char *file_name, char *data_block, enum PADDING_WAY padding, uint8_t need_padding) {
    uint32_t file_size = count_file_length(file_name);
    FILE* file = fopen(file_name, "rb");
    if(file == NULL) {
        fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", file_name, strerror(errno));
        exit(1);
    }
    if(file_size == 0) { /* 密钥或者初始向量文件为空 */
        printf(">>> The file named [%s] is empty, and can be generated using the -g instruction.\n", file_name);
        exit(0);
    }
    if(file_size >= DES_BLOCK_BYTE_NUM || !need_padding) {  /* 密钥或者初始向量长度大于等于 8B，多的部分直接舍弃 或 解密不需要填充也直接读取 */
        fread(data_block, sizeof(char), DES_KEY_SIZE, file);
    } else { /* 加密时 密钥或者初始向量文件长度不足 8B，需要填充 */
        uint8_t num_of_bytes_padding = (uint8_t)(DES_BLOCK_BYTE_NUM - file_size%DES_BLOCK_BYTE_NUM); /* 需要填充的字节数 */
        fread(data_block, sizeof(char), file_size, file);
        /* 这里文件长度在1~7之间(0<length<8) 此时file_size即最后一个分组的长度 */
        padding_one_block(padding, data_block, num_of_bytes_padding);  
    } // end of if-else
    fclose(file);
} // end of function padding_a_block()

uint64_t load_blocks_file(char *input_file_name, char *filled_input_file_name, char *input_data_block, enum PADDING_WAY padding) {
    uint64_t num_of_input_data_bytes = 0;
    /* 每次取一个分组大小数据进内存，再写入临时文件 */
    uint32_t file_size = count_file_length(input_file_name);
    uint8_t last_block_bytes = (uint8_t)file_size%DES_BLOCK_BYTE_NUM; /* 值为0则刚好为分组整数倍 */
    /* 长度刚好是分组的整数倍也需要添加一个分组的填充 */
    uint8_t num_of_bytes_padding = (uint8_t)(DES_BLOCK_BYTE_NUM - last_block_bytes); /* 需要填充的字节数 */
    uint32_t num_of_blocks = file_size/DES_BLOCK_BYTE_NUM + 1;

    FILE* input_file = fopen(input_file_name, "rb");
    if(input_file == NULL) {
        fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", input_file_name, strerror(errno));
        exit(1);
    }
    FILE* filled_input_file = fopen(filled_input_file_name, "wb");
    if(filled_input_file == NULL) {
        fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
        exit(1);
    }
    fseek(input_file, 0L, SEEK_SET);
    fseek(filled_input_file, 0L, SEEK_SET);

    uint32_t block_count = 0;

    /* 文件内容不是分组的整数倍长度 */
    while(fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, input_file)) {
        block_count++;
        if(block_count == num_of_blocks) { /* 最后一个字节没有刚好满一个分组长度 */
            /* 根据填充方式进行填充 */
            padding_one_block(padding, input_data_block, num_of_bytes_padding);
        } // end of if
        fwrite(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file); /* 考虑磁盘空间不足的情况 */
        memset(input_data_block, 0, DES_BLOCK_BYTE_NUM); /* 把本次分组暂存内存清空 */
    } // end of while
    if(last_block_bytes == 0) { /* 长度刚好是分组的整数倍也需要添加一个分组的填充 */
        /* 根据填充方式进行填充 */
        padding_one_block(padding, input_data_block, num_of_bytes_padding);
        fwrite(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file); /* 考虑磁盘空间不足的情况 */
    } // end of if
    num_of_input_data_bytes = file_size + num_of_bytes_padding;
    fclose(filled_input_file);
    fclose(input_file);
    return num_of_input_data_bytes;
}

/**
  * @brief  DES 命令行加解密选项流程控制
  * @param  text[]-输入的内容
  * @retval 无
  */
void desProcess() {
    /* DES 
    DES全称为Data Encryption Standard，即数据加密标准，是一种使用密钥加密的块算法，
    1977年被美国联邦政府的国家标准局确定为联邦资料处理标准（FIPS），并授权在非密级政府通信中使用，随后该算法在国际上广泛流传开来。
    需要注意的是，在某些文献中，作为算法的DES称为数据加密算法（Data Encryption Algorithm, DEA），已与作为标准的DES区分开来。
        命令行使用 参数:
            参数处理使用 getopt() getopt_long() 方便可选项的参数
            -g generate key 生成密钥
            -e encrypt 加密
            -d decrypt 解密
            [-c] console output 把输出也打印到控制台
        [1] 密钥 & 明文输入: 
            (1) 密钥可生成也可自己定义密钥文件 密钥长度是64位(bit)，超过位数密钥被忽略
            -g & -c 则 把密钥输出到控制台
            (2) 明文自己定义文件
            -c 后跟文件名 把文件二进制全部输出
        [2] 密文 加密结果输出:
            输出到文件 加上 -c 以字符和二进制两种形式输出到控制台
        [3] 模式
            (1) ECB : Electronic codebook 电子密码本
                需要加密的消息直接按照块密码的块大小被分为数个块，并对每个块进行独立加密。
            (2) CBC : Cipher-block chaining 密码块链接
                在CBC模式中，每个明文块先与前一个密文块进行异或后，再进行加密。
                在这种方法中，每个密文块都依赖于它前面的所有明文块。
                同时，为了保证每条消息的唯一性，在第一个块中需要使用初始化向量。
            (3) OFB : Output feedback 输出反馈
            (4) CFB : Cipher feedback 密文反馈
                
            (5) CTR : Counter 计数器模式
                CTR模式（Counter mode，CM）也被称为 ICM模式（Integer Counter Mode，整数计数模式）和SIC模式（Segmented Integer Counter）。
        [4] 长度超过要分组，分组后最后一个分组不足的需要填充
            (1) No Padding : 不填充
            (2) Zeros Padding : 全部填充 0x00
                已是 64bit 仍要填充
                如果原始文件以一个或多个零字节结尾，则零填充可能不可逆，从而无法区分明文数据字节和填充字节。
                当消息的长度可以从带外导出时，可以使用它。它通常应用于二进制编码的字符串（以空结尾的字符串），因为空字符通常可以作为空白去掉。
                零填充有时也称为“空填充”或“零字节填充”。如果明文已经被块大小整除，则一些实现可以添加额外的零字节块。
                示例：在以下示例中，块大小为8字节，4字节需要填充
                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 00 |
            (3) ISO 10126 : 
                ISO 10126规定，填充应在具有随机字节的最后一个分组的末尾完成， 并且所填充字节数应该由最后一个字节指定。
                示例：在以下示例中，块大小为8字节，4字节需要填充
                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 81 A6 23 04 |
            (4) Ansi X9.23 : 
                在ANSI X9.23中，总是添加1到8个字节作为填充。
                该块用随机字节填充（尽管许多实现使用00）
                并且块的最后一个字节被设置为添加的字节数。
                示例：在以下示例中，块大小为8字节，4字节需要填充（十六进制格式）
                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 |
            (5) PKCS 5 : 
                PKCS#7 定义于 RFC 5652 （征求意见草案第 5652 号）。
                PKCS #7 : 缺 n 个字节，就在后面填 n 个 n
                PKCS#5填充与PKCS#7填充相同，除了它仅被定义用于使用64位（8字节）块大小的块密码之外。实际上，两者可以互换使用。

                每个填充字节的值是用于填充的字节数。
                即是说，若需要填充 N 个字节，则每个填充字节值都是 N。填充的字节数取决于算法可以处理的最小数据块的字节数量。

                01
                02 02
                03 03 03
                04 04 04 04
                05 05 05 05 05
                06 06 06 06 06 06
                etc.

                示例：在以下示例中，块大小为8字节，4字节需要填充
                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 04 04 04 04 |

                注意: 若最后一个分组正好 8B，也要再填充 8B 的 0x08，否则无法解密。
    */
    /* [1] 输入参数校验 */
    if(key_file_name==NULL || input_file_name==NULL || output_file_name==NULL) { /* 前三个为必要参数 */
        printf(">>> The necessary parameters are missing, please check the input command.\n");
    }
    if(!file_exist(key_file_name)) {
        printf(">>> The key file does not exist, and can be generated using the -g instruction.\n");
        exit(1);
    }
    if(!file_exist(input_file_name)) {
        printf(">>> The file named [%s] does not exist, please check whether the file path is correct or there is a spelling error.\n", input_file_name);
        exit(1);
    }
    user_prompt_depends_on_existence_of_file(output_file_name);

    enum MODE_NAME mode = ECB;
    enum PADDING_WAY padding = PKCS7;

    /* 模式和填充方式校验 正确输入顺序是 padding mode iv_file_name */    
    /* 三个可选参数都没填（输入命令格式里位置最前的byte_padding_way都没填，后面两个一定没填），取默认值 mode=ECB, padding=PKCS7 */
    if(byte_padding_way == NULL) { 
        mode = ECB;
        padding = PKCS7;
    } else if(mode_name == NULL) { /* 只输入一个可选参数（输入命令格式里第二个mode_name没填，第三个iv一定没填） */
        if((padding=find_enum_padding(padding, byte_padding_way)) != -1) { /* 第一个参数是padding */
            mode = ECB; /* 取默认值 mode=ECB */
        } else { /* 第一个参数不是padding，就必须是mode */
            if((mode=find_enum_mode(mode, byte_padding_way)) != -1) { /* 第一个参数是mode */
                if(mode != ECB) { /* 非ECB必须输入初始向量iv，只有一个参数则iv没输入，输出错误提示 */
                    printf(">>> The initial vector file is not specified. It can be generated using the -g instruction.\n");
                    exit(1);
                }
                padding = PKCS7; /* padding没填取默认值 */
            } else { /* 第一个参数不是mode，单独填入一个iv没意义 */
                printf(">>> The parameters are incorrect, please check the input command.\n");
                exit(1);
            } // end of if-else mode
        } // end of if-else padding
    } else if(initialization_vector_file_name == NULL) { /* 只输入两个可选参数 */
        if((padding=find_enum_padding(padding, byte_padding_way)) != -1) { /* 第一个参数是padding */
            if((mode=find_enum_mode(mode, mode_name)) != -1) { /* 第二个参数是mode，则mode必须是ECB因为只有两个参数padding和mode */
                if(mode != ECB) { /* 非ECB必须输入初始向量iv，输出错误提示 */
                    printf(">>> The initial vector file is not specified. It can be generated using the -g instruction.\n");
                    exit(1);
                }
            } else { /* 第二个参数不是mode，则第二个参数肯定错了，不指定mode默认ECB，不需要IV */
                printf(">>> Please specify the mode provided.\n");
                exit(1);
            } // end of if-else mode
        } else { /* 第一个参数不是padding，就必须是mode */
            if((mode=find_enum_mode(mode, byte_padding_way)) != -1) { /* 第一个参数是mode */
                padding = PKCS7; /* padding没填取默认值 */
                initialization_vector_file_name = mode_name; /* 省略了padding，则输入的值对应差了一位 */
            } else { /* 第一个参数不是mode */
                printf(">>> Please specify the mode provided.\n");
                exit(1);
            } // end of if-else mode
        } // end of if-else padding
    } else { /* 如果都填了，需要校验填充方式和模式是否是给定的（对填充和模式的switch分支中的default处理了），iv文件是否存在（ECB不需要输入iv，就不做校验） */
        padding = find_enum_padding(padding, byte_padding_way);
        mode = find_enum_mode(mode, mode_name);
        if(mode!=ECB && !file_exist(initialization_vector_file_name)) {
            printf(">>> The initialization vector file does not exist, and can be generated using the -g instruction.\n");
            exit(1);
        }
    } // end of if-else_if-else    

    /* 初始校验完成，声明变量 */
    uint8_t need_padding; /* 是否需要填充，取决于 e_or_d */
    char key[DES_KEY_SIZE] = {0}; /* 密钥长度8B */
    uint64_t num_of_input_data_bytes = 0;
    /* 用于存储一个分组 8B 的数据 */
    char input_data_block[DES_BLOCK_BYTE_NUM+1] = {0};
    char output_data_block[DES_BLOCK_BYTE_NUM+1] = {0};
    char initialization_vector[DES_BLOCK_BYTE_NUM+1] = {0}; /* 初始向量 */
    char vector[DES_BLOCK_BYTE_NUM+1] = {0};
    char intermediate_data_block[DES_BLOCK_BYTE_NUM+1] = {0};
    char filled_input_file_name_prefix[] = "filled_inputfile_";
    char temp_file_suffix[] = ".destmpfile";
    /* 临时文件都存储到output_file相同目录 */
    char *pure_input_file_name = (char*)calloc(strlen(input_file_name)+1, sizeof(char));
    if(!seperate_file_and_path(input_file_name, NULL, pure_input_file_name)) { /* 路径切分失败，则原文件名不包含路径，直接使用原文件名 */
        strcpy(pure_input_file_name, input_file_name);
    }
    seperate_file_and_path(input_file_name, NULL, pure_input_file_name);
    char *filled_input_file_name = assemble_file_name(output_file_name, filled_input_file_name_prefix, temp_file_suffix, pure_input_file_name);
    free(pure_input_file_name);
    char *temp_vector_file_name = NULL; /* 暂存向量的临时文件名，仅ofb和ctr会使用，保存到 output_file同目录 */

    /* 将填充好的输入文件存储进临时文件，直接存储到源文件到最后还需要删掉填充内容，否则再次执行程序填充内容会出错
        而删掉源文件的指定内容没办法直接操作源文件实现，需要临时文件的参与
        故直接采用临时文件存储，结束时删除临时文件
     */
    if(file_exist(filled_input_file_name)) { /* 存在的话输出覆盖提示 */
        user_prompt_depends_on_existence_of_file(filled_input_file_name);
    }

    /* [2] 文件填充成分组的整数倍存入申请的动态内存
            填充密钥文件: 超出8B的直接舍弃, 不足8B按照明文相同规则填充
            明文文件: 按规则填充后保存到申请的动态内存
    */
    /* 密钥填充，填充好的密钥加载入内存 */
    if(e_or_d == ENCRYPTION) { /* 加密才填充，解密不要填充 */
        /* 输入文件填充 */
        num_of_input_data_bytes = load_blocks_file(input_file_name, filled_input_file_name, input_data_block, padding);
        need_padding = TRUE;
    } else { /* 加密操作使用填充后的临时文件(filled)，解密使用原文件，为后续统一操作，将两者文件名统一 */
        free(filled_input_file_name);
        filled_input_file_name = input_file_name;
        // strcpy(filled_input_file_name, input_file_name); /* 怕长度超出越界 */
        num_of_input_data_bytes = count_file_length(filled_input_file_name);
        need_padding = FALSE;
    }
    load_one_block_file(key_file_name, key, padding, need_padding);
    /* 初始向量填充后载进内存，ECB不需要 */
    if(mode != ECB) {
        load_one_block_file(initialization_vector_file_name, initialization_vector, padding, need_padding);
    }

    /* [3] 根据模式操作加解密 */
    switch(mode) {
        /* ECB直接分组并对各个分组加密 */
        case ECB: { 
            FILE* filled_input_file = fopen(filled_input_file_name, "rb");
            if(filled_input_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
                exit(1);
            }
            FILE* output_file = fopen(output_file_name, "wb");
            if(output_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", output_file_name, strerror(errno));
                exit(1);
            }
            fseek(filled_input_file, 0L, SEEK_SET);
            while(fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file)) {
                des(input_data_block, key, output_data_block, e_or_d);
                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, output_file);
                memset(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM);
                memset(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM);
            } // end of while
            fclose(filled_input_file);
            fclose(output_file);
            break;
        } // end of case ECB
        /* CBC模式中，每个明文块先与前一个密文块进行异或后，再进行加密。在第一个块中需要使用初始化向量。 */
        case CBC: {
            FILE* filled_input_file = fopen(filled_input_file_name, "rb");
            if(filled_input_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
                exit(1);
            }
            FILE* output_file = fopen(output_file_name, "wb");
            if(output_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", output_file_name, strerror(errno));
                exit(1);
            }
            fseek(filled_input_file, 0L, SEEK_SET);
            strcpy(vector, initialization_vector); /* 先把初始向量赋给向量分组，加密时异或发生在des()前，解密时异或发生在des()后 */

            while(fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file)) {
                if(e_or_d == ENCRYPTION) { /* 加密时异或发生在des()前 */
                    char_array_xor(input_data_block, vector, DES_BLOCK_BYTE_NUM);
                }
                des(input_data_block, key, output_data_block, e_or_d);
                if(e_or_d == DECRYPTION) { /* 解密时异或发生在des()后 */
                    char_array_xor(output_data_block, vector, DES_BLOCK_BYTE_NUM);
                }

                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, output_file);
                
                if(e_or_d == ENCRYPTION) { /* 加密时每一分组加密的结果为下一轮的向量 */
                    strcpy(vector, output_data_block);
                } else { /* 解密时每一分组的输入密文为下一轮的向量 */
                    strcpy(vector, input_data_block);
                }
            } // end of while
            fclose(filled_input_file);
            fclose(output_file);
            break;
        } // end of case CBC
        /* OFB模式，明文 n 个分组，则对初始向量IV加密 n 次，得到 n 个向量，明文各个分组分别异或向量得到 n 个分组密文
            加解密步骤相同
         */
        case OFB: {
            uint64_t input_data_blocks_num = num_of_input_data_bytes / DES_BLOCK_BYTE_NUM;
            temp_vector_file_name = assemble_file_name(output_file_name, "ofb_vector_", temp_file_suffix, NULL);
            FILE* temp_vector_file = fopen(temp_vector_file_name, "wb");
            if(temp_vector_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", temp_vector_file_name, strerror(errno));
                exit(1);
            }
            FILE* filled_input_file = fopen(filled_input_file_name, "rb");
            if(filled_input_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
                exit(1);
            }
            FILE* output_file = fopen(output_file_name, "wb");
            if(output_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", output_file_name, strerror(errno));
                exit(1);
            }
            strcpy(input_data_block, initialization_vector);
            for(uint64_t i=0; i<input_data_blocks_num; i++) {
                des(input_data_block, key, output_data_block, ENCRYPTION); /* 加解密都是对向量加密 */
                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, temp_vector_file);
                strcpy(input_data_block, output_data_block);
            } // end of for
            fseek(temp_vector_file, 0L, SEEK_SET);
            while(fread(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file)) {
                fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, temp_vector_file);
                char_array_xor(output_data_block, input_data_block, DES_BLOCK_BYTE_NUM);
                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, output_file);
            } // end of while
            fclose(temp_vector_file);
            fclose(filled_input_file);
            fclose(output_file);
            break;
        } // end of case OFB
        /* CFB模式: 对向量加密后与明文异或得到密文，这个密文作为下一个向量
            加解密的唯一差别在于每轮作为 des() 输入的向量取值不同，加密下一轮输入的向量为本轮的结果，而解密下一轮输入的向量为本轮从密文文件中取出的分组
         */
        case CFB: {
            FILE* filled_input_file = fopen(filled_input_file_name, "rb");
            if(filled_input_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
                exit(1);
            }
            FILE* output_file = fopen(output_file_name, "wb");
            if(output_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", output_file_name, strerror(errno));
                exit(1);
            }
            fseek(filled_input_file, 0L, SEEK_SET);
            strcpy(vector, initialization_vector); /* 先把初始向量赋给输出的分组，每次读取输入分组后先异或上一轮的输出分组 */

            while(fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file)) {
                des(vector, key, output_data_block, ENCRYPTION); /* 先加密向量，加解密都是对向量进行des加密 */
                char_array_xor(output_data_block, input_data_block, DES_BLOCK_BYTE_NUM); /* 向量与明文异或 */
                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, output_file); /* 写入加密输出文件 */

                if(e_or_d == ENCRYPTION) { /* 加密下一轮输入的向量为本轮的结果 */
                    strcpy(vector, output_data_block); /* 本轮输出为下一轮的向量 */
                } else { /* 解密下一轮输入的向量为本轮从密文文件中取出的分组 */
                    strcpy(vector, input_data_block); /* 本轮输出为下一轮的向量 */
                }
                
                memset(input_data_block, 0, DES_BLOCK_BYTE_NUM);
            } // end of while
            fclose(filled_input_file);
            fclose(output_file);
            break;
        } // end of case CFB
        /* CFR: 由初始向量IV累加1得到各个向量，向量加密后与明文分组异或得到密文分组
            加解密流程一致，加解密都是用des算法加密向量
         */
        case CTR: {
            /* 先生成向量存储到向量临时文件 */
            uint64_t input_data_blocks_num = num_of_input_data_bytes / DES_BLOCK_BYTE_NUM;
            temp_vector_file_name = assemble_file_name(output_file_name, "ctr_vector_", temp_file_suffix, NULL);
            FILE* temp_vector_file = fopen(temp_vector_file_name, "wb");
            if(temp_vector_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", temp_vector_file_name, strerror(errno));
                exit(1);
            }
            strcpy(vector, initialization_vector);

            for(uint64_t i=0; i<input_data_blocks_num; i++) {
                fwrite(vector, sizeof(char), DES_BLOCK_BYTE_NUM, temp_vector_file);
                char_array_counter(vector, DES_BLOCK_BYTE_NUM);
            }

            fseek(temp_vector_file, 0L, SEEK_SET);

            FILE* filled_input_file = fopen(filled_input_file_name, "rb");
            if(filled_input_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", filled_input_file_name, strerror(errno));
                exit(1);
            }
            FILE* output_file = fopen(output_file_name, "wb");
            if(output_file == NULL) {
                fprintf(stderr, ">>> Error opening file [%s]: %s\n>>> Please check if the file path is misspelled, The program cannot create a file in a folder that does not exist.\n", output_file_name, strerror(errno));
                exit(1);
            }

            while(fread(input_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, filled_input_file)) {
                fread(vector, sizeof(char), DES_BLOCK_BYTE_NUM, temp_vector_file); /* 读取向量中当前明文分组对应向量分组 */
                des(vector, key, output_data_block, ENCRYPTION); /* 先加密向量 */
                char_array_xor(output_data_block, input_data_block, DES_BLOCK_BYTE_NUM); /* 向量与明文异或 */
                fwrite(output_data_block, sizeof(char), DES_BLOCK_BYTE_NUM, output_file); /* 写入加密输出文件 */
                memset(input_data_block, 0, DES_BLOCK_BYTE_NUM);
            } // end of while
            fclose(temp_vector_file);
            fclose(filled_input_file);
            fclose(output_file);
            break;
        } // end of case CTR
        default: {
            printf(">>> The entered mode does not exist. Please check the spelling. The mode can only be the following values (both upper and lower case are acceptable): ECB | CBC | OFB | CFB | CTR.\n");
            exit(1);
        } // end of default
    } // end of switch(mode)

    /* 解密需要去掉明文填充 */       
    if(e_or_d == DECRYPTION) {  
        /* 根据填充方式去掉填充 */
        switch(padding) {
            case ZERO: {
                FILE* output_file = fopen(output_file_name, "rb");
                fseek(output_file, -1L, SEEK_END);
                char padding_bytes_num = 0;
                char file_one_byte = 0;
                /* 计算文件结尾填充了多少零 */
                while(fread(&file_one_byte, sizeof(char), sizeof(char), output_file) && (file_one_byte==0)) {
                    padding_bytes_num++;
                    fseek(output_file, -1L-padding_bytes_num, SEEK_END); /* 文件从后往前读 */
                } // end of while
                fclose(output_file);
                uint64_t num_of_final_output_data_bytes = num_of_input_data_bytes - padding_bytes_num;
                delete_file_content(output_file_name, num_of_final_output_data_bytes, padding_bytes_num, DES_BLOCK_BYTE_NUM);
                break;
            } // end of case ZERO
            default: {
                FILE* output_file = fopen(output_file_name, "rb");
                fseek(output_file, -1L, SEEK_END);
                char padding_bytes_num = 0;
                fread(&padding_bytes_num, sizeof(char), sizeof(char), output_file);
                fclose(output_file);
                uint64_t num_of_final_output_data_bytes = num_of_input_data_bytes - padding_bytes_num;
                delete_file_content(output_file_name, num_of_final_output_data_bytes, padding_bytes_num, DES_BLOCK_BYTE_NUM);
                break;
            } // end of case default
        } // end of switch(padding)
    } // end of if

    /* 询问是否全部删除中间的一些临时文件
        [1] 加密的话会生成填充临时文件，解密没有
        [2] ctr和ofb会生成向量临时文件
     */
    user_prompt_delete_tmpfile(filled_input_file_name, e_or_d);
    if(e_or_d == ENCRYPTION) {
        remove(filled_input_file_name);
        /* 释放动态内存，解密的情况在前面已经释放掉了 */
        free(filled_input_file_name);
    }
    if(mode==OFB || mode==CTR) {
        remove(temp_vector_file_name);
    }
} // end of desProcess()