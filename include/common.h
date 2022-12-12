#include<stdint.h>

#ifndef __COMMON_H__
#define __COMMON_H__

void char_to_bin_8bits(char one_byte, char bits[]); /* 将传入的char型数据(一个字节)转换为8位二进制并返回(8位二进制采用char型数组存储，输出需要使用%s或%c) */
void char_to_bin(char bytes[], char bits[], unsigned int bits_length);
void rotate_left_one_byte(char* byte, unsigned int shift_digit);
void rotate_left_bits(char char_array[], unsigned int shift_digit, unsigned int bit_length);
void permutation(char after_permutation[], char text[], unsigned int permutation_table[], unsigned int table_length);
int file_exist(char* file_name);
uint32_t count_file_length(char* file_name);
void char_array_xor(char dest[], char source[], int array_length);
void char_array_counter(char array[], int array_length);
int delete_file_content(char* file_name, uint64_t offset, uint64_t len, uint64_t buffer_bytes_length);
uint8_t seperate_file_and_path(char *file_path, char *path_name, char *file_name);
char* assemble_file_name(char *source_file_name, char *prefix, char *suffix, char *middle_name);

#endif