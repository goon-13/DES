#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>
#include<math.h>

#include "common.h"

/**
  * @brief  [小端方式存储]将传入的char型数据(一个字节)转换为8位二进制并返回(8位二进制采用char型数组存储，输出需要使用%s或%c)
  * @param  one_byte[] 传入的一个字节
  * @param bits 转换成的8位二进制
  * @retval 无
  */
void char_to_bin_8bits(char one_byte, char bits[]) {
  memset(bits, 0, 8);
  unsigned char *p = (unsigned char*)&one_byte;

  for(int i=0; i<8; i++) {
    /*  1 << i : 将 1 向高位移，如 1<<3 = 1000
        *p 取出one_byte整个字节内容，&上1<<i则是由低位向高位逐bit取出数据
    */
    if(*p & (1<<i)) { /* 由低位逐渐取至高位 */
      bits[7-i] = '1';
    } else {
      bits[7-i] = '0';
    }
  } // end of for
}

/**
  * @brief  [小端方式存储]将传入的char型数组(多个字节)转换为8位二进制并返回，每8位存储一个空格(二进制串采用char型数组存储，输出需要使用%s或%c)
  * @param bytes[] 传入的多个字节
  * @param bits 转换成的二进制串
  * @param bits_length 总共字符串有多少位bit位，要加多少空格和最后的字符串结束符函数内会计算，传值时不考虑
  * @retval 无
  */
void char_to_bin(char bytes[], char bits[], unsigned int bits_length) {
  unsigned char bit_offset = bits_length % 8; /* 若最后一个字节未填满，最后一个字节有几位数据 */
  unsigned int bytes_length = bit_offset ? bits_length/8+1 : bits_length/8; /* bit串存储共占几个字节 */
  bits_length += (bytes_length-1); /* 每个字节要插入一个空格，最后一个字节后面不需要加空格 */
  memset(bits, 0, bits_length+1);

  /* 外层循环遍历字节，内层循环遍历字节内的位
      [1] 先将 bits 的数组下标 +8*i+i,  +i为插入的空格数量
      [2] 每个字节处理完要加上一个空格
   */
  for(int i=0; i<bytes_length; i++) {
    char byte = bytes[i];
    for(int j=0; j<8; j++) {
      /*  1 << i : 将 1 向高位移，如 1<<3 = 1000
          byte整个字节内容 & 上1<<i则是由低位向高位逐bit取出数据
      */
      if(byte & (0x80>>j)) { /* 由高位逐渐取至低位 */
        bits[8*i + i + j] = '1';
      } else {
        bits[8*i + i + j] = '0';
      }
    } // end of for j
    if(i != bytes_length-1) { /* 最后一个字节后面不加空格 */
      bits[8*i + i + 8] = ' '; /* 每个字节处理完要加上一个空格 */
    }
  } // end of for i
}

/**
  * @brief  (单字节)将一个字节的位循环左移
  * @param  byte 待移位字节
  * @param  shift_digit 循环左移多少位
  * @retval 无
  */
void rotate_left_one_byte(char* byte, unsigned int shift_digit) {
    shift_digit %= 8;
    for(int i=0; i<shift_digit; i++) {
        char highest_position = *byte & 0x80; /* 取出byte的最高位，因为左移操作最高位会溢出丢失 */
        *byte <<= 1; /* byte左移1位 */
        if(highest_position) { /* 如果最高位是1，最低位需要置1达到循环的效果 */
            *byte |= 0x01;
        }
    } // end of for
} // end of function rotate_left_one_byte()

/**
  * @brief  (多字节)将char 数组中的位循环左移，char数组最后一个字节可能填不满，比如最后一个字节仅占高四位
  * @param  byte 待移位字节
  * @param  shift_digit 循环左移多少位
  * @retval 无
  */
void rotate_left_bits(char char_array[], unsigned int shift_digit, unsigned int bit_length) {
    /* 循环左移只有每个字节的高位会发生溢出 */
    unsigned char bit_offset = bit_length % 8; /* 若最后一个字节未填满，最后一个字节有几位数据 */

    /* 若最后一个字节有效bit位数 < 左移位数，暂时不实现这种情况的处理 */
    if(shift_digit > bit_offset) {
        return;
    }

    unsigned int array_length = bit_offset ? bit_length/8+1 : bit_length/8; /* bit串存储共占几个字节 */
    unsigned char* overflow_position;
    unsigned int i = 0;

    shift_digit %= 8;
    overflow_position = (unsigned char*)calloc(array_length+1, sizeof(char));

    unsigned char get_overflow_bits = 0x00; /* 用于 byte 进行 & 操作 取出溢出位 */
    switch(shift_digit) {
        case 0: {get_overflow_bits=0x00; break;} /* 0x00 = 0000 0000 不左移，无溢出 */
        case 1: {get_overflow_bits=0x80; break;} /* 0x80 = 1000 0000 左移 1 位，溢出 最高位 */
        case 2: {get_overflow_bits=0xC0; break;} /* 0xC0 = 1100 0000 左移 2 位，溢出 最高 2 位 */
        case 3: {get_overflow_bits=0xE0; break;} /* 0xE0 = 1110 0000 左移 3 位，溢出 最高 3 位 */
        case 4: {get_overflow_bits=0xF0; break;} /* 0xF0 = 1111 0000 左移 4 位，溢出 最高 4 位 */
        case 5: {get_overflow_bits=0xF8; break;} /* 0xF8 = 1111 1000 左移 5 位，溢出 最高 5 位 */
        case 6: {get_overflow_bits=0xFC; break;} /* 0xFC = 1111 1100 左移 6 位，溢出 最高 6 位 */
        case 7: {get_overflow_bits=0xFE; break;} /* 0xFE = 1111 1110 左移 7 位，溢出 最高 7 位 */
    } 
    /* 把bit串整体左移 shift_digit 位，以字节为单位从低位向高位遍历
        [1] 从最后一个字节开始，取出最高位溢出位，待前一个字节进行左移操作后再将 低位 置为取出的溢出位
        [2] 如此往前，每一轮进行 取出当前字节高位溢出位，|=后一个字节的溢出位
        [3] 到首字节，取出溢出位后，要|=到最后一个字节的bit有效位的末尾，采用 
            overflow[0] << bit_offset; 
            overflow[0]为首字节的高位溢出位
        [4] 最后一个字节若有效bit长度 < 左移位数，溢出位需要拼接上首字节溢出位 -- 暂时不实现
     */
    for(i=0; i<array_length; i++) { /* 第一个for循环存储高位溢出 */
        char byte = char_array[i];
        int overflow_array_index = i-1; /* 每个字节的高位溢出是赋给前一个字节的低位的 */
        if(overflow_array_index < 0) {
            overflow_array_index = array_length-1; /* 首字节的高位溢出是要赋给末尾字节的低位的 */
        }
        unsigned int bit_length_of_this_byte = overflow_array_index==(array_length-1) ? bit_offset : 8;
        overflow_position[overflow_array_index] = (byte & get_overflow_bits) >> (bit_length_of_this_byte-shift_digit); /* 取出byte的最高位，因为左移操作最高位会溢出丢失，并放到字节的低位上方便第二轮for循环置位 */
    } // end of for i
    for(i=0; i<array_length; i++) { /* 第二个for循环将高位溢出逐个赋给各个字节低位 */
        /* 先左移操作 */
        char_array[i] <<= shift_digit; /* 要<<=，而不是<<，否则没赋值 */
        /* 再置低位溢出位 */
        char_array[i] |= overflow_position[i];
    } // end of for i
} // end of function rotate_left_bits()

/**
  * @brief  将 text 按照 permutation_table 的置换规则置换后，结果存储至 after_permutation
  * @param  after_permutation[] 置换后结果
  * @param  text[] 待置换数组
  * @param  permutation_table[] 置换规则表
  * @param  table_length 置换规则表的长度，用于遍历逐个取出置换表的值
  * @retval 无
  */
void permutation(char after_permutation[], char text[], unsigned int permutation_table[], unsigned int table_length) {
    /* 传入的after_permutation若有使用过，残留了数据，需要先全部置0清空一下 */
    for(int i=0; i<table_length/8; i++) {
        after_permutation[i] &= 0x00;
    }
    /* (1_1) 初始置换IP
        遍历IP表，将文本分组 text[] 第 IP[i] bit的数据取出
        存至 after_initial_permutation[] 的第 i bit
        从而实现将 text[] 进行初始IP置换，结果存储在 after_initial_permutation[]
        
        对字节进行左移右移操作时，移动的位数需要-1
        因为使用的移动位数 是 这个bit在字节中的第几位，从最高位（首位）要到达它，只需要移动 [位数-1] 位就可以了
        比如要从第1位移动至第6位，实际只需要右移 6-1 = 5位即可到达
    */
    for(int i=0; i<table_length; i++) {
        /*  IP置换表为地图，按着IP表找到 置换后第 i 位 存储的 原来 text[] 中的对应位
            text[] 为char型数组，每个元素占1B即8bit，设 text[] 长度为 n
            定位 text[] 的 第 x bit 由两个维度确定 ==> x 取值范围应为 0~63 而不是 1~64
            x / 8 ==> 得到第 x bit在text[]中第几个元素（也即第几个字节） --> x/8 结果的范围为 0~n-1 对应数组下标
            x % 8 ==> 得到第 x bit在其所属元素（字节）的第几位 --> x%8 结果的范围为 0~7
         */
        /* [0] 将IP表取出的 第 x bit 的位置下标 取值范围 1~64 映射至 0~63
            x / 8 : 
                text[0] 对应位数 : 0~7
                    若直接取 IP表的值，应该对应第 1~8 位，而1~7除以8的结果可以得到0，但8/8=1，会找到text[1]去
                    故 对应 0~7 位，则前八个位可以正确对应到 text[0] 的 0 下标的元素
                text[1] 对应位数 : 8~15
                text[2] 对应位数 : 16~23
                ...
            x % 8 : 结果范围应该是 0~7，若直接使用IP表中值，比如第 1 位，1%8 = 1，1本应该在第一个字节的最高位，若取值为0直接找第一位就方便了
            综上，先将 IP表中取出的值进行 减1 操作，方便后续处理
            IP表中还是按照DES的规定存储原来的位置信息即范围在 1~64
        */
        int table_index = permutation_table[i] - 1;
        /* [1] text[0] 对应 1~8 bit ... */
        unsigned char from_which_elem_index = table_index / 8;
        /* [2] x % 8 取值范围 0~7 */
        unsigned char from_which_bit_of_elem = table_index % 8;
        /* [3] 取出 x 元素存到一个字节里，x在其所属字节的相对位置保持不变，其余位都置为0 
                0x80 = 1000 0000
                >> : 二进制右移运算符。将一个数的各二进制位全部右移若干位，正数左补0，负数左补1，右边丢弃。                
                因为使用的移动位数 是 这个bit在字节中的第几位，从最高位（首位）要到达它，只需要移动【位数-1】位就可以了
                & : 与操作，有0则0，全1才1
                将x所在字节的数据 & 上0x80>>from_which_bit_of_elem，除了目标位外全部置0
        */
        unsigned char original_bit = text[from_which_elem_index] & (0x80>>from_which_bit_of_elem);
        /* [4] 将 目标位的数据 移动到 i 所在的对应于所属字节的相对位置
                未处理时 是 x 元素在其置换前所属字节中的相对位置
                先将 x 左移到字节的最高位，再右移至 i 在其所属字节中的相对位置 (i%8)
                -- from_which_bit_of_elem需要进行-1操作 -- 第[0]步先对IP表中取出的值进行减1操作，这一步就不需要了
                -- 因为比如要从第1位移动至第6位，实际只需要右移 6-1 = 5位即可到达 -- 第[0]步先对IP表中取出的值进行减1操作，这一步就不需要了
                而 i%8 不需要减1，因为 i 为数组下标，从0开始，相当于已经进行过 减1 的操作了
        */
        unsigned char original_bit_shift_to_i = (original_bit<<from_which_bit_of_elem) >> (i%8);
        /* [5] i/8 得到置换后的数组将[3]所得目标位存储到哪一个字节中
                |= ： 一般用在置位，即置1，1的位置1，0的位保持不变。        
        */
        /* 需要将 目标位的数据 移动到 i 所在的对应于所属字节的相对位置 */
        after_permutation[i/8] |= original_bit_shift_to_i;
    } // end of for
} // end of function permutation()

/**
  * @brief  判断文件是否存在，存在返回1，不存在返回0
  * @param  file_name 指向文件名字符串
  * @retval result 存在返回1，不存在返回0
  */
int file_exist(char* file_name)
{
  /* 利用fopen的可读属性判断文件是否存在。
    fopen以读的形式打开文件，只有当文件不存在时，返回值才为空
    如果文件没有可读属性，只要文件存在，也可以被打开并读出其内容。
 */
  FILE* temp = fopen(file_name, "r");
  int result = 1;
  if(temp == NULL) {
    result = 0;
  } else {
    fclose(temp);
  }
  return result;
}

/**
  * @brief  计算文件长度(字节数)
  * @param  file_name 指向文件名字符串
  * @retval 无
  */
uint32_t count_file_length(char* file_name) {
  FILE* file = fopen(file_name, "r");
  fseek(file, 0L, SEEK_END); /* 文件到结尾 */
  /* C 库函数 long int ftell(FILE *stream) 返回给定流 stream 的当前文件位置。uint32_t==unsigned==unsigned long */
  uint32_t file_size = ftell(file);
  fseek(file, 0L, SEEK_SET); /* 文件回到开头 */
  fclose(file);
  return file_size;
}

/**
  * @brief  将 dest 数组和 source 数组进行异或，内容存储进 dest 数组，两个数组长度需要一致
  * @param  dest[]
  * @param  source[]
  * @param  array_length 数组长度
  * @retval 无
  */
void char_array_xor(char dest[], char source[], int array_length) {
  for(int i=0; i<array_length; i++) {
    dest[i] ^= source[i];
  } 
}

/**
  * @brief  对char数组进行+1与数组元素间进位操作，数组元素是补码表示
  * @param  array[]
  * @param  array_length 数组长度
  * @retval 无
  */
void char_array_counter(char array[], int array_length) {
  uint8_t carry_bit = 1; /* 进位位，最低位要加1，置为进位的初始值 */
  int i = array_length-1;

  while(i >= 0) {
    uint16_t elem = (uint8_t)array[i]; /* 更大空间能存储溢出的进位 */
    uint16_t byte_plus_carry = elem + carry_bit;
    array[i] += carry_bit;
    if(byte_plus_carry > 255) { /* +1后超出 1111 1111 = 255，产生进位 */
      carry_bit = 1;
    } else {
      break; /* 没进位了就结束 */
    }
    i--;
  }
} // end of function char_array_counter()

/**
* @brief 把一个文件的指定内容复制到另一个文件
* @param dest_file_name 要复制的源文件文件名
* @param source_file_name 复制的目标文件名
* @param dest_offset 目标文件的位置偏移，也就是复制到目标文件的什么位置
* @param source_offset 源文件的位置偏移（相对文件开头），也就是从哪里开始复制
* @param copy_len 要复制的内容长度，等于0表示复制source_offset后边的所有内容
* @param buffer_bytes_length 缓冲区长度，每次读取源文件的一个块存入缓存再写入目标文件
* @return 成功复制的字节数
**/
uint64_t fcopy(FILE* dest_file, FILE* source_file, uint64_t dest_offset, uint64_t source_offset, uint64_t copy_len, uint64_t buffer_bytes_length){
  char* buffer = (char*)calloc(sizeof(char), buffer_bytes_length); /* 开辟缓存 */ 
  int count_fread_bytes; /* 每次调用fread()读取的字节数 */ 
  uint64_t num_of_copy_bytes = 0; /* 总共复制了多少个字节 */
  int num_of_fread = 0; /* 需要调用多少次fread()函数 */
  int i; /* 循环控制变量 */
  /* 把文件流当前位置指向指定位置 */
  fseek(source_file, source_offset, SEEK_SET);
  fseek(dest_file, dest_offset, SEEK_SET);
  if(copy_len == 0) { /* 复制所有内容 */
    while( (count_fread_bytes=fread(buffer, sizeof(char), buffer_bytes_length, source_file)) > 0 ) {
      num_of_copy_bytes += count_fread_bytes;
      fwrite(buffer, count_fread_bytes, 1, dest_file);
    } // end of while
  } else { /* 复制copy_len个字节的内容 */
    /* copy_len%buffer_bytes_length==0说明整除 */
    num_of_fread = copy_len/buffer_bytes_length + ((copy_len%buffer_bytes_length)?1:0); 
    for(i=1; i<=num_of_fread; i++) {
      uint64_t num_of_remain_bytes = copy_len - num_of_copy_bytes;
      if(num_of_remain_bytes < buffer_bytes_length) { 
        buffer_bytes_length = num_of_remain_bytes;
      }
      count_fread_bytes = fread(buffer, sizeof(char), buffer_bytes_length, source_file);
      fwrite(buffer, sizeof(char), count_fread_bytes, dest_file);
      num_of_copy_bytes += count_fread_bytes;
    } // end of for
  } // end of if-else
  /* C 库函数 int fflush(FILE *stream) 刷新流 stream 的输出缓冲区。 如果成功，该函数返回零值。如果发生错误，则返回 EOF，且设置错误标识符（即 feof）。 */
  fflush(dest_file);
  free(buffer);
  return num_of_copy_bytes;
} // end of function fcopy()

/**
* @brief 删除指定文件的指定内容，通过临时文件先复制源文件要保留的内容再覆盖源文件实现，删掉源文件从 offset 开始 len 长度的内容
* @param file_name 待操作源文件文件名
* @param offset 删掉源文件从 offset 开始 len 长度的内容
* @param len 删掉源文件从 offset 开始 len 长度的内容
* @param buffer_length 缓冲区长度，每次读取源文件的一个块存入缓存再写入目标文件
* @return 成功复制的字节数
**/
int delete_file_content(char* file_name, uint64_t offset, uint64_t len, uint64_t buffer_bytes_length){
  uint64_t file_size = count_file_length(file_name);
  /* C 库函数 char *tmpnam(char *str) 生成并返回一个有效的临时文件名，该文件名之前是不存在的。如果 str 为空，则只会返回临时文件名。 */
  if(offset>file_size || offset<0 || len<0){ /* 参数校验 */
    return -1;
  }
  FILE* file = fopen(file_name, "rb");
  FILE* temp_file = tmpfile();
  fcopy(temp_file, file, 0, 0, offset, 8); //将前offset字节的数据复制到临时文件
  fcopy(temp_file, file, offset+len, offset, -1, 8); //将offset+len之后的所有内容都复制到临时文件

  freopen(file_name, "wb", file);
  fcopy(file, temp_file, 0, 0, 0, 8);
  
  fclose(file);
  fclose(temp_file);
  return 0;
} // end of function

/**
* @brief 分离一个完整的文件路径为文件名(带后缀)以及其所属路径，需要确保传入的完整路径是字符串，即最后一位为字符串结束符号
* @param file_path 待操作完整文件路径
* @param path_name 分离出的文件路径，可以为NULL值，则函数内申请动态内存
* @param file_name 文件名，可以为NULL值，则函数内申请动态内存，满足仅需要路径或者仅需要文件名的需求
* @return 成功返回1，失败返回0(文件路径不包含斜杠等情形)
**/
uint8_t seperate_file_and_path(char *file_path, char *path_name, char *file_name) {
  uint32_t file_path_length = strlen(file_path);
  uint8_t path_null = 0; /* 传入参数为空标志，方便后续结束时free申请的动态内存 */
  uint8_t name_null = 0;
  if(path_name == NULL) { /* 可以为NULL值，则函数内申请动态内存 */
    path_name = (char*)calloc(file_path_length, sizeof(char));
    path_null = 1;
  }
  if(file_name == NULL) {
    file_name = (char*)calloc(file_path_length, sizeof(char));
    name_null = 1;
  }
  uint32_t index;
  for(index=file_path_length-1; index>0; index--) {
    if(file_path[index] == '\\' || file_path[index] == '/') { /* 倒着寻找最后文件名前的斜杠号 */
      break;
    }
  } // end of for
  if(index == 0 || (path_null && name_null)) { /* 没找到斜杠，或者没传入接收分离结果的字符指针则函数继续进行也没意义，结果无法保存 */
    return 0;
  }
  /* 路径长度 index+1，还需要一个字符串结束符号 */
  memset(path_name, 0, index+2);
  /* 路径总长度 file_path_length，文件名前面的路径长度为index+1（index下标从0开始），故文件名长度 file_path_length-(index+1)，而文件名字符串最后还需要一位存储字符串结束符 0 */
  memset(file_name, 0, file_path_length-index);
  for(uint32_t i=0; i<=index; i++) {
    path_name[i] = file_path[i];
  }
  path_name[index+1] = '\0';
  for(uint32_t i=index+1; i<file_path_length; i++) {
    file_name[i-index-1] = file_path[i];
  }
  file_name[file_path_length-index-1] = '\0';
  if(path_null) {
    free(path_name);
  }
  if(name_null) {
    free(file_name);
  }
  return 1;
}

/**
* @brief 拼装文件名，路径会保持与source_file_name一致
* @param prefix 要拼装的文件名前缀
* @param suffix 要拼装的文件名后缀
* @param source_file_name 原文件名，如果是带路径的要把路径拷贝到前缀的前面
* @param middle_name 文件的中间名，为NULL则直接取source_file的文件名
* @return 成功返回1，失败返回0(文件路径不包含斜杠等情形)
**/
char* assemble_file_name(char *source_file_name, char *prefix, char *suffix, char *middle_name) {
  uint8_t contain_path = 0; /* 原文件是否包含路径 */

  char *file_path = (char *)calloc(strlen(source_file_name)+1, sizeof(char));
  char *pure_file_name = (char *)calloc(strlen(source_file_name)+1, sizeof(char));
  contain_path = seperate_file_and_path(source_file_name, file_path, pure_file_name);

  /* 文件长度要算对，否则动态申请的内存在free时会出错，可能引起越界，但越界不一定直接报错，可能覆盖了crt的统计信息，导致free的时候出问题 */
  uint32_t path_and_file_len = (middle_name==NULL) ? strlen(source_file_name) : (strlen(source_file_name)-strlen(pure_file_name)+strlen(middle_name));
  uint32_t assemble_file_name_len = strlen(prefix) + strlen(suffix) + path_and_file_len + 1;
  /* 用于暂存原输入文件名,+1因为要存字符串结束符 */
  char *result_file_name = (char *)calloc(assemble_file_name_len, sizeof(char));

  if(contain_path) { /* 包含路径，要把路径放到前缀前面 */
    strcpy(result_file_name, file_path); /* 路径 */
    strcat(result_file_name, prefix); /* 前缀 */
    strcat(result_file_name, (middle_name==NULL || strlen(middle_name)==0)?pure_file_name:middle_name); /* 中间原文件名 */
  } else { /* 不包含路径，前缀直接放到最前 */
    strcpy(result_file_name, prefix); /* 前缀 */
    strcat(result_file_name, (middle_name==NULL || strlen(middle_name)==0)?source_file_name:middle_name); /* 中间原文件名 */
  }
  strcat(result_file_name, suffix); /* 后缀名 */
  
  free(file_path);
  free(pure_file_name);

  return result_file_name;
}