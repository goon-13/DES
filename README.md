# DES-密码学教材中DES算法的C语言实现

## 参考-Reference
参考了[tarequeh](https://github.com/tarequeh)的[DES](https://github.com/tarequeh/DES)，采用相同的命令行使用方式。  
命令行选项参数解析在windows x64环境下使用[alex85k](https://github.com/alex85k)的[wingetopt](https://github.com/alex85k/wingetopt)。  
关于getopt()的使用参考[getopt-优雅地处理命令行参数](https://www.yanbinghu.com/2019/08/17/57486.html)。  

感谢~😀

Refer to the 的[DES](https://github.com/tarequeh/DES) of [tarequeh](https://github.com/tarequeh), the program is also used through the command line like tarequeh.  
The command line option parameter resolution uses the [wingetopt](https://github.com/alex85k/wingetopt) of [alex85k](https://github.com/alex85k) in the Windows x64 environment.  
The reference for using getopt(): [getopt-gracefully handles command line arguments](https://www.yanbinghu.com/2019/08/17/57486.html).

Thanks~ 😀
## 简介-Brief Introduction
代码为密码学教材("Cryptography Theory and Practice Third Edition")中Data Encryption Standard(DES)的C语言实现。程序通过命令行使用。  
需要注意的是教材中的DES与实际投入使用的DES不太一样，在某些文献中，作为算法的DES被称为DEA(Data Encryption Algorithm，数据加密算法)，以与作为标准的DES区分开来。所以严格来说，本项目是对DEA的实现。详情参照[DES_维基百科](https://zh.m.wikipedia.org/zh/%E8%B3%87%E6%96%99%E5%8A%A0%E5%AF%86%E6%A8%99%E6%BA%96)。  
针对工作模式的描述参考[分组密码工作模式_维基百科](https://zh.m.wikipedia.org/zh-hans/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F#%E7%94%B5%E5%AD%90%E5%AF%86%E7%A0%81%E6%9C%AC%EF%BC%88ECB%EF%BC%89)。  

在项目的test文件夹中有一个名为[Whole_Process_Of_Single_DES(点击下载)](https://github.com/goon-13/DES/raw/main/test/Whole_Process_Of_Single_DES.xlsx)的excel表格文件，我使用excel函数实现了针对一个分组的DES流程，方便学习时理解以及测试程序输出数据的正确性。  

经过测试在合法的参数输入下程序能正常运行。对一些可能的非法输入有进行了校验，但可能有些没有考虑周到的错误输入不能正确处理，如果发现了错误以及不规范之处希望能帮忙指出，非常感谢~

The code is the C implementation of Data Encryption Standard(DES) in the Cryptography Theory and Practice Third Edition. The program is used through the command line.  
It should be noted that the DES in the textbook is different from the DES actually put into use. In some literatures, the DES as an algorithm is called DEA(Data Encryption Algorithm) to distinguish it from the DES as a standard. So strictly speaking, this project is the realization of DEA. Refer to [DES(Wikipedia)](https://zh.m.wikipedia.org/zh/%E8%B3%87%E6%96%99%E5%8A%A0%E5%AF%86%E6%A8%99%E6%BA%96) for details.  
For the description of the operation mode, refer to the block [Block cipher mode of operation(Wikipedia)](https://zh.m.wikipedia.org/zh-hans/%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F#%E7%94%B5%E5%AD%90%E5%AF%86%E7%A0%81%E6%9C%AC%EF%BC%88ECB%EF%BC%89).

In the test folder of the project, there is a file named [Whole_Process_Of_Single_DES(Click Download)](https://github.com/goon-13/DES/raw/main/test/Whole_Process_Of_Single_DES.xlsx), which is a Excel table file. I used excel functions to implement the DES process for one DES data block, which is convenient for understanding during learning and testing the correctness of the program's output data.  

After testing, the program can run normally with legal parameter input. Some possible illegal inputs have been verified, but maybe some inadvertent incorrect inputs cannot be handled correctly. If errors and irregularities are found, I hope you can point them out. Thank you very much~

## 使用-Tutorial
1. -h  
查看命令指南  
``./DES.exe -h``
2. -g key_file_name  
生成随机的密钥文件。  
``./DES.exe -g keyfile.key``
3. -e key_file_name plaintext_file_name encrypted_ciphertext_file_name (byte_padding_way) (mode_name) (initialization_vector_file_name)  
进行加密。参数需要按照给定顺序指定才能正确解析。括号内为可省略项。
``./DES.exe -e keyfile.key input.txt output.txt p cbc iv.txt``
4. -d key_file_name ciphertext_file_name decrypted_plaintext_file_name (byte_padding_way) (mode_name) (initialization_vector_file_name)  
进行解密。  
``./DES.exe -d keyfile.key input.txt output.txt I CFB iv.txt``
5. -c file_name  
在命令行打印指定文件的十六进制和二进制格式。  
``./DES.exe -c output.txt``

## 实例-Usage
1. 未输入参数。 
No parameters entered.  
![win_without_args.jpg](https://github.com/goon-13/DES/blob/main/img/win/1_win_without_args.jpg)
2. 查看命令指南。
View the command guide.  
![win_help.jpg](https://github.com/goon-13/DES/blob/main/img/win/2_win_help.jpg)
3. 参数缺失。
Required parameter missing.  
![win_miss_args.jpg](https://github.com/goon-13/DES/blob/main/img/win/3_win_miss_args.jpg)
4. 生成密钥文件并输出其十六进制及二进制格式。
Generate the key file and output it in hexadecimal and binary formats.  
![win_g_and_c.jpg](https://github.com/goon-13/DES/blob/main/img/win/4_win_g_and_c.jpg)
5. 在CTR模式，ISO10126填充方式下进行加密。输入为：密钥文件keyfile.key，明文文件input.txt，初始向量文件iv.txt；输出密文至文件output_ctr_iso.txt。
Encryption is performed in CTR mode and ISO10126 padding mode. Input: key file keyfile.key, plaintext file input.txt, initialization vector file iv.txt; Output ciphertext to file output_ctr_iso.txt.  
![win_e_iso_ctr.jpg](https://github.com/goon-13/DES/blob/main/img/win/5_win_e_iso_ctr.jpg)
6. 对上一步生成的密文进行解密。输出明文至文件decrypted_input_ctr_iso.txt。
Decrypt the ciphertext generated in the previous step. Output plaintext to file decrypted_input_ctr_iso.txt.  
![win_d_iso_ctr.jpg](https://github.com/goon-13/DES/blob/main/img/win/6_win_d_iso_ctr.jpg)
7. 对一些可能的非法输入的处理。
Handling of some possible illegal inputs.  
![win_error1_folder_not_exist.jpg](https://github.com/goon-13/DES/blob/main/img/win/7_win_error1_folder_not_exist.jpg)

## 更多-More
代码还有许多需要优化的地方，并且目前仅在windows x64环境下可用，linux环境的兼容还在实现中。  
后续会继续使用C语言实现其他的加解密方式。

The code still needs to be optimized, and it is only available in the Windows x64 environment at present. The compatibility of the Linux environment is still in the process of implementation.
Later, I will continue to use C language to implement other encryption and decryption methods.