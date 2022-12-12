#ifndef __USER_PROMPTS__
#define __USER_PROMPTS__

#define ENCRYPTION 1 /* 加密 */
#define DECRYPTION 0 /* 解密 */

void user_prompt_usage();
void user_prompt_depends_on_existence_of_file(char* file_name);
void user_prompt_delete_tmpfile(char* dynamic_mem_alloc, uint8_t e_or_d);

#endif