#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>

#define BUFF_SIZE 1024

void* hash_file_md5 (char* file_path)
{
  EVP_MD_CTX *contxt;
  const EVP_MD *md5_struct;
  unsigned int md5_len, bytes;
  unsigned char buff[BUFF_SIZE], md5_value[EVP_MAX_MD_SIZE];
  FILE *fd = fopen(file_path, "rb");

  if (fd == NULL) {
    printf ("%s can't be opened.\n", file_path);
    return (void*)3;
  }
 
  md5_struct = EVP_md5();
  contxt = EVP_MD_CTX_new();
  EVP_DigestInit_ex(contxt, md5_struct, NULL);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    EVP_DigestUpdate(contxt, buff, bytes);
  }
  
  EVP_DigestFinal_ex(contxt, md5_value, &md5_len);
  EVP_MD_CTX_free(contxt);
    
  for (size_t i = 0; i < md5_len; i++) {
    printf("%02x", md5_value[i]);
  }
  printf(" %s\n", file_path);
    
  fclose(fd);
  return NULL;
}

