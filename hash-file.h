#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>

#define BUFF_SIZE 1024

void* hash_file_md5 (char* file_path, unsigned char* digestbuf)
{
  void* contxt = malloc(sizeof(MD5_CTX));
  const EVP_MD md5_struct;
  int bytes;
  unsigned char buff[BUFF_SIZE];
  FILE *fd = fopen(file_path, "rb");
  
  if (fd == NULL) {
    printf ("%s can't be opened.\n", file_path);
    return (void*)3;
  }
 
  md5_struct = EVP_md5();
  EVP_DigestInit_ex()

  EVP_DigestFinal_ex()


  MD5_Init(contxt);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    MD5_Update(contxt, buff, bytes);
  }
  
  MD5_Final(digestbuf, contxt);
    
  fclose(fd);
  free(contxt);
  return NULL;
}

