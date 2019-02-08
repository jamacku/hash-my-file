#include <stdio.h>
#include <stdlib.h>

#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#define BUFF_SIZE 1024

enum hash_algo {
  HASH_MD2,
  HASH_MD4,
  HASH_MD5,
  HASH_RIPEMD160,
  HASH_SHA1,
  HASH_SHA224,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512,
  _HASH_MAX_ALGO
};

struct hash_opts {
  char algo_name[16];
  size_t hash_size;
  size_t context_size;
  int (*algo_init)(void*);
  int (*algo_update)(void*, const unsigned char*, unsigned long);
  int (*algo_final)(unsigned char*, void*);
};


void* hash_file (char* file_path, unsigned char* digestbuf, struct hash_opts* algo)
{
  void* contxt = malloc(algo->context_size);
  int bytes;
  unsigned char buff[BUFF_SIZE];
  FILE *fd = fopen(file_path, "rb");
  
  if (fd == NULL) {
    printf ("%s can't be opened.\n", file_path);
    return (void*)3;
  }
  
  algo->algo_init(contxt);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    algo->algo_update(contxt, buff, bytes);
  }
  
  algo->algo_final(digestbuf, contxt);
    
  fclose(fd);
  free(contxt);
  return NULL;
}

