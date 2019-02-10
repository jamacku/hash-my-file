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

struct hash_opts algos[_HASH_MAX_ALGO] = {{         /*HASH_MD2*/
                                            "md2",
                                            MD2_DIGEST_LENGTH,
                                            sizeof(MD2_CTX),
                                            &MD2_Init,
                                            &MD2_Update,
                                            &MD2_Final
                                          }, {      /*HASH_MD4*/
                                            "md4",
                                            MD4_DIGEST_LENGTH,
                                            sizeof(MD4_CTX),
                                            &MD4_Init,
                                            &MD4_Update,
                                            &MD4_Final
                                          }, {      /*HASH_MD5*/
                                            "md5",
                                            MD5_DIGEST_LENGTH,
                                            sizeof(MD5_CTX),
                                            &MD5_Init,
                                            &MD5_Update,
                                            &MD5_Final
                                          }, {      /*HASH_RIPEMD160*/
                                            "ripemd160",
                                            RIPEMD160_DIGEST_LENGTH,
                                            sizeof(RIPEMD160_CTX),
                                            &RIPEMD160_Init,
                                            &RIPEMD160_Update,
                                            &RIPEMD160_Final
                                          }, {      /*HASH_SHA1*/
                                            "sha1",
                                            SHA_DIGEST_LENGTH,
                                            sizeof(SHA_CTX),
                                            &SHA1_Init,
                                            &SHA1_Update,
                                            &SHA1_Final
                                          }, {      /*HASH_SHA224*/
                                            "sha224",
                                            SHA224_DIGEST_LENGTH,
                                            sizeof(SHA256_CTX),
                                            &SHA224_Init,
                                            &SHA224_Update,
                                            &SHA224_Final
                                          }, {      /*HASH_SHA256*/
                                            "sha256",
                                            SHA256_DIGEST_LENGTH,
                                            sizeof(SHA256_CTX),
                                            &SHA256_Init,
                                            &SHA256_Update,
                                            &SHA256_Final
                                          }, {      /*HASH_SHA384*/
                                            "sha384",
                                            SHA384_DIGEST_LENGTH,
                                            sizeof(SHA512_CTX),
                                            &SHA384_Init,
                                            &SHA384_Update,
                                            &SHA384_Final
                                          }, {      /*HASH_SHA512*/
                                            "sha512",
                                            SHA512_DIGEST_LENGTH,
                                            sizeof(SHA512_CTX),
                                            &SHA512_Init,
                                            &SHA512_Update,
                                            &SHA512_Final
                                          }};

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

