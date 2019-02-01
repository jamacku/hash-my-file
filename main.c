#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#define BUFF_SIZE 1024

struct hash_opts {
  char algo_name[16];
  size_t hash_size;
  size_t context_size;
  int (*algo_init)(void*);
  int (*algo_update)(void*, const unsigned char*, unsigned long);
  int (*algo_final)(unsigned char*, void*);
};

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

int hash_file (FILE* fd, struct hash_opts* algo)
{
  unsigned char* hash = (unsigned char*)malloc(algo->hash_size); 
  void* contxt = malloc(algo->context_size);
  int bytes;
  unsigned char buff[BUFF_SIZE];

  algo->algo_init(contxt);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    algo->algo_update(contxt, buff, bytes);
  }
  
  algo->algo_final(hash, contxt);
    
  for (int i = 0; i < algo->hash_size; i++) {
    printf("%02x", hash[i]);
  }
 
  fclose(fd);
  free(hash);
  free(contxt);
  return 0;
}


int main (int argc, char** argv)
{
  int aflag = 0;
  int fflag = 0;
  char *avalue = NULL;
  char *fvalue = NULL;
  unsigned algo_index;
  int c;
  
  struct hash_opts algos[_HASH_MAX_ALGO] = {{         /*HASH_MD2*/
                                              .algo_name = "md2",
                                              .hash_size = MD2_DIGEST_LENGTH,
                                              .context_size = sizeof(MD2_CTX),
                                              .algo_init = &MD2_Init,
                                              .algo_update = &MD2_Update,
                                              .algo_final = &MD2_Final
                                            }, {      /*HASH_MD4*/
                                              .algo_name = "md4",
                                              .hash_size = MD4_DIGEST_LENGTH,
                                              .context_size = sizeof(MD4_CTX),
                                              .algo_init = &MD4_Init,
                                              .algo_update = &MD4_Update,
                                              .algo_final = &MD4_Final
                                            }, {      /*HASH_MD5*/
                                              .algo_name = "md5",
                                              .hash_size = MD5_DIGEST_LENGTH,
                                              .context_size = sizeof(MD5_CTX),
                                              .algo_init = &MD5_Init,
                                              .algo_update = &MD5_Update,
                                              .algo_final = &MD5_Final
                                            }, {      /*HASH_RIPEMD160*/
                                              .algo_name = "ripemd160",
                                              .hash_size = RIPEMD160_DIGEST_LENGTH,
                                              .context_size = sizeof(RIPEMD160_CTX),
                                              .algo_init = &RIPEMD160_Init,
                                              .algo_update = &RIPEMD160_Update,
                                              .algo_final = &RIPEMD160_Final
                                            }, {      /*HASH_SHA1*/
                                              .algo_name = "sha1",
                                              .hash_size = SHA_DIGEST_LENGTH,
                                              .context_size = sizeof(SHA_CTX),
                                              .algo_init = &SHA1_Init,
                                              .algo_update = &SHA1_Update,
                                              .algo_final = &SHA1_Final
                                            }, {      /*HASH_SHA224*/
                                              .algo_name = "sha224",
                                              .hash_size = SHA224_DIGEST_LENGTH,
                                              .context_size = sizeof(SHA256_CTX),
                                              .algo_init = &SHA224_Init,
                                              .algo_update = &SHA224_Update,
                                              .algo_final = &SHA224_Final
                                            }, {      /*HASH_SHA256*/
                                              .algo_name = "sha256",
                                              .hash_size = SHA256_DIGEST_LENGTH,
                                              .context_size = sizeof(SHA256_CTX),
                                              .algo_init = &SHA256_Init,
                                              .algo_update = &SHA256_Update,
                                              .algo_final = &SHA256_Final
                                            }, {      /*HASH_SHA384*/
                                              .algo_name = "sha384",
                                              .hash_size = SHA384_DIGEST_LENGTH,
                                              .context_size = sizeof(SHA512_CTX),
                                              .algo_init = &SHA384_Init,
                                              .algo_update = &SHA384_Update,
                                              .algo_final = &SHA384_Final
                                            }, {      /*HASH_SHA512*/
                                              .algo_name = "sha512",
                                              .hash_size = SHA512_DIGEST_LENGTH,
                                              .context_size = sizeof(SHA512_CTX),
                                              .algo_init = &SHA512_Init,
                                              .algo_update = &SHA512_Update,
                                              .algo_final = &SHA512_Final
                                            }};
  
   opterr = 0;

  while ((c = getopt (argc, argv, "a:f:")) != -1) {
    switch (c) {
      case 'a':
        aflag = 1;
        avalue = optarg;
        // printf("avalue: %s\n", avalue);
        if ((strcmp(avalue, "md2")) == 0) {
          algo_index = HASH_MD2;
        } else if ((strcmp(avalue, "md4")) == 0) {
          algo_index = HASH_MD4;
        } else if ((strcmp(avalue, "md5")) == 0) {
          algo_index = HASH_MD5;
        } else if ((strcmp(avalue, "ripemd160")) == 0) {
          algo_index = HASH_RIPEMD160;
        } else if ((strcmp(avalue, "sha1")) == 0) {
          algo_index = HASH_SHA1;
        } else if ((strcmp(avalue, "sha224")) == 0) {
          algo_index = HASH_SHA224;
        } else if ((strcmp(avalue, "sha256")) == 0) {
          algo_index = HASH_SHA256;
        } else if ((strcmp(avalue, "sha384")) == 0) {
          algo_index = HASH_SHA384;
        } else if ((strcmp(avalue, "sha512")) == 0) {
          algo_index = HASH_SHA512;
        } else {
          printf("Missing parameter a!!\n");
          return 5;
        }
        break;

      case 'f':
        fflag = 1;
        fvalue = optarg;
        // printf("fvalue: %s\n", fvalue);
        break;
       
      case '?':
        if (optopt == 'a') {
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        } else if (optopt == 'f') { 
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        } else if (isprint(optopt)) {
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        } else {
          fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        }
        return 1;
      
      default:
        abort();
    }
  }

  // printf ("aflag = %d, avalue = %s, fflag = %d, fvalue = %s\n", aflag, avalue, fflag, fvalue);
  
  // printf("[%s] | context size: %lu | hash_size: %ld\n", algos[algo_index].algo_name, algos[algo_index].context_size, algos[algo_index].hash_size);

  if((aflag == 1) && (fflag == 1)) {
    char *file_name = fvalue;
    FILE *fd = fopen(file_name, "rb");

    if (fd == NULL) {
      printf ("%s can't be opened.\n", file_name);
      return 2;
    }

    hash_file(fd, &algos[algo_index]);
    printf("  %s\n", fvalue);

  } else {
    printf("Missing parameter -a and/or -f\n");
    return 1;
  }
  return 0;
}
