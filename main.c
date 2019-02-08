#include "hash-file.h"

#include <ctype.h>
#include <unistd.h>
#include <string.h>

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

  if((aflag == 1) && (fflag == 1)) {
    unsigned char* digestbuf = (unsigned char*)malloc(algos[algo_index].hash_size); 
    char* file_name = fvalue;

    hash_file(file_name, digestbuf, &algos[algo_index]);
    for (size_t i = 0; i < algos[algo_index].hash_size; i++) {
      printf("%02x", digestbuf[i]);
    }
    printf(" %s\n", fvalue);

  } else {
    printf("Missing parameter -a and/or -f\n");
    return 1;
  }
  return 0;
}
