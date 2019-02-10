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
