#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/md5.h>

/*
 *  OpenSSL - MD5
 *
 unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md);
 int MD5_Init(MD5_CTX *c);
 int MD5_Update(MD5_CTX *c, const void *data, unsigned long len);
 int MD5_Final(unsigned char *md, MD5_CTX *c);
 */

int main(int argc, char** argv)
{
  int dflag = 0;
  int fflag = 0;
  char *dvalue = NULL;
  char *fvalue = NULL;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "df:")) != -1) {
    switch (c) {
      case 'd':
        // get directory path
        dflag = 1;
        dvalue = optarg;
        break;

      case 'f':
        // get file name
        fflag = 1;
        fvalue = optarg;
        break;
       
      case '?':
        if (optopt == 'd') {
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

  printf ("dflag = %d, dvalue = %s, fflag = %d, fvalue = %s\n", dflag, dvalue, fflag, fvalue);

  unsigned char hash[MD5_DIGEST_LENGTH];
  if((dflag == 1) || (fflag == 1)) {
    char *file_name = fvalue;
    FILE *fd = fopen(file_name, "rb");

    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (fd == NULL) {
      printf ("%s can't be opened.\n", file_name);
      return 2;
    }

    MD5_Init (&mdContext);
    
    while ((bytes = fread (data, 1, 1024, fd)) != 0) {
      MD5_Update (&mdContext, data, bytes);
    }
    MD5_Final (hash, &mdContext);
    
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
      printf("%02x", hash[i]);
    }

    printf (" %s\n", file_name);
    fclose (fd);

  } else {
    printf("Missing parameter -d and/or -f\n");
    return 1;
  }
  return 0;
}
