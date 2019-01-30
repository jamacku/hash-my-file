#include <stdio.h>
#include <openssl/md5.h>

/*
 unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md);
 int MD5_Init(MD5_CTX *c);
 int MD5_Update(MD5_CTX *c, const void *data, unsigned long len);
 int MD5_Final(unsigned char *md, MD5_CTX *c);
 */

int main(int argc, char** argv)
{
  unsigned char hash[MD5_DIGEST_LENGTH];
  if(argc > 1) {
    char *file_name = argv[1];
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
    printf("Wrong number of parameters! [%d]", argc);
    return 1;
  }
  return 0;
}
