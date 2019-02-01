#include <stdio.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
  unsigned char hash[SHA512_DIGEST_LENGTH];
  if(argc > 1) {
    char *file_name = argv[1];
    FILE *fd = fopen(file_name, "rb");

    SHA512_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (fd == NULL) {
      printf ("%s can't be opened.\n", file_name);
      return 2;
    }

    SHA512_Init (&mdContext);
    
    while ((bytes = fread (data, 1, 1024, fd)) != 0) {
      SHA512_Update (&mdContext, data, bytes);
    }
    SHA512_Final (hash, &mdContext);
    
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
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
