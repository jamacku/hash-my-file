#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BUFF_SIZE 1024

int main(int argc, char *argv[])
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len, i;

  unsigned int bytes;
  unsigned char buff[BUFF_SIZE];
  FILE *fd = fopen("../test.txt", "rb");

  if (fd == NULL) {
    printf ("%s can't be opened.\n", "../test.txt");
    return 3;
  }

  if (argv[1] == NULL) {
    printf("Usage: mdtest digestname\n");
    exit(1);
  }

  md = EVP_get_digestbyname(argv[1]);
  if (md == NULL) {
    printf("Unknown message digest %s\n", argv[1]);
    exit(1);
  }

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    EVP_DigestUpdate(mdctx, buff, bytes);
  }

  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);

  printf("Digest is: ");
  for (i = 0; i < md_len; i++) {
    printf("%02x", md_value[i]);
  }
  printf("\n");

  exit(0);
}
