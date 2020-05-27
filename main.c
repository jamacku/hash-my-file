#include "hash-file.h"

#include <ctype.h>
#include <unistd.h>
#include <string.h>

int main (int argc, char** argv)
{
  int fflag = 0;
  char *fvalue = NULL;
  int c; 
  opterr = 0;

  while ((c = getopt (argc, argv, "f:")) != -1) {
    switch (c) {
      case 'f':
        fflag = 1;
        fvalue = optarg;
        break;
       
      case '?':
        if (optopt == 'f') { 
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

  if(fflag == 1) {
    unsigned char* digestbuf = (unsigned char*)malloc(MD5_DIGEST_LENGTH); 
    char* file_name = fvalue;

    hash_file_md5(file_name, digestbuf);
    for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
      printf("%02x", digestbuf[i]);
    }
    printf(" %s\n", fvalue);

  } else {
    printf("Missing parameter -a and/or -f\n");
    return 1;
  }
  return 0;
}
