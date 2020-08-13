#include "hash-file.h"

#include <ctype.h>
#include <unistd.h>
#include <string.h>

int main (int argc, char** argv)
{
  int fflag = 0;
  char *file_name = NULL;
  char *result_file = NULL;
  int c; 
  opterr = 0;

  while ((c = getopt (argc, argv, "f:r:")) != -1) {
    switch (c) {
      case 'f':
        ++fflag;
        file_name = optarg;
        break;

      case 'r':
        ++fflag;
        result_file = optarg;
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

  if (fflag == 2) {
    hash_file_md5(file_name, result_file);
  } else if (fflag == 1){
    printf("Missing parameter -r\n");
    return 1;
  } else {
    printf("Missing parameter -f\n");
    return 1;
  }
  return 0;
}
