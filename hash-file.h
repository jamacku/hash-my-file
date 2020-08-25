#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>

#define BUFF_SIZE 1024

void* hash_file_md5 (char* file_path, char* file_path_result)
{
  EVP_MD_CTX *contxt;
  const EVP_MD *md5_struct;
  unsigned int md5_len, bytes;
  unsigned char buff[BUFF_SIZE], md5_value[EVP_MAX_MD_SIZE];
  FILE *fd = fopen(file_path, "r");
  FILE *fd_result = fopen(file_path_result, "a");

  if (fd == NULL) {
    printf ("%s can't be opened.\n", file_path);
    return (void*)3;
  }
  
  if (fd_result == NULL) {
    printf ("%s can't be opened.\n", file_path_result);
    return (void*)3;
  }
 
  md5_struct = EVP_md5();
  contxt = EVP_MD_CTX_new();
  EVP_DigestInit_ex(contxt, md5_struct, NULL);

  while ((bytes = fread(buff, 1, BUFF_SIZE, fd)) != 0) {
    EVP_DigestUpdate(contxt, buff, bytes);
  }
  
  EVP_DigestFinal_ex(contxt, md5_value, &md5_len);
  EVP_MD_CTX_free(contxt);
    
  for (size_t i = 0; i < md5_len; i++) {
    printf("%02x", md5_value[i]);
    fprintf(fd_result, "%02x", md5_value[i]);
  }
  printf(" %s\n", file_path);  
  fprintf(fd_result, " %s\n", file_path);  

  fclose(fd);
  fclose(fd_result);
  return NULL;
}

char *check_hash_value (char *file_path, char *source_path)
{

  FILE *fd = fopen(file_path, "r");

  char *line = NULL;
  size_t len = 0;
  ssize_t nread;

  if (fd == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  while ((nread = getline(&line, &len, fd)) != -1) {
    printf("Retrieved line of length %zu:\n", nread);
    fwrite(line, nread, 1, stdout);
  }

  free(line);
  fclose(fd);
  return NULL;
}
