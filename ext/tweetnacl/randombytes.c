#include "randombytes.h"

void randombytes(unsigned char * ptr,unsigned int length) 
{
  char failed = 0;
  FILE* fh = fopen("/dev/urandom", "rb");
  if (fh != NULL) {
    if (fread(ptr, length, 1, fh) == 0) {
      failed = 1;
    }
    fclose(fh);
  } else {
    failed = 1;
  }
  /* 
   * yes, this is horrible error handling but we don't have better 
   * options from here and I don't want to start changing the design 
   * of the library 
   */
  if (failed) {
    exit(1);
  }
}
