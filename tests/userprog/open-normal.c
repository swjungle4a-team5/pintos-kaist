/* Open a file. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  // printf("######## start open-normal.c ######## \n");

  int handle = open ("sample.txt");
  // printf("######## after open() \n");
  if (handle < 2){
    // printf("######## after open() \n");
    fail ("open() returned %d", handle);
  }

}
