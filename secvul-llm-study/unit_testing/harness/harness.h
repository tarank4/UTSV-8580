#ifndef HARNESS_H
#define HARNESS_H

#include <stdio.h>
#include <stdlib.h>

/* Call these to indicate test results */
#define RESULT_PASS()  do { printf("RESULT:PASS\n"); exit(0); } while (0)
#define RESULT_FAIL()  do { printf("RESULT:FAIL\n"); exit(1); } while (0)


// The LLM must implement this function to run the test in their implementation.
void run_test(void);

#endif /* HARNESS_H */


