#ifndef HARNESS_H
#define HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Useful Macros */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define __u8  uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __s8  int8_t
#define __s16 int16_t
#define __s32 int32_t

/* Call these to indicate test results */
#define RESULT_PASS()  do {{ printf("RESULT:PASS\n"); exit(0); }} while (0)
#define RESULT_FAIL()  do {{ printf("RESULT:FAIL\n"); exit(1); }} while (0)

/* Context relevant to this specific test */
{context}


// The LLM must implement this function to run the test in their implementation.
void run_test(void);

#endif /* HARNESS_H */


