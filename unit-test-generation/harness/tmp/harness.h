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
#define RESULT_PASS()  do { printf("RESULT:PASS\n"); exit(0); } while (0)
#define RESULT_FAIL()  do { printf("RESULT:FAIL\n"); exit(1); } while (0)

/* Context relevant to this specific test */
#ifndef MOCK_CONTEXT_H
#define MOCK_CONTEXT_H

#include <stdint.h>  // For uint8_t and int16_t
#include <stddef.h>  // For size_t, if needed

// Define constants
#define VP9_FILTER_WEIGHT 128  // Example value for rounding
#define VP9_FILTER_SHIFT 7     // Example value for normalization
#define kMaxDimension 64       // Example maximum dimension for the fixed code

// Mock the clip_pixel function
static inline uint8_t clip_pixel(int value) {
    if (value < 0) return 0;
    if (value > 255) return 255;
    return (uint8_t)value;
}

#endif // MOCK_CONTEXT_H


// The LLM must implement this function to run the test in their implementation.
void run_test(void);

#endif /* HARNESS_H */


