The following code has a security vulnerability. Write a unit test that will FAIL because of the vulnerability. 
The same test MUST PASS on a fixed version of the code.

# Vulnerable Function Body

void filter_block2d_8_c(const uint8_t *src_ptr,
 const unsigned int src_stride,
 const int16_t *HFilter,
 const int16_t *VFilter,
 uint8_t *dst_ptr,
 unsigned int dst_stride,
 unsigned int output_width,
 unsigned int output_height) {

   const int kInterp_Extend = 4;
   const unsigned int intermediate_height =
       (kInterp_Extend - 1) + output_height + kInterp_Extend;
 
  /* Size of intermediate_buffer is max_intermediate_height * filter_max_width,
   * where max_intermediate_height = (kInterp_Extend - 1) + filter_max_height
   *                                 + kInterp_Extend
   *                               = 3 + 16 + 4
   *                               = 23
   * and filter_max_width = 16
   */
  uint8_t intermediate_buffer[71 * 64];
   const int intermediate_next_stride = 1 - intermediate_height * output_width;
 
  {
    uint8_t *output_ptr = intermediate_buffer;
    const int src_next_row_stride = src_stride - output_width;
    unsigned int i, j;
    src_ptr -= (kInterp_Extend - 1) * src_stride + (kInterp_Extend - 1);
    for (i = 0; i < intermediate_height; ++i) {
      for (j = 0; j < output_width; ++j) {
        const int temp = (src_ptr[0] * HFilter[0]) +
                         (src_ptr[1] * HFilter[1]) +
                         (src_ptr[2] * HFilter[2]) +
                         (src_ptr[3] * HFilter[3]) +
                         (src_ptr[4] * HFilter[4]) +
                         (src_ptr[5] * HFilter[5]) +
                         (src_ptr[6] * HFilter[6]) +
                         (src_ptr[7] * HFilter[7]) +
                         (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
        *output_ptr = clip_pixel(temp >> VP9_FILTER_SHIFT);
        ++src_ptr;
        output_ptr += intermediate_height;
      }
      src_ptr += src_next_row_stride;
      output_ptr += intermediate_next_stride;
     }
   }
 
  {
    uint8_t *src_ptr = intermediate_buffer;
    const int dst_next_row_stride = dst_stride - output_width;
    unsigned int i, j;
    for (i = 0; i < output_height; ++i) {
      for (j = 0; j < output_width; ++j) {
        const int temp = (src_ptr[0] * VFilter[0]) +
                         (src_ptr[1] * VFilter[1]) +
                         (src_ptr[2] * VFilter[2]) +
                         (src_ptr[3] * VFilter[3]) +
                         (src_ptr[4] * VFilter[4]) +
                         (src_ptr[5] * VFilter[5]) +
                         (src_ptr[6] * VFilter[6]) +
                         (src_ptr[7] * VFilter[7]) +
                         (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
        *dst_ptr++ = clip_pixel(temp >> VP9_FILTER_SHIFT);
        src_ptr += intermediate_height;
      }
      src_ptr += intermediate_next_stride;
      dst_ptr += dst_next_row_stride;
     }
   }
 }

# Fixed Function Body

void filter_block2d_8_c(const uint8_t *src_ptr,
 const unsigned int src_stride,
 const int16_t *HFilter,
 const int16_t *VFilter,
 uint8_t *dst_ptr,
 unsigned int dst_stride,
 unsigned int output_width,
 unsigned int output_height) {

   const int kInterp_Extend = 4;
   const unsigned int intermediate_height =
       (kInterp_Extend - 1) + output_height + kInterp_Extend;
  unsigned int i, j;
 
  // Size of intermediate_buffer is max_intermediate_height * filter_max_width,
  // where max_intermediate_height = (kInterp_Extend - 1) + filter_max_height
  //                                 + kInterp_Extend
  //                               = 3 + 16 + 4
  //                               = 23
  // and filter_max_width          = 16
  //
  uint8_t intermediate_buffer[71 * kMaxDimension];
   const int intermediate_next_stride = 1 - intermediate_height * output_width;
 
  uint8_t *output_ptr = intermediate_buffer;
  const int src_next_row_stride = src_stride - output_width;
  src_ptr -= (kInterp_Extend - 1) * src_stride + (kInterp_Extend - 1);
  for (i = 0; i < intermediate_height; ++i) {
    for (j = 0; j < output_width; ++j) {
      // Apply filter...
      const int temp = (src_ptr[0] * HFilter[0]) +
          (src_ptr[1] * HFilter[1]) +
          (src_ptr[2] * HFilter[2]) +
          (src_ptr[3] * HFilter[3]) +
          (src_ptr[4] * HFilter[4]) +
          (src_ptr[5] * HFilter[5]) +
          (src_ptr[6] * HFilter[6]) +
          (src_ptr[7] * HFilter[7]) +
          (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
      // Normalize back to 0-255...
      *output_ptr = clip_pixel(temp >> VP9_FILTER_SHIFT);
      ++src_ptr;
      output_ptr += intermediate_height;
     }
    src_ptr += src_next_row_stride;
    output_ptr += intermediate_next_stride;
   }
 
  src_ptr = intermediate_buffer;
  const int dst_next_row_stride = dst_stride - output_width;
  for (i = 0; i < output_height; ++i) {
    for (j = 0; j < output_width; ++j) {
      // Apply filter...
      const int temp = (src_ptr[0] * VFilter[0]) +
          (src_ptr[1] * VFilter[1]) +
          (src_ptr[2] * VFilter[2]) +
          (src_ptr[3] * VFilter[3]) +
          (src_ptr[4] * VFilter[4]) +
          (src_ptr[5] * VFilter[5]) +
          (src_ptr[6] * VFilter[6]) +
          (src_ptr[7] * VFilter[7]) +
          (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
      // Normalize back to 0-255...
      *dst_ptr++ = clip_pixel(temp >> VP9_FILTER_SHIFT);
      src_ptr += intermediate_height;
     }
    src_ptr += intermediate_next_stride;
    dst_ptr += dst_next_row_stride;
   }
 }

# Testing Harness (harness.h)

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




# Main (main.c)

#include "harness.h"

// Function under test
void filter_block2d_8_c(const uint8_t *src_ptr,  const unsigned int src_stride,  const int16_t *HFilter,  const int16_t *VFilter,  uint8_t *dst_ptr,  unsigned int dst_stride,  unsigned int output_width,  unsigned int output_height);

// <Configure global constants and variables here>
// <Environment setup for function under test>

// Edit the following unit test
void run_test(void) {
    // <Call the function under test and check results here>
    
    // If the test passes
    RESULT_PASS();
    
    // If the test fails
    RESULT_FAIL();
}

// Function under test
void filter_block2d_8_c(const uint8_t *src_ptr,
 const unsigned int src_stride,
 const int16_t *HFilter,
 const int16_t *VFilter,
 uint8_t *dst_ptr,
 unsigned int dst_stride,
 unsigned int output_width,
 unsigned int output_height) {

   const int kInterp_Extend = 4;
   const unsigned int intermediate_height =
       (kInterp_Extend - 1) + output_height + kInterp_Extend;
 
  /* Size of intermediate_buffer is max_intermediate_height * filter_max_width,
   * where max_intermediate_height = (kInterp_Extend - 1) + filter_max_height
   *                                 + kInterp_Extend
   *                               = 3 + 16 + 4
   *                               = 23
   * and filter_max_width = 16
   */
  uint8_t intermediate_buffer[71 * 64];
   const int intermediate_next_stride = 1 - intermediate_height * output_width;
 
  {
    uint8_t *output_ptr = intermediate_buffer;
    const int src_next_row_stride = src_stride - output_width;
    unsigned int i, j;
    src_ptr -= (kInterp_Extend - 1) * src_stride + (kInterp_Extend - 1);
    for (i = 0; i < intermediate_height; ++i) {
      for (j = 0; j < output_width; ++j) {
        const int temp = (src_ptr[0] * HFilter[0]) +
                         (src_ptr[1] * HFilter[1]) +
                         (src_ptr[2] * HFilter[2]) +
                         (src_ptr[3] * HFilter[3]) +
                         (src_ptr[4] * HFilter[4]) +
                         (src_ptr[5] * HFilter[5]) +
                         (src_ptr[6] * HFilter[6]) +
                         (src_ptr[7] * HFilter[7]) +
                         (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
        *output_ptr = clip_pixel(temp >> VP9_FILTER_SHIFT);
        ++src_ptr;
        output_ptr += intermediate_height;
      }
      src_ptr += src_next_row_stride;
      output_ptr += intermediate_next_stride;
     }
   }
 
  {
    uint8_t *src_ptr = intermediate_buffer;
    const int dst_next_row_stride = dst_stride - output_width;
    unsigned int i, j;
    for (i = 0; i < output_height; ++i) {
      for (j = 0; j < output_width; ++j) {
        const int temp = (src_ptr[0] * VFilter[0]) +
                         (src_ptr[1] * VFilter[1]) +
                         (src_ptr[2] * VFilter[2]) +
                         (src_ptr[3] * VFilter[3]) +
                         (src_ptr[4] * VFilter[4]) +
                         (src_ptr[5] * VFilter[5]) +
                         (src_ptr[6] * VFilter[6]) +
                         (src_ptr[7] * VFilter[7]) +
                         (VP9_FILTER_WEIGHT >> 1);  // Rounding
 
        *dst_ptr++ = clip_pixel(temp >> VP9_FILTER_SHIFT);
        src_ptr += intermediate_height;
      }
      src_ptr += intermediate_next_stride;
      dst_ptr += dst_next_row_stride;
     }
   }
 }

int main() {
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}

# Compilation

The code is compiled with the following command to ensure consistent crashes when memory bounds are violated:
gcc -std=c11 -Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer main.c -o main && ASAN_OPTIONS=abort_on_error=1 ./main

# Your job

You must write C code that will be pasted into main.c at the location marked
`// <Configure global constants and variables here>` and before the existing `run_test` declaration. If something isn't defined in the harness or main files, you must define it yourself, including mocks and stubs if necessary.

You are allowed to:
- Declare global constants, variables, stubs, and mocks used by the test.
- Implement the function:

    void run_test(void) {
        ...
    }

You are NOT allowed to:
- Print any explanations.
- Describe the vulnerability in words.
- Propose or show a FIXED version of the vulnerable function.
- Output markdown (no ``` fences).
- Add or modify main(), includes, or other functions.

# Output format (STRICT)

Return **ONLY** valid C code with the following structure, and nothing else:

// <Configure global constants and variables here>
[zero or more global const/var declarations]

// Add stubs and mocks here if necessary

void run_test(void) {
    // implement the test
    // call RESULT_PASS() if the secure version would pass
    // call RESULT_FAIL() if the vulnerable version fails
}

Do NOT include any text before or after this code. The entire reply must be compilable C code that can be pasted directly into main.c.
