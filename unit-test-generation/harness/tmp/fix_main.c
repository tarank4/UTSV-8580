#include "harness.h"

// Function under test
void filter_block2d_8_c(const uint8_t *src_ptr,  const unsigned int src_stride,  const int16_t *HFilter,  const int16_t *VFilter,  uint8_t *dst_ptr,  unsigned int dst_stride,  unsigned int output_width,  unsigned int output_height);

// <Configure global constants and variables here>
// Call the function under test
// <Configure global constants and variables here>
const unsigned int large_output_width = 72;
const unsigned int output_height = 1;
uint8_t src_buffer[71 * 64];
int16_t HFilter[8] = {1, 1, 1, 1, 1, 1, 1, 1};
int16_t VFilter[8] = {1, 1, 1, 1, 1, 1, 1, 1};
uint8_t dst_buffer[71 * 64];

void run_test(void) {
    // Initialize source buffer with some values
    memset(src_buffer, 128, sizeof(src_buffer));

    // This should cause a buffer overflow in the vulnerable version
    filter_block2d_8_c(src_buffer, 64, HFilter, VFilter, dst_buffer, 64, large_output_width, output_height);

    // If we reach here, it means the vulnerable version did not crash
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

int main() {
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}