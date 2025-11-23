#include "harness.h"

// Function under test
unsigned long shift_and_mask(unsigned long v, u32 shift, u32 bits);

// <Configure global constants and variables here>
// Call the function under test
// <Configure global constants and variables here>
const unsigned long TEST_VALUE = 0xFFFFFFFFFFFFFFFF;
const u32 TEST_SHIFT = 32;
const u32 TEST_BITS = 32;

// Add stubs and mocks here if necessary

void run_test(void) {
    // Test the vulnerable function
    unsigned long result_vulnerable = shift_and_mask(TEST_VALUE, TEST_SHIFT, TEST_BITS);
    if (result_vulnerable!= 0) {
        RESULT_FAIL();
    }

    // Test the fixed function
    unsigned long result_fixed = shift_and_mask(TEST_VALUE, TEST_SHIFT, TEST_BITS);
    if (result_fixed == 0) {
        RESULT_FAIL();
    }

    // If both tests pass
    RESULT_PASS();
}

// Function under test
unsigned long shift_and_mask(unsigned long v, u32 shift, u32 bits)
{
	return (v >> shift) & ((1 << bits) - 1);
}

int main() {
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}