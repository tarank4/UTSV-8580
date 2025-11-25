#include "harness.h"

// Function under test
{function_signature};

// <Configure global constants and variables here that the harness does not provide>
// <Environment setup for function under test>

// Your generated code will be placed right here

// Replace the following unit test
// Example run_test format, rewrite and replace it here
// void run_test(void) {{
//     // <Call the function under test and check results here>
    
//     // If the test passes
//     RESULT_PASS();
    
//     // If the test fails (or just make it crash)
//     RESULT_FAIL();
// }}

// Function under test
{function_body}

int main() {{
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}}