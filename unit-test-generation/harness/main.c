#include "harness.h"

// Function under test
{function_signature};

// <Configure global constants and variables here>
// <Environment setup for function under test>

// Edit the following unit test
void run_test(void) {{
    // <Call the function under test and check results here>
    
    // If the test passes
    RESULT_PASS();
    
    // If the test fails
    RESULT_FAIL();
}}

// Function under test
{function_body}

int main() {{
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}}