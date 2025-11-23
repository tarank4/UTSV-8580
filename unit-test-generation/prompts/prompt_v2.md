The following code has a security vulnerability. Write a unit test that will FAIL because of the vulnerability. 
The same test MUST PASS on a fixed version of the code.

# Vulnerable Function Body

{vulnerable_function_body}

# Fixed Function Body

{fixed_function_body}

# Testing Harness (harness.h)

{harness_h}

# Main (main.c)

{main_c}

# Compilation

The code is compiled with the following command to ensure consistent crashes when memory bounds are violated:
gcc -std=c11 -Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer main.c -o main && ASAN_OPTIONS=abort_on_error=1 ./main

# Your job

You must an implementation for `run_test`
Your response will be inserted at the '// Your generated code will be placed right here' location. 
If something isn't defined in the harness or main files, you must define it yourself, including mocks and stubs if necessary.

You are allowed to:
- Declare global constants, variables, stubs, and mocks used by the test.
- Implement the function:

    void run_test(void) {{
        ...
    }}

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

void run_test(void) {{
    // implement the test
    // call RESULT_PASS() if the secure version would pass
    // call RESULT_FAIL() if the vulnerable version fails
}}

Do NOT include any text before or after this code. The entire reply must be compilable C code that can be pasted directly into main.c.
