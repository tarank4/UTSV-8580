The following code has a security vulnerability. Write a unit test that will FAIL because of the vulnerability. 
The same test MUST PASS on a fixed version of the code.

# Vulnerable Function Body

void init_syntax_once ()
{
   register int c;
   int done;

   if (done)
     return;

   bzero (re_syntax_table, sizeof re_syntax_table);

   for (c = 'a'; c <= 'z'; c++)
     re_syntax_table[c] = Sword;

   for (c = 'A'; c <= 'Z'; c++)
     re_syntax_table[c] = Sword;

   for (c = '0'; c <= '9'; c++)
     re_syntax_table[c] = Sword;

   re_syntax_table['_'] = Sword;

   done = 1;
}

# Fixed Function Body

void init_syntax_once ()
{
   register int c;
   int done = 0;

   if (done)
     return;
   bzero (re_syntax_table, sizeof re_syntax_table);

   for (c = 0; c < CHAR_SET_SIZE; ++c)
     if (ISALNUM (c))
	re_syntax_table[c] = Sword;

   re_syntax_table['_'] = Sword;

   done = 1;
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

#include <string.h> // For memset
#include <stddef.h> // For size_t, if needed

#define CHAR_SET_SIZE 256
#define ISALNUM(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') || ((c) >= '0' && (c) <= '9'))

// Map bzero to memset for portability
#define bzero(ptr, size) memset((ptr), 0, (size))

// Define the SyntaxType enum and the re_syntax_table array
enum SyntaxType { Sword };
enum SyntaxType re_syntax_table[CHAR_SET_SIZE];

#endif // MOCK_CONTEXT_H


// The LLM must implement this function to run the test in their implementation.
void run_test(void);

#endif /* HARNESS_H */




# Main (main.c)

#include "harness.h"

// Function under test
void init_syntax_once ();

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
void init_syntax_once ()
{
   register int c;
   int done;

   if (done)
     return;

   bzero (re_syntax_table, sizeof re_syntax_table);

   for (c = 'a'; c <= 'z'; c++)
     re_syntax_table[c] = Sword;

   for (c = 'A'; c <= 'Z'; c++)
     re_syntax_table[c] = Sword;

   for (c = '0'; c <= '9'; c++)
     re_syntax_table[c] = Sword;

   re_syntax_table['_'] = Sword;

   done = 1;
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
