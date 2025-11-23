The following code has a security vulnerability. Write a unit test that will FAIL because of the vulnerability. 
The same test MUST PASS on a fixed version of the code.

# Vulnerable Function Body

char* parse_content_length( char* buffer, char* end, int* length)
{
	int number;
	char *p;
	int  size;

	p = buffer;
	/* search the beginning of the number */
	while ( p<end && (*p==' ' || *p=='\t' || (*p=='\r' && *(p+1)=='\n') ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* parse the number */
	size = 0;
	number = 0;
	while (p<end && *p>='0' && *p<='9') {
		number = number*10 + (*p)-'0';
		if (number<0) {
			LM_ERR("number overflow at pos %d in len number [%.*s]\n",
				(int)(p-buffer),(int)(end-buffer), buffer);
			return 0;
		}
		size ++;
		p++;
	}
	if (p==end || size==0)
		goto error;
	/* now we should have only spaces at the end */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* the header ends proper? */
	if ( (*(p++)!='\n') && (*(p-1)!='\r' || *(p++)!='\n' ) )
		goto error;

	*length = number;
	return p;
error:
	LM_ERR("parse error near char [%d][%c]\n",*p,*p);
	return 0;
}

# Fixed Function Body

char* parse_content_length( char* buffer, char* end, int* length)
{
	int number;
	char *p;
	int  size;

	p = buffer;
	/* search the beginning of the number */
	while ( p<end && (*p==' ' || *p=='\t' || (*p=='\r' && *(p+1)=='\n') ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* parse the number */
	size = 0;
	number = 0;
	while (p<end && *p>='0' && *p<='9') {
		/* do not actually cause an integer overflow, as it is UB! --liviu */
		if (number > 214748363) {
			LM_ERR("integer overflow risk at pos %d in len number [%.*s]\n",
				(int)(p-buffer),(int)(end-buffer), buffer);
			return 0;
		}

		number = number*10 + (*p)-'0';
		size ++;
		p++;
	}
	if (p==end || size==0)
		goto error;
	/* now we should have only spaces at the end */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* the header ends proper? */
	if ( (*(p++)!='\n') && (*(p-1)!='\r' || *(p++)!='\n' ) )
		goto error;

	*length = number;
	return p;
error:
	LM_ERR("parse error near char [%d][%c]\n",*p,*p);
	return 0;
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

#include <stdio.h>  // For printf (used in LM_ERR)
#include <stdlib.h> // For standard library functions like malloc, free, etc.

// Define the LM_ERR macro for error logging
#define LM_ERR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#endif // MOCK_CONTEXT_H


// The LLM must implement this function to run the test in their implementation.
void run_test(void);

#endif /* HARNESS_H */




# Main (main.c)

#include "harness.h"

// Function under test
char* parse_content_length( char* buffer, char* end, int* length);

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
char* parse_content_length( char* buffer, char* end, int* length)
{
	int number;
	char *p;
	int  size;

	p = buffer;
	/* search the beginning of the number */
	while ( p<end && (*p==' ' || *p=='\t' || (*p=='\r' && *(p+1)=='\n') ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* parse the number */
	size = 0;
	number = 0;
	while (p<end && *p>='0' && *p<='9') {
		number = number*10 + (*p)-'0';
		if (number<0) {
			LM_ERR("number overflow at pos %d in len number [%.*s]\n",
				(int)(p-buffer),(int)(end-buffer), buffer);
			return 0;
		}
		size ++;
		p++;
	}
	if (p==end || size==0)
		goto error;
	/* now we should have only spaces at the end */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* the header ends proper? */
	if ( (*(p++)!='\n') && (*(p-1)!='\r' || *(p++)!='\n' ) )
		goto error;

	*length = number;
	return p;
error:
	LM_ERR("parse error near char [%d][%c]\n",*p,*p);
	return 0;
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
