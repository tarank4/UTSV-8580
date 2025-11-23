#include "harness.h"

// Function under test
char* parse_content_length( char* buffer, char* end, int* length);

// <Configure global constants and variables here>
// Call the function under test
// <Configure global constants and variables here>
const char* test_input = "Content-Length: 2147483648\r\n";
int test_length;
char* test_end = (char*)test_input + strlen(test_input);

// Add stubs and mocks here if necessary

void run_test(void) {
    char* result = parse_content_length((char*)test_input, test_end, &test_length);
    if (result == 0) {
        RESULT_FAIL();
    } else {
        RESULT_PASS();
    }
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

int main() {
    // Run the test implemented by the LLM
    run_test();
    
    // Should never reach here
    return 1;
}