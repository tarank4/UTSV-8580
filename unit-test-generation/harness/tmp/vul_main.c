#include "harness.h"

// Function under test
void init_syntax_once ();

// <Configure global constants and variables here>
// Call the function under test
// <Configure global constants and variables here>
int done = 1; // Set done to 1 to simulate the vulnerability condition

// Add stubs and mocks here if necessary

void run_test(void) {
    init_syntax_once();
    if (re_syntax_table['a'] == Sword) {
        RESULT_FAIL(); // This should fail in the vulnerable version because done is not initialized
    } else {
        RESULT_PASS(); // This should pass in the fixed version
    }
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