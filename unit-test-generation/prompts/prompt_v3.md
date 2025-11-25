You are writing a differential unit test for a C security fix.

Goal:

* Create a test that FAILS (or crashes or hangs) on the vulnerable function.
* The same test MUST PASS on the fixed function.
* Do not only barely cause a crash, be as aggressive as possible. (e.g. if you need >32 bytes to go OOB, use 1000 bytes.)
* Use the provided harness and main context.
* Do NOT redefine anything the harness already defines.
* You SHOULD redefine stdlib external functions (e.g. malloc, strlen) to versions that crash on bad inputs to help cause divergence.
* Output must be valid C11.

You MUST respond in exactly two sections, in this order:

<ANALYSIS>
1. Identify the single concrete divergence condition between vulnerable and fixed.
2. Identify what external functions need to be mocked, stubbed, or replaced using macros to get consistent divergence. You should replace stdlib functions with functions that trigger crashes on bad inputs to help cause divergence.
3. Describe the exact runtime behavior you will force on the vulnerable version.
4. Describe the exact runtime behavior you expect on the fixed version.
5. Lay out the number and size of any buffers or arrays you will use to cause a crash.
6. List any harness globals you will set and why.
7. Sanity check: simulate 1–2 loop iterations or key steps showing divergence.
Do NOT write any C code here.
</ANALYSIS>

<FINAL_CODE>
// <Configure global constants and variables here>
[only C declarations that are NOT already in the harness]

// Add stubs and mocks here if necessary
[only if they are NOT already in the harness]
[any function used in the function under test needs to be mocked here]

void run_test(void) {{
...
}}
</FINAL_CODE>

Hard rules for <FINAL_CODE>:

* Output only C code, no commentary.
* No markdown fences.
* No C++ features (no lambdas, no auto, no typeof, no nested function bodies).
* Do not redefine harness-provided types, globals, or functions.
* You can and should rely on crashes to catch the vulnerable versions via OOB accesses.
* You can use macros to replace function dependencies (for example, to replace malloc with a checked version with #define malloc checked_malloc).
* Reader width must match length_power if you implement a reader.
* Avoid alignment UB in readers (use memcpy if needed).
* The test must *demonstrate divergence*, not just “big numbers.”
* Utilize the <FINAL_CODE> </FINAL_CODE> tags so I can parse your response correctly.
Context:

# Vulnerable Function Body

{vulnerable_function_body}

# Fixed Function Body

{fixed_function_body}

# Testing Harness (harness.h)

{harness_h}

# Main (main.c)

{main_c}

# Compilation

gcc -std=c11 -Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer main.c -o main && ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1 ./main
