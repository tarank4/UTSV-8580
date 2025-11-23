"""
Given an LLMs response it will evaluate if the unit test succesfully passes on the fixed version and fails on the vulnerable version.
This will run the unit test against both versions.
"""

from case import Case
from evaluation.runner import run_unit_test, RunResult

import os

def clean_response(response: str) -> str:
    """
    Clean the LLM response to extract only the C code for the unit test.
    This function removes any markdown formatting or extraneous text.
    """
    # Remove any markdown code fences "````" and "```c"
    if "```" in response:
        parts = response.split("```")
        # Find the part that contains C code
        for part in parts:
            if part.strip().startswith("c") or part.strip().startswith("C"):
                return part.strip().lstrip("c").lstrip("C").strip()
        # If no specific C code fence, return the first code block
        return parts[1].strip()
    return response.strip()


def evaluate_unit_test(case: Case, response: str) -> int:
    """
    The LLM's response replaces the main.c file and is compiled and run against both the vulnerable and fixed versions.
    """

    score = 0

    # TODO: Add response parsing and validation to ensure it's the run_test implementation with 
    # global variables/constants if needed.
    response = clean_response(response)

    os.makedirs("harness/tmp", exist_ok=True)

    with open("harness/tmp/prompt.md", "w") as f:
        f.write(case.get_prompt())
    
    # Save the code that is being compiled to temp files for debugging
    with open("harness/tmp/vul_main.c", "w") as f:
        f.write(case.get_replaceable_main_c(case.vulnerable_function_body, response))

    with open("harness/tmp/fix_main.c", "w") as f:
        f.write(case.get_replaceable_main_c(case.fixed_function_body, response))
    
    with open("harness/tmp/harness.h", "w") as f:
        f.write(case.harness_header_with_context)

    result = run_unit_test(case.harness_header_with_context, case.get_replaceable_main_c(case.vulnerable_function_body, response))
    print("STDOUT and STDERR for vulnerable version:")
    print("stdout: '", result.stdout, "'")
    print("stderr: '", result.stderr, "'")
    if "RESULT:FAIL" in result.stdout:
        score += 1
    elif "Segmentation fault" in result.stderr:
        print("Segmentation fault detected, counting as FAIL")
        score += 1

    # Do it again with non vulnerable
    result = run_unit_test(case.harness_header_with_context, case.get_replaceable_main_c(case.fixed_function_body, response))
    print("STDOUT and STDERR for fixed version:")
    print(result.stdout)
    print(result.stderr)
    if "RESULT:PASS" in result.stdout:
        score += 1

    return score