"""
Given an LLMs response it will evaluate if the unit test succesfully passes on the fixed version and fails on the vulnerable version.
This will run the unit test against both versions.
"""

from case import Case
from evaluation.runner import run_unit_test, RunResult
from dataclasses import dataclass

import os

@dataclass
class EvaluationResult:
    fail_on_vuln: bool
    pass_on_fixed: bool
    total_score: int
    vul_stdout: str = ""
    vul_stderr: str = ""
    fix_stdout: str = ""
    fix_stderr: str = ""

    def as_markdown(self):
        return (
            f"# Evaluation Result\n"
            f"- Fail on Vulnerable: {'Yes' if self.fail_on_vuln else 'No'}\n"
            f"- Pass on Fixed: {'Yes' if self.pass_on_fixed else 'No'}\n"
            f"- Total Score: {self.total_score}\n"
            f"## Vulnerable Version Output\n"
            f"### STDOUT\n"
            f"```\n{self.vul_stdout}\n```\n"
            f"### STDERR\n"
            f"```\n{self.vul_stderr}\n```\n"
            f"## Fixed Version Output\n"
            f"### STDOUT\n" 
            f"```\n{self.fix_stdout}\n```\n"
            f"### STDERR\n"
            f"```\n{self.fix_stderr}\n```\n"
        )

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
    
    if "<FINAL_CODE>" in response and "</FINAL_CODE>" in response:
        start = response.index("<FINAL_CODE>") + len("<FINAL_CODE>")
        end = response.index("</FINAL_CODE>")
        return response[start:end].strip()
    return response.strip()


def evaluate_unit_test(case: Case, response: str, use_apptainer: bool) -> EvaluationResult:
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

    result_vul = run_unit_test(case.harness_header_with_context, case.get_replaceable_main_c(case.vulnerable_function_body, response), use_apptainer=use_apptainer)

    fail_on_vuln = False
    pass_on_fixed = False


    if "RESULT:FAIL" in result_vul.stdout:
        fail_on_vuln = True
    elif "Segmentation fault" in result_vul.stderr:
        print("Segmentation fault detected, counting as FAIL")
        fail_on_vuln = True
    elif result_vul.returncode != 0:
        print(f"Non-zero return code ({result_vul.returncode}) detected, counting as FAIL")
        fail_on_vuln = True

    # Do it again with non vulnerable
    result_fix = run_unit_test(case.harness_header_with_context, case.get_replaceable_main_c(case.fixed_function_body, response), use_apptainer=use_apptainer)
    print("STDOUT and STDERR for fixed version:")
    print(result_fix.stdout)
    print(result_fix.stderr)
    if "RESULT:PASS" in result_fix.stdout:
        pass_on_fixed = True

    return EvaluationResult(
        fail_on_vuln=fail_on_vuln,
        pass_on_fixed=pass_on_fixed,
        total_score=int(fail_on_vuln) + int(pass_on_fixed),
        vul_stdout=result_vul.stdout,
        vul_stderr=result_vul.stderr,
        fix_stdout=result_fix.stdout,
        fix_stderr=result_fix.stderr,
    )