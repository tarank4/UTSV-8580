from pathlib import Path
import json

harness_dir = Path("harness/")
prompt_dir = Path("prompts/prompt_v2.md")


def get_harness_header() -> str:
    with open(harness_dir / "harness.h", "r") as f:
        return f.read()


def get_main_c() -> str:
    with open(harness_dir / "main.c", "r") as f:
        return f.read()


def get_main_test_replace() -> str:
    with open(harness_dir / "main_test_replace.c", "r") as f:
        return f.read()


class Case:
    harness_header = get_harness_header()
    main_c = get_main_c()
    main_test_replace = get_main_test_replace()

    def __init__(
        self,
        cve_list: str,
        function_name: str,
        vulnerable_function_body: str,
        fixed_function_body: str,
        context: str = "",
    ):
        self.cve_list = cve_list
        self.function_name = function_name
        self.vulnerable_function_body = self.clean_body(vulnerable_function_body)
        self.fixed_function_body = self.clean_body(fixed_function_body)
        self.function_signature = self.extract_function_signature()
        self.context = context
        self.harness_header_with_context = Case.harness_header.format(
            context=self.context
        )

    def extract_function_signature(self) -> str:
        # No newline version of the body for easier parsing
        body_single_line = " ".join(self.vulnerable_function_body.splitlines())
        # Find the position of the opening brace
        brace_pos = body_single_line.find("{")
        if brace_pos == -1:
            raise ValueError("Invalid function body: no opening brace found.")
        # Extract the part before the opening brace
        signature_part = body_single_line[:brace_pos].strip()
        return signature_part

    def clean_body(self, body: str) -> str:
        """
        Remove static or inline keywords from function body to avoid linkage issues in the harness.
        """
        body = body.replace("static ", "")
        body = body.replace("inline ", "")

        # If there is no return type, than insert "void " at the start
        first_line = body.splitlines()[0].strip()
        return_type = first_line.split(" ")[0]
        if return_type == self.function_name:
            body = "void " + body

        return body.strip()

    def get_replaceable_main_c(
        self, function_body, run_test_implementation: str
    ) -> str:
        return Case.main_test_replace.format(
            function_signature=self.function_signature,
            function_body=function_body,
            run_test_implementation=run_test_implementation,
        )

    def get_prompt(self) -> str:
        with open(prompt_dir, "r") as f:
            prompt_template = f.read()

        prompt = prompt_template.format(
            vulnerable_function_body=self.vulnerable_function_body,
            fixed_function_body=self.fixed_function_body,
            harness_h=self.harness_header_with_context,
            main_c=Case.main_c.format(
                function_signature=self.function_signature,
                function_body=self.vulnerable_function_body,
            ),
        )

        return prompt

    def __str__(self) -> str:
        return f"Case(cve_list={self.cve_list})"

    def to_dict(self) -> dict:
        return {
            "cve_list": self.cve_list,
            "function_name": self.function_name,
            "vulnerable_function_body": self.vulnerable_function_body,
            "fixed_function_body": self.fixed_function_body,
            "context": self.context,
        }

    @staticmethod
    def from_dict(data: dict) -> "Case":
        return Case(
            cve_list=data["cve_list"],
            function_name=data["function_name"],
            vulnerable_function_body=data["vulnerable_function_body"],
            fixed_function_body=data["fixed_function_body"],
            context=data.get("context", ""),
        )


def build_case_from_row(row: dict) -> Case:
    return Case(
        cve_list=row["cve_list"],
        function_name=row["func_name"],
        vulnerable_function_body=row["vuln_func_body"],
        fixed_function_body=row["fixed_func_body"],
        context=row.get("generated_context", ""),
    )

