import subprocess
import tempfile
from pathlib import Path
import shutil

# Where to store the Apptainer image (per user)
APPTAINER_IMAGE_PATH = Path("/home/ema8/UTSV-8580/containers/gcc_latest.sif")
# Source image to pull. You can pin a version if you want, for example "docker://gcc:14"
APPTAINER_URI = "docker://gcc:latest"


"""
Runs the unit tests and captures standard output and error.

Runs using a lightweight Apptainer container.

Files to compile:
- harness.h
- main.c

These are given as raw strings.
"""
def run_unit_test(harness_h_code: str, main_c_code: str) -> tuple[str, str]:

    tmpdir_path = Path(tempfile.mkdtemp(prefix="c_unit_harness_"))
    try:
        # Write the provided source files into the temp directory
        (tmpdir_path / "harness.h").write_text(harness_h_code, encoding="utf-8")
        (tmpdir_path / "main.c").write_text(main_c_code, encoding="utf-8")

        # Build the command:
        #   - bind the temp dir at /work
        #   - clean environment, no home mount
        #   - compile and run
        cmd = [
            "apptainer",
            "exec",
            "--cleanenv",
            "--no-home",
            "-B",
            f"{tmpdir_path}:/work",
            APPTAINER_IMAGE_PATH,
            "sh",
            "-lc",
            "cd /work && gcc -std=c11 -Wall -Wextra -O2 main.c -o main && ./main",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as e:
            return "", f"Failed to run apptainer: {e}. Is Apptainer installed and on PATH?"

        stdout = proc.stdout
        stderr = proc.stderr
        return stdout, stderr

    finally:
        # Best effort cleanup of temporary directory
        try:
            shutil.rmtree(tmpdir_path)
        except OSError:
            pass


# Example usage
if __name__ == "__main__":
    harness_h = """
    #ifndef HARNESS_H
    #define HARNESS_H

    void vulnerable_function(const char *input);

    #endif // HARNESS_H
    """

    main_c = """
    #include <stdio.h>
    #include <string.h>
    #include "harness.h"

    void vulnerable_function(const char *input) {
        char buffer[10];
        strcpy(buffer, input); // Potential buffer overflow
        printf("Buffer content: %s\\n", buffer);
    }

    void safe_function(const char *input) {
        char buffer[10];
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\\0'; // Ensure null-termination
        printf("Buffer content: %s\\n", buffer);
    }

    int main() {
        const char *test_input = "Some Text That Is Definitely Too Long";
        vulnerable_function(test_input);
        safe_function(test_input);
        return 0;
    }
    """

    out, err = run_unit_test(harness_h, main_c)
    print("STDOUT:")
    print(out)
    print("STDERR:")
    print(err)