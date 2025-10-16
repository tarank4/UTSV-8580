import argparse
import os
import json
import google.generativeai as genai

# --- Configuration ---
API_KEY_FILE = "gemini.key"

if not os.path.exists(API_KEY_FILE):
    print(f"Error: API key file not found at {API_KEY_FILE}")
    print("Please create a file named 'gemini.key' in the root directory of the project and paste your API key in it.")
    exit()

with open(API_KEY_FILE, 'r') as f:
    api_key = f.read().strip()

genai.configure(api_key=api_key)





def run_experiment(code, prompt_path):
    """
    Runs a single experiment.

    Args:
        code (str): Path to the code snippet in the format <cwe_id>/<filename>.
        prompt_path (str): Path to the JSON file containing the prompt templates.
    """
    try:
        cwe_id, code_file = code.split('/', 1)
    except ValueError:
        print(f"Error: Invalid code path format: {code}. Expected format: <cwe_id>/<filename>")
        return

    code_path = os.path.join("data", "preprocessed", cwe_id, code_file)
    if not os.path.exists(code_path):
        print(f"Error: Code file not found at {code_path}")
        return

    if not os.path.exists(prompt_path):
        print(f"Error: Prompt file not found at {prompt_path}")
        return

    # 1. Read the prompt file
    with open(prompt_path, 'r') as f:
        prompt_data = json.load(f)
    system_prompt = prompt_data["system_prompt"]
    user_prompt_template = prompt_data["user_prompt"]

    # Determine experiment type
    if "classify_only" in prompt_path:
        experiment_type = "classify_only"
    elif "test_first" in prompt_path:
        experiment_type = "test_first"
    else:
        experiment_type = "unknown"

    # 2. Read the code snippet
    with open(code_path, 'r') as f:
        code_snippet = f.read()

    # 3. Inject code into the user prompt
    prompt = user_prompt_template.format(code_snippet=code_snippet)

    # 4. Call the Gemini API
    print("===================================")
    print(f"Running experiment for {cwe_id}...")
    print(f"Code: {os.path.basename(code_path)}")
    print(f"Prompt: {os.path.basename(prompt_path)}")
    print("===================================")
    print("\n--- SYSTEM PROMPT ---")
    print(system_prompt)
    print("\n--- USER PROMPT ---")
    print(prompt)
    print("----------------")

    model = genai.GenerativeModel(model_name="gemini-2.5-flash", system_instruction=system_prompt)
    response = model.generate_content(prompt)

    # 5. Parse and save the response
    model_name = model.model_name.split('/')[-1]
    code_file_name = os.path.basename(code_path).replace('.cpp', '')
    results_dir = os.path.join("results", model_name, cwe_id, code_file_name)
    os.makedirs(results_dir, exist_ok=True)

    prompt_name = os.path.basename(prompt_path).replace('.json', '')
    output_filename = f"{prompt_name}_response.json"
    output_path = os.path.join(results_dir, output_filename)

    result = {"model": model.model_name}

    response_text = response.text.strip()
    lines = response_text.splitlines()
    structured_response_line = lines[-1]

    parts = [p.strip() for p in structured_response_line.split('|')]
    response_data = {}
    for part in parts:
        try:
            key, value = part.split(':', 1)
            response_data[key.strip()] = value.strip()
        except ValueError:
            pass

    result["answer"] = response_data.get("vulnerability", "N/A")
    result["cwe_id"] = response_data.get("cwe_id", "N/A")
    result["explanation"] = response_data.get("explanation", "")

    if experiment_type == "test_first":
        unit_test_lines = lines[:-1]
        # Find C++ code block
        cpp_code_start = -1
        cpp_code_end = -1
        for i, line in enumerate(unit_test_lines):
            if "```cpp" in line:
                cpp_code_start = i
            elif "```" in line:
                cpp_code_end = i
        
        if cpp_code_start != -1 and cpp_code_end != -1:
            result["unit_test"] = "\n".join(unit_test_lines[cpp_code_start+1:cpp_code_end])
        else:
            result["unit_test"] = "\n".join(unit_test_lines)

    with open(output_path, 'w') as f:
        json.dump(result, f, indent=4)

    print(f"\nResponse saved to {output_path}")
    print("===================================")

# example: python scripts/run_experiment.py --code CWE-476/null_ptr_bad_1.cpp --prompt_path prompts/classify_only.json
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a security vulnerability detection experiment with an LLM.")
    parser.add_argument("--code", required=True, help="Path to the code snippet in the format <cwe_id>/<filename>.")
    parser.add_argument("--prompt_path", required=True, help="Path to the prompt template file.")
    args = parser.parse_args()

    run_experiment(args.code, args.prompt_path)
