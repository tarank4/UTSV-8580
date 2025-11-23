import pandas as pd

from models.llama import LlamaModel
from models.qwen import QwenModel
from utils.mylogger import MyLogger
from case import build_case_from_row, Case
from evaluation.eval import evaluate_unit_test
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Change hugging face cache dir
os.environ["HF_HOME"] = "/scratch/ema8/huggingface_cache"

logger = MyLogger("logs/main.log")

dataset: pd.DataFrame = pd.read_csv("data/dataset_unified_with_context.csv")
print("Dataset loaded with {} rows".format(len(dataset)))

# model = LlamaModel("llama-3.1-8b-instruct", logger)
model = QwenModel("qwen2.5-coder-7b-instruct", logger)

for case_idx, row in dataset.iterrows():
    case: Case = build_case_from_row(row.to_dict())
    print("Case:", case)
    logger.log(f"Case {case_idx}: {case}")

    # print("Vulnerable function body:", case.vulnerable_function_body)
    # print("Fixed function body:", case.fixed_function_body)

    print("=" * 20)
    # print("Prompt for the example case:")
    # print(case.get_prompt())
    messages = [
        {
            "role": "system",
            "content": (
                "You are a tool that ONLY generates C unit tests for a given harness. "
                "You must respond with C code ONLY, no explanations, no markdown, "
                "no patched versions of the vulnerable function."
            ),
        },
        {
            "role": "user",
            "content": case.get_prompt(),
        },
    ]
    response = model.predict(messages, batch_size=1, no_progress_bar=False)
    # print("=" * 20)
    # print("Model response:")
    # print(response)

    # print("=" * 20)
    # print("Evaluating the generated unit test...")
    evaluation_result = evaluate_unit_test(case, response)
    print("Evaluation result:", evaluation_result)
    with open("logs/evaluation_results.txt", "a") as f:
        f.write(f"Case {case_idx}: Score {evaluation_result}\n")



