import argparse
import json
import os
from pathlib import Path

import pandas as pd

from models.llama import LlamaModel
from models.qwen import QwenModel
from utils.mylogger import MyLogger
from case import build_case_from_row, Case
from evaluation.eval import evaluate_unit_test

# Disable tokenizer parallelism spam
os.environ["TOKENIZERS_PARALLELISM"] = "false"
# Change hugging face cache dir
os.environ["HF_HOME"] = "/scratch/ema8/huggingface_cache"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and/or evaluate C unit tests for vulnerable/fixed code."
    )
    parser.add_argument(
        "--mode",
        choices=["inference-only", "run-only", "both"],
        default="both",
        help=(
            "inference-only: run the LLM and save outputs, no evaluation\n"
            "run-only: load previously saved outputs and only run evaluation\n"
            "both: run inference and evaluation in a single pass"
        ),
    )
    parser.add_argument(
        "--dataset-path",
        default="data/dataset_unified_with_context.csv",
        help="Path to the CSV dataset.",
    )
    parser.add_argument(
        "--responses-path",
        default="logs/model_responses.jsonl",
        help="Path to JSONL file where model outputs are saved/loaded.",
    )
    parser.add_argument(
        "--model-type",
        choices=["qwen", "llama"],
        default="qwen",
        help="Which model wrapper to use.",
    )
    parser.add_argument(
        "--qwen-name",
        default="qwen2.5-coder-32b-instruct",
        help="Qwen model name (if --model-type qwen).",
    )
    parser.add_argument(
        "--llama-name",
        default="llama-3.1-8b-instruct",
        help="LLaMA model name (if --model-type llama).",
    )
    return parser.parse_args()


def load_model(model_type: str, llama_name: str, qwen_name: str, logger: MyLogger):
    if model_type == "llama":
        return LlamaModel(llama_name, logger)
    else:
        return QwenModel(qwen_name, logger)


def run_inference_only(
    dataset: pd.DataFrame,
    model,
    logger: MyLogger,
    responses_path: Path,
):
    responses_path.parent.mkdir(parents=True, exist_ok=True)
    with responses_path.open("w", encoding="utf-8") as f_out:
        for case_idx, row in dataset.iterrows():
            if case_idx != 52:
                continue
            case: Case = build_case_from_row(row.to_dict())
            print("Case:", case)
            logger.log(f"Case {case_idx}: {case}")
            print("=" * 20)

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

            record = {
                "case_idx": int(case_idx),
                "cve_list": case.cve_list,
                "response": response,
            }
            json.dump(record, f_out)
            f_out.write("\n")


def run_run_only(
    dataset: pd.DataFrame,
    logger: MyLogger,
    responses_path: Path,
):
    if not responses_path.exists():
        raise FileNotFoundError(
            f"Responses file '{responses_path}' does not exist. "
            "Run with --mode inference-only or both first."
        )

    # Load all responses into a dict keyed by case_idx
    responses_by_idx = {}
    with responses_path.open("r", encoding="utf-8") as f_in:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            responses_by_idx[int(rec["case_idx"])] = rec["response"]

    os.makedirs("logs", exist_ok=True)
    eval_log_path = Path("logs/evaluation_results.txt")

    for case_idx, row in dataset.iterrows():
        if case_idx not in responses_by_idx:
            print(f"Skipping case {case_idx}: no stored response found.")
            logger.log(f"Skipping case {case_idx}: no stored response found.")
            continue

        case: Case = build_case_from_row(row.to_dict())
        response = responses_by_idx[case_idx]

        print("Case:", case)
        logger.log(f"Case {case_idx}: {case}")
        print("=" * 20)

        evaluation_result = evaluate_unit_test(case, response)
        print("Evaluation result:", evaluation_result)
        with eval_log_path.open("a", encoding="utf-8") as f_eval:
            f_eval.write(f"Case {case_idx}: Score {evaluation_result}\n")


def run_both(
    dataset: pd.DataFrame,
    model,
    logger: MyLogger,
    responses_path: Path,
):
    responses_path.parent.mkdir(parents=True, exist_ok=True)
    eval_log_path = Path("logs/evaluation_results.txt")

    with responses_path.open("w", encoding="utf-8") as f_out:
        for case_idx, row in dataset.iterrows():
            case: Case = build_case_from_row(row.to_dict())
            print("Case:", case)
            logger.log(f"Case {case_idx}: {case}")
            print("=" * 20)

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

            # Save response for future run-only use
            record = {
                "case_idx": int(case_idx),
                "cve_list": case.cve_list,
                "response": response,
            }
            json.dump(record, f_out)
            f_out.write("\n")

            # Evaluate immediately
            evaluation_result = evaluate_unit_test(case, response)
            print("Evaluation result:", evaluation_result)
            with eval_log_path.open("a", encoding="utf-8") as f_eval:
                f_eval.write(f"Case {case_idx}: Score {evaluation_result}\n")


def main():
    args = parse_args()

    # Ensure logs dir exists for the logger
    Path("logs").mkdir(exist_ok=True)
    logger = MyLogger("logs/main.log")

    dataset: pd.DataFrame = pd.read_csv(args.dataset_path)
    print("Dataset loaded with {} rows".format(len(dataset)))
    logger.log(f"Dataset loaded with {len(dataset)} rows from {args.dataset_path}")

    responses_path = Path(args.responses_path)

    if args.mode in ("inference-only", "both"):
        model = load_model(args.model_type, args.llama_name, args.qwen_name, logger)
    else:
        model = None  # Not needed in run-only mode

    if args.mode == "inference-only":
        run_inference_only(dataset, model, logger, responses_path)
    elif args.mode == "run-only":
        run_run_only(dataset, logger, responses_path)
    else:  # both
        run_both(dataset, model, logger, responses_path)


if __name__ == "__main__":
    main()
