import argparse
import json
import os
from pathlib import Path
from tqdm import tqdm

import pandas as pd

from models.llama import LlamaModel
from models.qwen import QwenModel
from models.deepkseek_api import DeepSeekAPIModel
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
        "--model-type",
        choices=["qwen", "llama", "deepseek"],
        default="deepseek",
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

    parser.add_argument(
        "--deepseek-name",
        default="deepseek-chat",
        help="DeepSeek model name (if --model-type deepseek).",
    )

    parser.add_argument(
        "--use-apptainer",
        action="store_true",
        help="Whether to use Apptainer for running unit tests.",
    )
    return parser.parse_args()


def load_model(args, logger: MyLogger):
    if args.model_type == "llama":
        return LlamaModel(args.llama_name, logger)
    elif args.model_type == "deepseek":
        return DeepSeekAPIModel(args.deepseek_name, logger)
    elif args.model_type == "qwen":
        return QwenModel(args.qwen_name, logger)
    else:
        raise ValueError(f"Unknown model type: {args.model_type}")
    
def run_inference_single_stage(
    dataset: pd.DataFrame,
    model,
    logger: MyLogger,
    responses_path: Path,
):
    responses_path.parent.mkdir(parents=True, exist_ok=True)
    with responses_path.open("w", encoding="utf-8") as f_out:
        for case_idx, row in dataset.iterrows():
            case: Case = build_case_from_row(row.to_dict())
            print("Case:", case)
            logger.log(f"Case {case_idx}: {case}")
            print("=" * 20)

            print("=================== Prompt: ==================")
            print("Prompt:", case.get_prompt())

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a C low-level programming expert. "
                        "You must output only the unit test implementation code and analysis. "
                        "No other text."
                    ),
                },
                {
                    "role": "user",
                    "content": case.get_prompt(),
                },
            ]
            response = model.predict(messages, batch_size=1, no_progress_bar=False)

            print("=================== Response: ==================")
            print(response)
            print()

            # Get results for that response
            evaluation_result = evaluate_unit_test(case, response, use_apptainer=False)

            print("Evaluation result markdown:", evaluation_result.as_markdown())

            record = {
                "case_idx": int(case_idx),
                "cve_list": case.cve_list,
                "score": evaluation_result.total_score,
                "final_evaluation": evaluation_result.__dict__,
                "response": response,
                "messages": messages,
            }

            print("Score:", evaluation_result.total_score)
            json.dump(record, f_out)
            f_out.write("\n")


def run_inference_only_two_stage_with_analysis(
    dataset: pd.DataFrame,
    model,
    logger: MyLogger,
    responses_path: Path,
):
    responses_path.parent.mkdir(parents=True, exist_ok=True)
    with responses_path.open("w", encoding="utf-8") as f_out:
        for case_idx, row in tqdm(dataset.iterrows(), total=len(dataset)):
            if case_idx <= 24:
                continue
            case: Case = build_case_from_row(row.to_dict())
            print("Case:", case)
            logger.log(f"Case {case_idx}: {case}")
            print("=" * 20)

            print("=================== Prompt: ==================")
            print("Prompt:", case.get_prompt())

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a C low-level programming expert. "
                        "You must output exactly two sections: <ANALYSIS> </ANALYSIS> and <FINAL_CODE> </FINAL_CODE>. "
                        "No other text."
                    ),
                },
                {
                    "role": "user",
                    "content": case.get_prompt(),
                },
            ]
            first_response = model.predict(messages, batch_size=1, no_progress_bar=False)

            print("=================== Response: ==================")
            print(first_response)
            print()

            # Get results for that response
            evaluation_result = evaluate_unit_test(case, first_response, use_apptainer=False)

            print("Evaluation result markdown:", evaluation_result.as_markdown())

            # Ask it to refine and respond again to the prompt
            messages.extend([
                {
                    "role": "assistant",
                    "content": first_response,
                },
                {
                    "role": "system",
                    "content": (
                        "Results from running your unit test on the vulnerable and fixed functions:\n"
                        f"{evaluation_result.as_markdown()} \n"
                        )
                },
                {
                    "role": "user",
                    "content": (
                        "Rewrite your <ANALYSIS> </ANALYSIS> and <FINAL_CODE> unit test implementation </FINAL_CODE> to fix any mistakes or issues in the first attempt to get "
                        "pass on the fixed version and fail on the vulnerable version. "
                        "Your analysis should reflect on what went wrong in the first attempt. "
                    ),
                }
            ]
            )

            second_response = model.predict(messages, batch_size=1, no_progress_bar=False)

            print("=================== Refined Response: ==================")
            print(second_response)
            print()

            final_evaluation_result = evaluate_unit_test(case, second_response, use_apptainer=False)


            record = {
                "case_idx": int(case_idx),
                "cve_list": case.cve_list,
                "score": final_evaluation_result.total_score,
                "final_evaluation": final_evaluation_result.__dict__,
                "response": second_response,
                "messages": messages,
                "intermediate_evaluation": evaluation_result.__dict__,
            }

            print("Final Evaluation result markdown:", final_evaluation_result.as_markdown())
            json.dump(record, f_out)
            f_out.write("\n")
            print("Score:", final_evaluation_result.total_score)


def run_run_only(
    dataset: pd.DataFrame,
    logger: MyLogger,
    responses_path: Path,
    use_apptainer: bool,
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

    score_report_columns = ["case_idx", "fail_on_vuln", "pass_on_fixed", "total_score"]
    score_report = []

    for case_idx, row in dataset.iterrows():
        if case_idx <= 24:
            continue
        if case_idx not in responses_by_idx:
            print(f"Skipping case {case_idx}: no stored response found.")
            logger.log(f"Skipping case {case_idx}: no stored response found.")
            continue

        case: Case = build_case_from_row(row.to_dict())
        response = responses_by_idx[case_idx]

        print("Case:", case)
        logger.log(f"Case {case_idx}: {case}")
        print("=" * 20)

        evaluation_result = evaluate_unit_test(case, response, use_apptainer=use_apptainer)
        print("Evaluation result:", evaluation_result)
        with eval_log_path.open("a", encoding="utf-8") as f_eval:
            f_eval.write(f"Case {case_idx}: Score {evaluation_result}\n")
        
        score_report.append(
            (case_idx, evaluation_result.fail_on_vuln, evaluation_result.pass_on_fixed, evaluation_result.total_score)
        )

    score_report_df = pd.DataFrame(
        score_report,
        columns=score_report_columns,
    )
    score_report_df.to_csv("logs/score_report.csv", index=False)
    print("Score report:")
    print(score_report_df)


        


def run_both(
    dataset: pd.DataFrame,
    model,
    logger: MyLogger,
    responses_path: Path,
    use_apptainer: bool,
):
    # dataset is just idx 50
    # dataset = dataset.iloc[[7]]

    # Only keep case_idx > 24
    # dataset = dataset[dataset.index > 24]
    run_inference_only_two_stage_with_analysis(
        dataset,
        model,
        logger,
        responses_path,
    )
    # run_run_only(
    #     dataset,
    #     logger,
    #     responses_path,
    #     use_apptainer,
    # )


def main():
    args = parse_args()

    # Ensure logs dir exists for the logger
    Path("logs").mkdir(exist_ok=True)
    logger = MyLogger("logs/main.log")

    dataset: pd.DataFrame = pd.read_csv(args.dataset_path)
    print("Dataset loaded with {} rows".format(len(dataset)))
    logger.log(f"Dataset loaded with {len(dataset)} rows from {args.dataset_path}")

    nice_string_args = "_".join(
        f"{k}-{v}" for k, v in sorted(vars(args).items()) if k != "dataset_path"
    )

    experiment_name = f"experiment_{nice_string_args}"
    responses_path = Path(f"logs/{experiment_name}_responses.jsonl")

    if args.mode in ("inference-only", "both"):
        model = load_model(args, logger)
    else:
        model = None  # Not needed in run-only mode

    if args.mode == "inference-only":
        run_inference_only(dataset, model, logger, responses_path)
    elif args.mode == "run-only":
        run_run_only(dataset, logger, responses_path, args.use_apptainer)
    else:  # both
        run_both(dataset, model, logger, responses_path, args.use_apptainer)



if __name__ == "__main__":
    main()
