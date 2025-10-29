python main.py \
    --model_name llama-3.1-8b-instruct \
    --benchmark juliet-cpp-1.3 \
    --top_cwe 9 \
    --n_examples 20 \
    --prompting_technique unit_test_generic \
    --prompt generic \
    --sys_prompt unit_test \
    --vul True \


python utils/metrics_test.py \
    --results_dir shared/v2/study_results_v2/llama-3.1-8b-instruct_juliet-cpp-1.3_prompt-unit_test_generic_user-generic_system-unit_test \
    --dataset_csv_path datasets/juliet/juliet-cpp-1.3.csv \
    --dataset_index_col index