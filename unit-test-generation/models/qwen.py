from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from tqdm.contrib.concurrent import thread_map
import os

import models.config as config
from utils.mylogger import MyLogger
from models.llm import LLM

os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:64"
assert torch.cuda.is_available(), "CUDA not visible. Check drivers and CUDA_VISIBLE_DEVICES."

# Official Qwen2.5 family on HF. Sizes listed in the collection.
# Pick the ones that sensibly fit on A100 40/80GB in bf16/fp16.
_model_name_map = {
    # General instruct models
    "qwen2.5-7b-instruct":  "Qwen/Qwen2.5-7B-Instruct",
    "qwen2.5-14b-instruct": "Qwen/Qwen2.5-14B-Instruct",
    "qwen2.5-32b-instruct": "Qwen/Qwen2.5-32B-Instruct",
    # 72B typically needs A100 80GB bf16 or tensor parallel
    "qwen2.5-72b-instruct": "Qwen/Qwen2.5-72B-Instruct",

    # Coder variants (if you want them)
    "qwen2.5-coder-7b-instruct":  "Qwen/Qwen2.5-Coder-7B-Instruct",
    "qwen2.5-coder-32b-instruct": "Qwen/Qwen2.5-Coder-32B-Instruct",
}

class QwenModel(LLM):
    """
    Local-only Qwen wrapper.

    Expected input:
      - Single conversation: list[{"role": "...", "content": "..."}]
      - Batched: list of conversations above, with batch_size > 0
    """

    def __init__(self, model_name, logger: MyLogger, **kwargs):
        # A100-friendly defaults
        kwargs.setdefault("torch_dtype", torch.bfloat16)   # A100 supports bf16, saves VRAM
        kwargs.setdefault("device_map", "auto")           # single GPU auto-places
        kwargs.setdefault("trust_remote_code", True)      # Qwen uses custom modeling code
        # If your LLM base passes this into from_pretrained, it helps speed a lot on A100.
        kwargs.setdefault("attn_implementation", "flash_attention_2")

        super().__init__(model_name, logger, _model_name_map, **kwargs)

        tok = self.pipe.tokenizer

        # Stop tokens: EOS plus ChatML end token if present
        self.terminators = [tok.eos_token_id]
        for special in ("<|im_end|>", "<|endoftext|>"):
            tid = tok.convert_tokens_to_ids(special)
            if tid is not None and tid != tok.unk_token_id and tid not in self.terminators:
                self.terminators.append(tid)

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        # Batched local run using threads, like your Together path used to do.
        if batch_size and isinstance(main_prompt, list) and main_prompt:
            is_batched = isinstance(main_prompt[0], list)
            if is_batched:
                args = range(len(main_prompt))
                return thread_map(
                    lambda i: self.predict_one(main_prompt[i], no_progress_bar=True),
                    args,
                    max_workers=batch_size,
                    disable=no_progress_bar,
                )

        return self.predict_one(main_prompt, no_progress_bar=no_progress_bar)

    def predict_one(self, prompt_messages, no_progress_bar=False):
        # prompt_messages is a single conversation in HF chat format
        prompt_text = self.pipe.tokenizer.apply_chat_template(
            prompt_messages,
            tokenize=False,
            add_generation_prompt=True
        )

        # Keep your near-deterministic setting
        self.model_hyperparams["temperature"] = 0.01

        # predict_main should handle generate() and terminators
        return self.predict_main(prompt_text, no_progress_bar=no_progress_bar)
