# models/deepseek_thinking.py
from transformers import AutoTokenizer, AutoModelForCausalLM
import re
import os
from typing import List, Dict, Any, Tuple, Union
from utils.mylogger import MyLogger
from models.llm import LLM

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "max_split_size_mb:256")

# You can expand this as you add new checkpoints
_model_name_map = {
    # Thinking variants. Keep these generic and allow override via kwargs.
    # Example ids you might use when available:
    "deepseek-r1-7b":  "deepseek-ai/DeepSeek-R1-Distill-7B",
    "deepseek-r1-8b":  "deepseek-ai/DeepSeek-R1-Distill-Llama-8B",
}

# Match DeepSeek style thoughts. Handles either <think>...</think> or special markers.
_THINK_BLOCKS = [
    re.compile(r"^\s*<think>(.*?)</think>\s*", re.S | re.I),
    # Some checkpoints use special unicode-like markers. Keep it permissive.
    re.compile(r"^\s*<\|begin.*?thinking\|>(.*?)<\|end.*?thinking\|>\s*", re.S | re.I),
]

def split_thoughts(text: str) -> Tuple[str, str]:
    """Return (thoughts, final). If none found, thoughts='' and final=text."""
    if not text:
        return "", ""
    for pat in _THINK_BLOCKS:
        m = pat.match(text)
        if m:
            return (m.group(1).strip(), text[m.end():].strip())
    return "", text.strip()

class DeepSeekThinkingModel(LLM):
    """
    Transformers adapter that supports DeepSeek 'thinking' models.
    - Strips reasoning by default. Set return_thoughts=True to include it.
    - Compatible with your existing LLM base and predict_main().
    """
    def __init__(self, model_name: str, logger: MyLogger, **kwargs):
        # Allow override of the HF repo id without changing _model_name_map
        override = kwargs.pop("override_model_id", None)
        if override:
            _model_name_map[model_name] = override

        super().__init__(model_name, logger, _model_name_map, **kwargs)

        # Optional behavior flags
        self.return_thoughts: bool = bool(kwargs.get("return_thoughts", False))
        self.keep_thoughts_in_text: bool = bool(kwargs.get("keep_thoughts_in_text", False))

        # Reasonable defaults for thinking models
        self.model_hyperparams.setdefault("temperature", 0.2)
        self.model_hyperparams.setdefault("top_p", 0.9)
        self.model_hyperparams.setdefault("max_new_tokens", 512)
        self.model_hyperparams.setdefault("repetition_penalty", 1.1)
        self.model_hyperparams.setdefault("no_repeat_ngram_size", 8)

        # EOS and optional terminators
        self.terminators = [self.pipe.tokenizer.eos_token_id]

    def _merge_sys_user(self, d: List[Dict[str, str]]) -> List[Dict[str, str]]:
        # Your current batch path merges system + user into one user message
        newd = {"role": "user", "content": d[0]["content"] + "\n" + d[1]["content"]}
        return [newd]

    def _maybe_strip_thoughts(self, text: str) -> str:
        thoughts, final = split_thoughts(text)
        if self.return_thoughts and thoughts:
            self.log("[THOUGHTS]\n" + thoughts)
        if self.keep_thoughts_in_text:
            return text
        return final or text

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        # Batch mode
        if batch_size > 0:
            prompts = []
            for p in main_prompt:
                merged = self._merge_sys_user(p)
                s = self.pipe.tokenizer.apply_chat_template(
                    merged, tokenize=False, add_generation_prompt=True
                )
                prompts.append(s)

            # For repeatability in batch eval
            self.model_hyperparams["temperature"] = 0.0

            outs = self.predict_main(
                prompts, batch_size=batch_size, no_progress_bar=no_progress_bar
            )
            # predict_main can return list[str] or list[dict]. Normalize to str and strip thoughts.
            cleaned = []
            for o in outs:
                text = o if isinstance(o, str) else str(o)
                cleaned.append(self._maybe_strip_thoughts(text))
            return cleaned

        # Single
        prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, tokenize=False, add_generation_prompt=True
        )
        l = len(self.tokenizer.tokenize(prompt))
        self.log("Prompt length:" + str(l))
        limit = 16000 if self.kwargs["max_input_tokens"] is None else self.kwargs["max_input_tokens"]
        if l > limit:
            return "Too long, skipping: " + str(l)

        # Slight randomness is fine here. Set lower if you need stability.
        self.model_hyperparams["temperature"] = float(self.model_hyperparams.get("temperature", 0.2))

        raw = self.predict_main(prompt, no_progress_bar=no_progress_bar)
        text = raw if isinstance(raw, str) else str(raw)
        return self._maybe_strip_thoughts(text)
