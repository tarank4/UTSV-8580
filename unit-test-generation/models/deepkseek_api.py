from openai import OpenAI
from tqdm.contrib.concurrent import thread_map
import os

import models.config as config
from utils.mylogger import MyLogger
from models.llm import LLM

# DeepSeek API model ids are OpenAI-compatible. Base URL is https://api.deepseek.com
# and models like "deepseek-chat" and "deepseek-reasoner" are supported. :contentReference[oaicite:0]{index=0}
_model_name_map = {
    "deepseek-chat": "deepseek-chat",
    "deepseek-reasoner": "deepseek-reasoner",
}

class DeepSeekAPIModel(LLM):
    """
    DeepSeek API wrapper.

    Expected input:
      - Single conversation: list[{"role": "...", "content": "..."}]
      - Batched: list of conversations above, with batch_size > 0

    Notes:
      - DeepSeek API is OpenAI-style /chat/completions. :contentReference[oaicite:1]{index=1}
      - deepseek-reasoner returns reasoning_content in addition to content and ignores
        temperature/top_p/etc. :contentReference[oaicite:2]{index=2}
    """

    def __init__(self, model_name, logger: MyLogger, **kwargs):
        # Do NOT call super().__init__ since this is not a local HF model.
        self.logger = logger
        self.model_name = _model_name_map.get(model_name, model_name)

        api_key = kwargs.pop("api_key", None) \
            or os.getenv("DEEPSEEK_API_KEY") \
            or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "DeepSeek API key not found. Set DEEPSEEK_API_KEY or pass api_key=..."
            )

        base_url = kwargs.pop(
            "base_url",
            os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        )

        self.client = OpenAI(api_key=api_key, base_url=base_url)

        # Default hyperparams, can be overridden via kwargs
        self.model_hyperparams = {
            "temperature": kwargs.pop("temperature", 0.01),
            "top_p": kwargs.pop("top_p", 1.0),
            "max_tokens": kwargs.pop(
                "max_tokens",
                getattr(config, "MAX_TOKENS", 4096)
            ),
            "stream": kwargs.pop("stream", False),
            "stop": kwargs.pop("stop", None),
            # If True and using deepseek-reasoner, return dict with reasoning + content
            "return_reasoning": kwargs.pop("return_reasoning", False),
        }
        # Keep any extra OpenAI-compatible params (presence_penalty, frequency_penalty, etc.)
        self.model_hyperparams.update(kwargs)

    def _build_request_params(self):
        params = dict(self.model_hyperparams)

        # deepseek-reasoner does not support or use sampling params. :contentReference[oaicite:3]{index=3}
        if self.model_name == "deepseek-reasoner":
            for k in ("temperature", "top_p", "presence_penalty", "frequency_penalty"):
                params.pop(k, None)

        # Remove local-only flags from request body
        params.pop("return_reasoning", None)

        # OpenAI SDK wants stop absent if None
        if params.get("stop") is None:
            params.pop("stop", None)

        return params

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        # Batched API run using threads, matching other wrappers.
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
        params = self._build_request_params()

        # print("Predicting DeepSeek with params:", params)

        # Add a system prompt to the front that says not to think for too long
        system_prompt = (
            "You are a helpful assistant that responds quickly. "
            "Reason just enough to answer, but do not overthink your responses. "
        )
        prompt_messages = [{"role": "system", "content": system_prompt}] + prompt_messages

        # print("Final prompt:", prompt_messages)

        try:
            if params.get("stream", False):
                stream = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=prompt_messages,
                    stream=True,
                    **{k: v for k, v in params.items() if k != "stream"},
                )
                parts = []
                reasoning_parts = []
                for chunk in stream:
                    if not chunk.choices:
                        continue
                    delta = chunk.choices[0].delta

                    # Support both attr and dict style deltas
                    rc = getattr(delta, "reasoning_content", None) \
                        or (delta.get("reasoning_content") if hasattr(delta, "get") else None)
                    c = getattr(delta, "content", None) \
                        or (delta.get("content") if hasattr(delta, "get") else None)

                    if rc:
                        reasoning_parts.append(rc)
                    if c:
                        parts.append(c)

                content = "".join(parts).strip()
                reasoning = "".join(reasoning_parts).strip()

            else:
                resp = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=prompt_messages,
                    **params,
                )
                msg = resp.choices[0].message

                content = getattr(msg, "content", None) \
                    or (msg.get("content") if hasattr(msg, "get") else "") \
                    or ""
                content = content.strip()

                reasoning = getattr(msg, "reasoning_content", None) \
                    or (msg.get("reasoning_content") if hasattr(msg, "get") else None) \
                    or ""
                reasoning = reasoning.strip()

        except Exception as e:
            # Log and re-raise so your pipeline can handle it.
            try:
                self.logger.log(f"DeepSeek API error: {e}")
            except Exception:
                pass
            raise

        if self.model_name == "deepseek-reasoner" and self.model_hyperparams.get("return_reasoning", False):
            return {"reasoning": reasoning, "content": content}

        return content
