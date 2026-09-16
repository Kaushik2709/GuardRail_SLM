"""
GuardRail-Zero Tier-1 SLM Inference Engine.
Loads Qwen2.5-0.5B-Instruct neural network (with fine-tuned LoRA adapter)
and serves the OpenAI-compatible /v1/completions endpoint.
"""

import os
import time
import uuid
import logging
import threading
from typing import List, Optional, Union
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardrail.slm_server")

app = FastAPI(
    title="GuardRail-Zero Real SLM Inference Engine",
    version="0.1.0",
    description="Real Qwen2.5-0.5B neural network classification server"
)


class CompletionRequest(BaseModel):
    model: str = "Qwen/Qwen2.5-0.5B-Instruct"
    prompt: Union[str, List[str]]
    max_tokens: Optional[int] = 6
    temperature: Optional[float] = 0.0
    stop: Optional[List[str]] = None


class Choice(BaseModel):
    text: str
    index: int = 0
    logprobs: Optional[dict] = None
    finish_reason: str = "stop"


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class CompletionResponse(BaseModel):
    id: str
    object: str = "text_completion"
    created: int
    model: str
    choices: List[Choice]
    usage: Usage


# Global model and tokenizer
tokenizer = None
model = None
model_loaded = False
loading_error = None
lora_adapter_name = None
load_lock = threading.Lock()


def load_slm_model():
    """Loads Qwen2.5-0.5B-Instruct neural network and LoRA weights."""
    global tokenizer, model, model_loaded, loading_error, lora_adapter_name
    with load_lock:
        if model_loaded:
            return

        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        model_id = os.getenv("GUARDRAIL_SLM_MODEL_NAME", "Qwen/Qwen2.5-0.5B-Instruct")
        lora_id = os.getenv("GUARDRAIL_SLM_LORA_NAME", "Kaushik2709/guardrail-zero-qwen-0.5b-lora")

        try:
            logger.info(f"Loading Qwen2.5-0.5B neural network from {model_id}...")
            tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token

            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=torch.float32,
                device_map="cpu",
                trust_remote_code=True
            )

            if lora_id:
                try:
                    from peft import PeftModel
                    logger.info(f"Applying fine-tuned LoRA adapter from {lora_id}...")
                    model = PeftModel.from_pretrained(model, lora_id)
                    lora_adapter_name = lora_id
                    logger.info(f"Successfully loaded fine-tuned security LoRA adapter from {lora_id}!")
                except Exception as e:
                    logger.warning(f"Could not load LoRA from {lora_id}: {e}")

            model.eval()
            model_loaded = True
            logger.info("Real SLM neural network successfully loaded and ready for inference!")
        except Exception as ex:
            loading_error = str(ex)
            logger.error(f"Failed to load model: {ex}")


@app.on_event("startup")
async def startup_event():
    # Load model in a background thread so Uvicorn can immediately bind port 8001
    # and respond to /health requests with "initializing" status
    thread = threading.Thread(target=load_slm_model, daemon=True)
    thread.start()


@app.get("/")
@app.get("/health")
async def health():
    return {
        "status": "healthy" if model_loaded else ("error" if loading_error else "initializing"),
        "service": "guardrail-zero-slm",
        "model": os.getenv("GUARDRAIL_SLM_MODEL_NAME", "Qwen/Qwen2.5-0.5B-Instruct"),
        "lora_adapter": lora_adapter_name,
        "neural_network_loaded": model_loaded,
        "error": loading_error
    }


@app.post("/v1/completions", response_model=CompletionResponse)
async def create_completion(req: CompletionRequest):
    global model, tokenizer, model_loaded
    prompt_str = req.prompt if isinstance(req.prompt, str) else " ".join(req.prompt)

    if not model_loaded:
        load_slm_model()

    import torch
    inputs = tokenizer(prompt_str, return_tensors="pt")
    input_length = inputs.input_ids.shape[1]

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=req.max_tokens or 6,
            temperature=req.temperature if (req.temperature and req.temperature > 0) else 0.0,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id
        )

    # Decode only newly generated tokens
    new_tokens = outputs[0][input_length:]
    generated_text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

    # Ensure generated text is enclosed in brackets, e.g. [SAFE] or [INJECTION_DIRECT]
    if not generated_text:
        generated_text = "[SAFE]"
    else:
        if not generated_text.startswith("["):
            generated_text = f"[{generated_text}"
        if not generated_text.endswith("]"):
            generated_text = f"{generated_text}]"

    prompt_tokens = input_length
    completion_tokens = len(new_tokens)

    return CompletionResponse(
        id=f"cmpl-slm-{uuid.uuid4().hex[:8]}",
        created=int(time.time()),
        model=req.model,
        choices=[
            Choice(
                text=generated_text,
                index=0,
                finish_reason="stop"
            )
        ],
        usage=Usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens
        )
    )
