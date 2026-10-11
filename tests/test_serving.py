"""Offline server-contract tests; no weights or PyTorch installation required."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from contextlib import nullcontext
import pytest
from fastapi import HTTPException

spec = importlib.util.spec_from_file_location("guardrail_test_serving", Path(__file__).resolve().parents[1]/"docker"/"slm_server.py")
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)

@pytest.mark.asyncio
async def test_unready_server_returns_503(monkeypatch):
    monkeypatch.setattr(server, "model_loaded", False)
    with pytest.raises(HTTPException) as error:
        await server.create_completion(server.CompletionRequest(prompt="text"))
    assert error.value.status_code == 503

@pytest.mark.asyncio
async def test_empty_generation_is_not_replaced_with_safe(monkeypatch):
    class Tokens(list):
        def __getitem__(self, key):
            value = super().__getitem__(key)
            return Tokens(value) if isinstance(key, slice) else SimpleNamespace(item=lambda: value)
    class Inputs(dict):
        input_ids = SimpleNamespace(shape=(1, 1))
    class Tokenizer:
        eos_token_id = 0
        pad_token_id = 0
        def __call__(self, *args, **kwargs): return Inputs()
        def decode(self, *args, **kwargs): return ""
    monkeypatch.setattr(server, "tokenizer", Tokenizer())
    monkeypatch.setattr(server, "model", SimpleNamespace(generate=lambda **kwargs: [Tokens([1,0])]))
    monkeypatch.setattr(server, "model_loaded", True)
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(no_grad=nullcontext))
    result = await server.create_completion(server.CompletionRequest(prompt="text", max_tokens=32))
    assert result.choices[0].text == ""


def test_adapter_failure_does_not_mark_base_model_ready(monkeypatch):
    factory = SimpleNamespace(from_pretrained=lambda *a, **k: SimpleNamespace(pad_token="pad"))
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(float32="float32"))
    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace(AutoModelForCausalLM=factory, AutoTokenizer=factory))
    def fail(*args, **kwargs): raise RuntimeError("adapter missing")
    monkeypatch.setitem(sys.modules, "peft", SimpleNamespace(PeftModel=SimpleNamespace(from_pretrained=fail)))
    monkeypatch.setattr(server, "model_loaded", False)
    monkeypatch.setattr(server, "loading_error", None)
    monkeypatch.setattr(server, "model", None)
    monkeypatch.setattr(server, "tokenizer", None)
    server.load_slm_model()
    assert not server.model_loaded
    assert server.loading_error == "Required LoRA adapter could not be loaded"
