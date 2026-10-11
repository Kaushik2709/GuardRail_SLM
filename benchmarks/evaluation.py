"""Shared strict dataset, metric and live-model verification helpers."""
import hashlib
import json
from pathlib import Path
import httpx
from app.core.slm_engine import SLMClassificationEngine
from app.core.heuristics import Classification

LABELS = {"SAFE", "INJECTION_DIRECT", "INJECTION_INDIRECT", "MALICIOUS_TOOL_CALL", "PII_LEAK"}

def normalize(text):
    return " ".join(text.casefold().split())

def family(row):
    source = row["source"].removesuffix("_augmented").removesuffix("_mutated")
    # All RAG templates reuse payloads; hold out the whole generator family.
    if source.startswith("synthetic/rag_"):
        return "synthetic/rag"
    return source

def read_rows(path):
    with open(path, encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    for row in rows:
        label = row.get("label", row.get("category", "" )).strip("[]")
        label = {"TOOL_POISONING": "MALICIOUS_TOOL_CALL"}.get(label, label)
        if label not in LABELS or not isinstance(row.get("text"), str) or not row["text"].strip():
            raise ValueError("Missing/invalid text or label")
        if not isinstance(row.get("source"), str) or not row["source"]:
            raise ValueError("Dataset must retain source provenance")
        if "is_safe" in row and row["is_safe"] != (label == "SAFE"):
            raise ValueError("Conflicting labels")
        row["label"] = f"[{label}]"
    if not rows:
        raise ValueError("Empty dataset")
    return rows

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def metrics(records):
    tp = sum(r["actual"] and r["blocked"] for r in records)
    fp = sum(not r["actual"] and r["blocked"] for r in records)
    tn = sum(not r["actual"] and not r["blocked"] for r in records)
    fn = sum(r["actual"] and not r["blocked"] for r in records)
    def ratio(a, b):
        return a / b if b else None
    return {"n": len(records), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "confusion_matrix": {"actual_threat": {"blocked": tp, "allowed": fn},
                                 "actual_benign": {"blocked": fp, "allowed": tn}},
            "accuracy": ratio(tp+tn, len(records)), "precision": ratio(tp, tp+fp),
            "recall": ratio(tp, tp+fn), "f1": ratio(2*tp, 2*tp+fp+fn),
            "false_positive_rate": ratio(fp, fp+tn), "false_negative_rate": ratio(fn, fn+tp),
            "indeterminate": sum(r["classification"] == "INDETERMINATE" for r in records)}

async def verify_model():
    url = SLMClassificationEngine().serving_url.rsplit("/v1/", 1)[0] + "/health"
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(url)
        response.raise_for_status()
        health = response.json()
    if health.get("neural_network_loaded") is not True or not isinstance(health.get("lora_adapter"), str) or not health["lora_adapter"]:
        raise RuntimeError("Benchmark requires a loaded fine-tuned adapter; base/fallback results rejected")
    if health.get("model") != SLMClassificationEngine().model_name:
        raise RuntimeError("Loaded model does not match requested model")
    return health

async def predict(engine, text, mode):
    if mode == "tier0":
        result = engine.heuristics.inspect(text)
    elif mode == "tier1":
        result = await engine.slm.classify(text)
    else:
        # Explicit modes do not depend on deployment enable flags.
        result = engine.heuristics.inspect(text)
        if result.is_safe:
            result = await engine.slm.classify(text)
    if mode != "tier0" and result.classification == Classification.INDETERMINATE:
        raise RuntimeError(f"Invalid model run: {result.details}")
    return result
