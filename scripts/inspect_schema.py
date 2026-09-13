# scripts/inspect_schema.py
from datasets import load_dataset

jb = load_dataset("walledai/JailbreakBench", split="train[:3]")
print("JailbreakBench features:", jb.column_names)
print("JailbreakBench sample:", jb[0])

pii = load_dataset("ai4privacy/pii-masking-300k", split="train[:3]")
print("PII features:", pii.column_names)
print("PII sample:", pii[0])
