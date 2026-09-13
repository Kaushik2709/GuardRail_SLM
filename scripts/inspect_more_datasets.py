# scripts/inspect_more_datasets.py
from datasets import load_dataset

candidates = [
    ("jackhhao/jailbreak-dataset", {}),
    ("MarkrAI/Jailbreak-Dataset", {}),
    ("TrustAIRLab/in-the-wild-jailbreak-prompts", {}),
    ("qualifire/tensortrust", {}),
    ("ai4privacy/pii-masking-300k", {"split": "train[:10]"}),
    ("walledai/JailbreakBench", {"split": "train[:10]"}),
    ("JailbreakBench/JailbreakBench", {}),
    ("fmps/prompt-injection", {"split": "train[:10]"}),
]

for name, kwargs in candidates:
    try:
        ds = load_dataset(name, **kwargs)
        print(f"[SUCCESS] {name}")
    except Exception as e:
        print(f"[FAILED] {name}: {str(e)[:100]}")
