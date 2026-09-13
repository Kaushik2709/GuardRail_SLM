# scripts/inspect_datasets.py
import sys

print("Testing Hugging Face dataset accessibility...")

def test_load(dataset_name, *args, **kwargs):
    from datasets import load_dataset
    print(f"Testing {dataset_name}...")
    try:
        ds = load_dataset(dataset_name, *args, **kwargs)
        print(f"  [SUCCESS] {dataset_name}: {ds}")
        return True
    except Exception as e:
        print(f"  [FAILED] {dataset_name}: {e}")
        return False

test_load("deepset/prompt-injections", split="train[:10]")
test_load("yahma/alpaca-cleaned", split="train[:10]")
test_load("allenai/wildjailbreak", split="train[:10]")
test_load("rubend18/ChatGPT-Jailbreak-Prompts", split="train[:10]")
