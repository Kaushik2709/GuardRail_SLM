"""Regression-test the actual notebook formatter without GPU/training imports."""
import ast
import json
from pathlib import Path
import pytest


def formatter():
    nb = json.loads((Path(__file__).resolve().parents[1]/"notebooks"/"train_guardrail_colab.ipynb").read_text(encoding="utf-8"))
    source = next("".join(c["source"]) for c in nb["cells"] if "def format_rows" in "".join(c["source"]))
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "format_rows"
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "LABELS" for t in n.targets)]
    class Tokenizer:
        def apply_chat_template(self, conversation, **kwargs):
            return conversation[-1]["content"]
        def __call__(self, text, **kwargs):
            return {"input_ids": [1] * 10}
    scope = {"json": json, "tokenizer": Tokenizer(), "SYSTEM_PROMPT": "test"}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "notebook formatter", "exec"), scope)
    return scope["format_rows"]

@pytest.mark.parametrize("category,expected", [("SAFE", "[SAFE]"), ("TOOL_POISONING", "[MALICIOUS_TOOL_CALL]"),
                                              ("INJECTION_DIRECT", "[INJECTION_DIRECT]"), ("PII_LEAK", "[PII_LEAK]")])
def test_generated_categories_are_not_defaulted_to_safe(tmp_path, category, expected):
    p = tmp_path/"train.jsonl"
    p.write_text(json.dumps({"text": "example", "category": category, "is_safe": category == "SAFE"})+"\n", encoding="utf-8")
    assert formatter()(str(p))[0]["text"] == expected

@pytest.mark.parametrize("row", [{"text": "example"}, {"text": "example", "category": "UNKNOWN"},
                                   {"text": "example", "category": "INJECTION_DIRECT", "is_safe": True}])
def test_invalid_training_labels_fail(tmp_path, row):
    p = tmp_path/"train.jsonl"
    p.write_text(json.dumps(row)+"\n", encoding="utf-8")
    with pytest.raises(ValueError): formatter()(str(p))
