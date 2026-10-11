import json
import pytest
from benchmarks.evaluation import metrics, read_rows, family
from benchmarks.benchmark_latency import percentile
from scripts.prepare_evaluation import prepare

def test_metrics_confusion_and_undefined_rates():
    rows = [{"actual": a, "blocked": b, "classification": "BLOCK" if b else "ALLOW"}
            for a,b in [(True,True),(False,True),(True,False),(False,False)]]
    m = metrics(rows)
    assert (m["tp"],m["fp"],m["tn"],m["fn"]) == (1,1,1,1)
    assert m["precision"] == m["recall"] == m["f1"] == .5
    assert m["false_negative_rate"] == m["false_positive_rate"] == .5
    assert metrics([])["accuracy"] is None
    assert percentile([1,2,3], .95) == pytest.approx(2.9)


def test_source_grouped_splits_and_label_contract(tmp_path):
    rows = [{"text": f"example {i}", "category": "TOOL_POISONING", "source": source, "is_safe": False}
            for i,source in enumerate(["one", "one_augmented", "two", "two_mutated", "three"])]
    rows += [dict(rows[0])]
    data = tmp_path / "input.jsonl"
    data.write_text("".join(json.dumps(r)+"\n" for r in rows), encoding="utf-8")
    report = prepare([str(data)], tmp_path / "out", ["two"], ["three"])
    assert all(o["normalized_texts"] == 0 for o in report["overlaps"])
    assert {family(r) for r in read_rows(tmp_path/"out"/"test.jsonl")} == {"two"}
    assert len(read_rows(tmp_path/"out"/"train.jsonl")) == 2
    assert all(r["label"] == "[MALICIOUS_TOOL_CALL]" for r in read_rows(data))


def test_missing_label_rejected(tmp_path):
    p = tmp_path / "invalid.jsonl"
    p.write_text(json.dumps({"text": "hello", "source": "unit-test"})+"\n", encoding="utf-8")
    with pytest.raises(ValueError): read_rows(p)

@pytest.mark.asyncio
async def test_benchmark_refuses_base_model(monkeypatch):
    import httpx
    from benchmarks.evaluation import verify_model
    async def get(*args, **kwargs):
        return httpx.Response(200, json={"neural_network_loaded": True, "lora_adapter": None},
                              request=httpx.Request("GET", "http://test/health"))
    monkeypatch.setattr(httpx.AsyncClient, "get", get)
    with pytest.raises(RuntimeError, match="adapter"):
        await verify_model()
