"""Dataset-driven binary security evaluation. No fallback results are accepted."""
import argparse
import asyncio
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.cascade import SecurityCascadeEngine
from benchmarks.evaluation import read_rows, sha256, metrics, verify_model, predict, family

async def evaluate(args):
    rows = read_rows(args.dataset)
    modes = ["tier0", "tier1", "combined"] if args.mode == "all" else [args.mode]
    health = await verify_model() if any(m != "tier0" for m in modes) else None
    seen = set()
    if args.training_data:
        seen = {family(r) for r in read_rows(args.training_data)}
    report = {"dataset_sha256": sha256(args.dataset), "training_sha256": sha256(args.training_data) if args.training_data else None,
              "scope": "Dataset diagnostic; held-out validity requires training lineage verification",
              "model_health": health, "results": {}}
    for mode in modes:
        records = []
        engine = SecurityCascadeEngine()
        for row in rows:
            result = await predict(engine, row["text"], mode)
            records.append({"actual": row["label"] != "[SAFE]", "blocked": not result.is_safe,
                            "classification": result.classification.value, "category": row["label"],
                            "unseen": family(row) not in seen})
        report["results"][mode] = {"overall": metrics(records),
            "by_category": {c: metrics([r for r in records if r["category"] == c]) for c in sorted({r["category"] for r in records})},
            "unseen_source_families": metrics([r for r in records if r["unseen"]]) if args.training_data else None}
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--training-data")
    parser.add_argument("--mode", choices=["tier0", "tier1", "combined", "all"], default="all")
    parser.add_argument("--output")
    asyncio.run(evaluate(parser.parse_args()))
