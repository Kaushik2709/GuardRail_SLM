"""Select existing legacy examples; this creates no new benchmark claims or labels."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.evaluation import read_rows
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("dataset")
    p.add_argument("output")
    a = p.parse_args()
    read_rows(a.dataset)  # Validate without changing the serialized original records.
    with open(a.dataset, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    chosen = []
    for label in sorted({r.get("category", r.get("label")) for r in rows}):
        chosen.extend([r for r in rows if r.get("category", r.get("label")) == label and len(r["text"].encode()) <= 1024][:8])
    Path(a.output).write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in chosen), encoding="utf-8")
    print(f"Selected {len(chosen)} legacy diagnostic rows; not a fresh held-out benchmark")
