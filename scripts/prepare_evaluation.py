"""Audit legacy splits or prepare source-disjoint future training/evaluation splits."""
import argparse
import hashlib
from collections import Counter
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.evaluation import read_rows, normalize, family, sha256

def audit(paths):
    report = {"files": {}, "overlaps": []}
    texts = {}; families = {}
    for path in paths:
        rows = read_rows(path)
        counts = Counter(normalize(r["text"]) for r in rows)
        texts[path] = set(counts)
        families[path] = {family(r) for r in rows}
        report["files"][path] = {"rows": len(rows), "sha256": sha256(path),
            "normalized_duplicate_rows": sum(n-1 for n in counts.values()),
            "categories": dict(Counter(r["label"] for r in rows)),
            "source_families": dict(Counter(family(r) for r in rows))}
    for i, a in enumerate(paths):
        for b in paths[i+1:]:
            report["overlaps"].append({"files": [a,b], "normalized_texts": len(texts[a]&texts[b]),
                "shared_source_families": sorted(families[a]&families[b])})
    return report

def prepare(paths, out, test_families, validation_families):
    if set(test_families) & set(validation_families):
        raise ValueError("Validation and test source families overlap")
    rows = [r for p in paths for r in read_rows(p)]
    available = {family(r) for r in rows}
    if (set(test_families) | set(validation_families)) - available:
        raise ValueError("Unknown holdout family")
    splits = {"train": [], "validation": [], "test": []}
    seen = {}
    for row in rows:
        key = normalize(row["text"])
        if key in seen:
            if seen[key] != row["label"]:
                raise ValueError("Conflicting duplicate labels")
            continue
        seen[key] = row["label"]
        f = family(row)
        split = "test" if f in test_families else "validation" if f in validation_families else "train"
        if row["label"] == "[SAFE]":
            # Benign content groups use a stable hash; attack families remain source-held-out.
            bucket = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 10
            split = "test" if bucket == 0 else "validation" if bucket == 1 else "train"
        splits[split].append(row)
    if any(not rows for rows in splits.values()):
        raise ValueError("All three splits must be nonempty")
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    paths_out = []
    for name, rows in splits.items():
        path = out / f"{name}.jsonl"
        if path.exists():
            raise FileExistsError(path)
        path.write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in rows), encoding="utf-8")
        paths_out.append(str(path))
    report = audit(paths_out)
    report.update({"inputs": {p: sha256(p) for p in paths},
        "method": "Attack source-family holdout before future training; normalized deduplication; benign normalized-text SHA256 buckets 80/10/10; input order retained",
        "limitations": "Not held out from existing adapters. Source grouping cannot prove absence of semantic/template leakage across sources.",
        "test_families": test_families, "validation_families": validation_families})
    (out / "manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    return report

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("paths", nargs="+")
    p.add_argument("--out")
    p.add_argument("--test-family", action="append", default=[])
    p.add_argument("--validation-family", action="append", default=[])
    p.add_argument("--report")
    a = p.parse_args()
    report = prepare(a.paths, a.out, a.test_family, a.validation_family) if a.out else audit(a.paths)
    text = json.dumps(report, indent=2)+"\n"
    if a.report: Path(a.report).write_text(text, encoding="utf-8")
    print(text)
