"""Wall-clock latency by explicit tier mode; model failures invalidate a run."""
import argparse
import asyncio
from collections import Counter
import json
import os
import platform
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.cascade import SecurityCascadeEngine
from benchmarks.evaluation import predict, read_rows, sha256, verify_model

def percentile(values, p):
    values = sorted(values)
    position = (len(values)-1)*p
    low = int(position); high = min(low+1, len(values)-1)
    return values[low] + (values[high]-values[low])*(position-low)

async def benchmark(args):
    if args.requests < 1 or args.concurrency < 1 or args.warmup < 0:
        raise ValueError("Invalid benchmark parameters")
    rows = read_rows(args.dataset)
    modes = ["tier0", "tier1", "combined"] if args.mode == "all" else [args.mode]
    health = await verify_model() if any(m != "tier0" for m in modes) else None
    report = {"hardware": args.hardware, "platform": platform.platform(), "python": platform.python_version(),
        "cpu": platform.processor(), "logical_cpus": os.cpu_count(), "model_health": health,
        "dataset_sha256": sha256(args.dataset), "requests": args.requests, "concurrency": args.concurrency,
        "batch_size": 1, "warmup": args.warmup,
        "request_utf8_bytes": {"min": min(len(r["text"].encode()) for r in rows),
                               "max": max(len(r["text"].encode()) for r in rows)},
        "generation": {"max_tokens": 32, "temperature": 0.0},
        "timing": "Per-request wall time after concurrency admission; includes HTTP/client overhead for SLM; excludes audit/upstream",
        "results": {}}
    for mode in modes:
        engine = SecurityCascadeEngine()
        for i in range(args.warmup):
            await predict(engine, rows[i % len(rows)]["text"], mode)
        latencies = []; tiers = Counter(); sem = asyncio.Semaphore(args.concurrency)
        async def run(i):
            async with sem:
                start = time.perf_counter()
                result = await predict(engine, rows[i % len(rows)]["text"], mode)
                latencies.append((time.perf_counter()-start)*1000)
                tiers[result.tier] += 1
        start = time.perf_counter()
        await asyncio.gather(*(run(i) for i in range(args.requests)))
        elapsed = time.perf_counter()-start
        report["results"][mode] = {"p50_ms": percentile(latencies, .5), "p95_ms": percentile(latencies, .95),
            "p99_ms": percentile(latencies, .99), "requests_per_second": args.requests/elapsed, "tiers": dict(tiers)}
    text = json.dumps(report, indent=2)
    if args.output: Path(args.output).write_text(text+"\n", encoding="utf-8")
    print(text)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True)
    p.add_argument("--mode", choices=["tier0", "tier1", "combined", "all"], default="all")
    p.add_argument("--hardware", required=True, help="Declared CPU/GPU/RAM deployment description")
    p.add_argument("--requests", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--warmup", type=int, default=10)
    p.add_argument("--output")
    asyncio.run(benchmark(p.parse_args()))
