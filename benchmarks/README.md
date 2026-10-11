# Evaluation methodology and provenance

Local `data/processed` artifacts were already present; original downloads have no pinned source revisions/license snapshots. Source cards confirm dataset identities, not which historical revision trained the adapter. Review source and underlying data terms before redistributing this mixed corpus.

| Source in assembly scripts | Use and limitations |
| --- | --- |
| [TrustAIRLab](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | Two dated jailbreak configurations; augmentation shares base attacks. |
| [deepset](https://huggingface.co/datasets/deepset/prompt-injections) | Injection-labeled training rows; card declares Apache-2.0. |
| [JailbreakBench mirror](https://huggingface.co/datasets/walledai/JailbreakBench) | Harmful subset mapped to injection; harmful requests are not necessarily injection. |
| [Community jailbreaks](https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts) | Community prompts; historical revision/lineage unrecorded. |
| [ai4privacy](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) | All selected source text labeled PII leak; includes personal data beyond credential regex scope. |
| [Alpaca cleaned](https://huggingface.co/datasets/yahma/alpaca-cleaned) | Instruction text assumed benign without human security relabeling. |
| Repository tool/RAG generators | Synthetic templates, wrappers and mutations, not independent attacks. |

Labels need manual review. Acquisition scripts catch download failures: target counts are not actual counts. Generators now write an unsplit `guardrail_corpus.jsonl` instead of random row splits after augmentation. No generated examples are represented as independent ML evidence.

## Audit legacy data

```bash
python scripts/prepare_evaluation.py data/processed/guardrail_train.jsonl data/processed/guardrail_test.jsonl --report benchmarks/results/dataset_audit.json
python benchmarks/benchmark_accuracy.py --dataset data/processed/guardrail_test.jsonl --training-data data/processed/guardrail_train.jsonl --mode tier0 --output benchmarks/results/tier0_accuracy.json
```

Legacy counts: 25,500 train / 4,500 test, 23/2 normalized duplicate rows within splits and five normalized texts crossing splits. All 11 collapsed source families cross the boundary. Synthetic base/mutated tools and augmented jailbreak/RAG templates share families. Legacy test is a diagnostic, not a clean unseen-family test. No validation artifact or training log proves historical training counts. The old notebook's further 95/5 split nominally gives 24,225 train / 1,275 validation, but validation was disabled. Those are code-derived counts, not evidence of a completed run.

## Prepare future held-out splits

```bash
python scripts/prepare_evaluation.py data/processed/guardrail_train.jsonl data/processed/guardrail_test.jsonl --out data/evaluation_v1 --test-family synthetic/sql_tool_poisoning --test-family deepset/prompt-injections --validation-family synthetic/python_tool_poisoning --report benchmarks/results/future_split_manifest.json
python benchmarks/benchmark_accuracy.py --dataset data/evaluation_v1/test.jsonl --training-data data/evaluation_v1/train.jsonl --mode tier0 --output benchmarks/results/tier0_source_holdout_accuracy.json
```

Use a fresh output directory. Normalize by casefolding and collapsing whitespace. Remove duplicate texts globally; conflicting labels abort. Collapse `_augmented`/`_mutated` sources to parents; all synthetic RAG templates form one family. Selected attack families go wholly to validation/test. Benign normalized text uses SHA256 modulo 10 (0=test, 1=validation, otherwise=train). Recorded inputs yield 24,367 train / 2,162 validation / 3,441 test rows, with zero normalized overlap. Test includes SQL, deepset and benign examples, not every category; rotate family selections for broader coverage. Source grouping does not prove absence of semantic/template overlap across sources.

These are held out only for **future training using the new train file**, not for existing adapters. Do not retrain on validation/test. Record reviewed labels, immutable acquisition revisions, licenses, generator commit, manifest and adapter hash before claiming trained-model held-out scores. Committed metrics/manifests contain hashes/counts, not corpus text.

## Real model diagnostics and latency

```bash
python scripts/select_diagnostic.py data/processed/guardrail_test.jsonl benchmarks/eval_datasets/legacy_diagnostic_40.jsonl
# Set GUARDRAIL_SLM_TIMEOUT_SECONDS=120 in your shell for CPU diagnostics.
python benchmarks/benchmark_accuracy.py --dataset benchmarks/eval_datasets/legacy_diagnostic_40.jsonl --training-data data/processed/guardrail_train.jsonl --mode all --output benchmarks/results/model_diagnostic_accuracy.json
python benchmarks/benchmark_latency.py --dataset benchmarks/eval_datasets/legacy_diagnostic_40.jsonl --mode all --hardware "Declare CPU GPU RAM dtype and serving setup" --requests 40 --concurrency 1 --warmup 5 --output benchmarks/results/model_diagnostic_latency.json
python benchmarks/benchmark_latency.py --dataset data/processed/guardrail_test.jsonl --mode tier0 --hardware "Declare CPU and RAM" --requests 4500 --concurrency 1 --warmup 100 --output benchmarks/results/tier0_latency.json
```

The selector takes the first eight existing examples per category with text <=1,024 UTF-8 bytes. It retains source text/labels, creates no new examples, favors shorter prompts and is not representative. JSONL is ignored by Git; reconstruct from matching input artifacts. Undefined rates are JSON null. Metrics include threat-positive precision, recall, F1, FPR, FNR, confusion matrix, category and benign results. Unseen-source metrics compare against a supplied training file, not undocumented adapter history.

Model modes require health identifying a loaded model and adapter, then valid labels for every actual inference. Missing adapters, timeouts or indeterminate responses invalidate the run: no fallback model scores are published. Tier modes explicitly select paths independent of deployment flags; combined short-circuits heuristic blocks. Compare modes on the same dataset; full legacy Tier-0 and 40-row model scores are different workloads.

Latency is per-request wall time after semaphore admission, including SLM HTTP/client overhead and server queueing, excluding upstream/audit. Batch size is one, greedy generation uses up to 32 tokens. Hardware/runtime, input byte ranges, concurrency, warmup, tiers and interpolated p50/p95/p99 accompany results. Synchronous Tier-0 asyncio concurrency is not CPU parallelism. Forty samples give coarse tails; use larger runs and concurrency sweeps for capacity claims. Notebook smoke timing is not a benchmark. No external product cost/VRAM/timing comparison was measured.

Training uses TRL's documented `max_length` field. The formatter rejects sequences longer than 1,024 tokens rather than silently truncating the target label. Review the context/memory policy explicitly if this stops a training run. [TRL SFT documentation](https://huggingface.co/docs/trl/sft_trainer) describes sequence truncation and evaluation APIs. The corrected notebook has syntax validation only, not a completed GPU training run.
