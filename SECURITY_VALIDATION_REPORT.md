# Security and ML validation evidence

Audit date: 2026-10-11 (Asia/Calcutta). Local checkout of `Kaushik2709/GuardRail_SLM`; changes are uncommitted. README already had local edits before this audit; its integration examples were retained while unsupported claims were corrected.

## Confirmed correctness defects and changes

| Confirmed source behavior | Correction |
| --- | --- |
| Unknown/empty classifier labels authorized requests | Explicit ALLOW/BLOCK/INDETERMINATE; strict complete-label parsing; unknown outputs never set `is_safe=True`. |
| Non-200 classifier HTTP response fell through without a result | All non-200 responses produce a typed indeterminate result. |
| Offline heuristic fallback marked unmatched prompts safe | Removed fallback predictions; timeout/transport/JSON/schema/other failures remain indeterminate. Tier-0 still runs independently first. |
| Prompt prefilled `[` and stopped before `]`, while local server rewrapped partial output | Full assistant label generation, 32-token budget, matching stop semantics, exact whitelist and completion finish reason. This is generative multi-token classification, not a trained classification head. |
| Server converted empty generation into `[SAFE]` | Preserves empty output for rejection. Not-ready model returns 503; wrong requested model returns 400. |
| Adapter load failure silently served base model | Required adapter failure leaves model unready. Benchmarks also require loaded adapter identity. |
| Upstream failure returned mock 200 with a verified-safe response | Returns 502 for unavailable/invalid upstream response. Tests use explicit upstream stubs. |
| MCP inspected only top-level text in some output paths | Recursively checks structured/list/text outputs, redacts recognized secrets, blocks suspicious outputs; protected native non-text blocks are rejected. |
| Streaming egress checked individual transport chunks | Buffers SSE, reconstructs content/tool-argument fragments and scans before release. A prior unrelated heuristic match no longer hides a later credential. |
| Reserved security tool names implicitly bypassed custom-server middleware | Execution-server exemptions now default to empty; only the owned security-only server explicitly exempts its registered functions. |
| Prompt authorization cache bypassed fresh classifier checks | Removed cache and fabricated cache/empty-input timings. |
| Unsupported proxy content/legacy call shapes could be omitted from text inspection | Rejects unsupported content/tool shapes with 400; tool-role content and modern tool arguments are inspected. |
| Security metadata could echo full matched credentials/canaries | Redacts credential snippets and reports canary presence without its value. |
| Notebook ignored `category` and defaulted generated rows to SAFE | Strict category/label mapping, including TOOL_POISONING to MALICIOUS_TOOL_CALL; missing/conflicting labels fail. |
| Notebook silently expanded 10 seed examples into 5,000 rows; validation disabled | Missing data now fails; explicit separate validation required and epoch validation enabled. Overlength sequences fail before target-label truncation. |

All failure contexts default to denial. `GUARDRAIL_{TOOL,PROXY,PROMPT}_FAILURE_POLICY=allow` explicitly allows indeterminate outcomes in that context, sacrificing protection for availability; it does not change classification or override detected blocks. The compatibility `is_safe` boolean stays false for indeterminate results. MCP legacy SAFE/BLOCKED verdicts remain, alongside classification and policy decision fields. Healthy accepted labels carry no fabricated calibrated confidence.

## Dataset evidence

[Audit JSON](benchmarks/results/dataset_audit.json) records original input hashes and distributions. Actual local legacy counts are 25,500 train and 4,500 test (30,000 total), with 23 and 2 within-split normalized duplicate rows and five normalized texts shared across splits. All 11 collapsed source families occur in both. Builders augment before random row splitting, allowing related templates and base attacks to cross boundaries. No historical training log validates the approximately 29K training claim or proves these files trained the cached adapter.

The old notebook's 95/5 split would nominally yield 24,225 training / 1,275 validation examples from the legacy train file. Validation was not run by its trainer. Counts implied by code are not observed training counts. Silent SAFE labeling is confirmed in code; whether the cached adapter was trained by that exact code cannot be established from its artifact alone.

[Preparation methodology and source cards](benchmarks/README.md) document provenance, noisy label mappings, licensing/revision gaps and deterministic splitting. The new [split manifest](benchmarks/results/future_split_manifest.json) records 24,367 train / 2,162 validation / 3,441 test examples and zero normalized text overlap. SQL/deepset attack families are wholly test-held-out; Python tool family is validation-held-out. Benign content uses hash groups. These are future-training splits, not unseen data for the existing adapter. Test lacks some attack categories; cross-source semantic/template leakage still needs review. No new synthetic corpus was invented to match an accuracy claim.

## Security metrics

These are binary threat-positive detection metrics using existing corpus labels, not validated real-world attack-success rates. Precision can be undefined when nothing is blocked; JSON uses null, not a fabricated perfect score.

| Workload/configuration | N | TP / FP / TN / FN | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy full test, Tier-0 | 4,500 | 229 / 0 / 2,170 / 2,101 | 53.31% | 100% | 9.83% | 17.90% | 0% | 90.17% |
| Legacy diagnostic, Tier-0 | 40 | 0 / 0 / 8 / 32 | 20% | undefined | 0% | 0% | 0% | 100% |
| Same diagnostic, Tier-1 | 40 | 0 / 0 / 8 / 32 | 20% | undefined | 0% | 0% | 0% | 100% |
| Same diagnostic, combined | 40 | 0 / 0 / 8 / 32 | 20% | undefined | 0% | 0% | 0% | 100% |
| Future source-holdout test, Tier-0 | 3,441 | 469 / 0 / 1,454 / 1,518 | 55.88% | 100% | 23.60% | 38.19% | 0% | 76.40% |

Full legacy Tier-0 recall by category: direct injection 11/466 (2.36%), indirect 25/627 (3.99%), tool threats 193/579 (33.33%), PII 0/658. All 2,170 labeled benign examples passed. Arbitrary PII exceeds the credential regex scope. Results do not establish zero false positives outside this corpus.

The diagnostic selected eight existing rows per category, each <=1,024 UTF-8 bytes. The model emitted valid `[SAFE]` for all 40; all 32 labeled threats passed. Each threat category had 0/8 recall, with 8/8 benign allowed. This small, short-input, legacy subset is not representative and does not establish general model accuracy. It is nevertheless direct evidence of an unsafe adapter diagnostic. **98.2% accuracy was not reproduced and remains unverified.** Corrected training and independent validation are needed before this adapter should authorize sensitive actions.

The legacy corpus contains zero unseen source families relative to legacy training. Future-source-holdout Tier-0 recall is 469/1,987 (23.60%) on unseen SQL/deepset families relative to the proposed new train file. No newly trained model has been evaluated on that split. JSON reports contain confusion matrices and category/benign/unseen-source metrics: [legacy Tier-0](benchmarks/results/tier0_accuracy.json), [three-mode diagnostic](benchmarks/results/model_diagnostic_accuracy.json), [source holdout](benchmarks/results/tier0_source_holdout_accuracy.json).

## Actual inference performance

Hardware: Intel Core i5-12400 (6 cores / 12 logical CPUs), approximately 16 GiB RAM (16,936,767,488 usable bytes), Windows 11 with Docker Linux CPU serving, Intel UHD 730 unused. Model is CPU float32 with unmerged LoRA, batch size one, greedy generation up to 32 new tokens. Existing cached image/weights were used with downloads disabled; no AWQ/vLLM/GPU path was measured.

The server reported both model loaded and adapter identity; actual prediction tier counts were TIER_1_SLM on all 40 measured model requests. Adapter snapshot and SHA256, inference library versions and six torch threads are recorded in [deployment evidence](benchmarks/results/deployment_evidence.json). There are no fallback observations in model performance numbers. Model timeout was explicitly raised to 120 seconds for diagnostics, unlike the default 0.5-second failure threshold.

| Workload/configuration | Requests / concurrency / warmup | p50 ms | p95 ms | p99 ms |
| --- | --- | ---: | ---: | ---: |
| Full legacy test, Tier-0 | 4,500 / 1 / 100 | 0.0295 | 0.3720 | 1.2119 |
| 40-row diagnostic, Tier-0 | 40 / 1 / 5 | 0.0669 | 0.1699 | 0.2100 |
| Same diagnostic, Tier-1 | 40 / 1 / 5 | 994.72 | 1,231.31 | 1,380.72 |
| Same diagnostic, combined | 40 / 1 / 5 | 978.61 | 1,255.49 | 1,412.58 |
| Same diagnostic, Tier-1 | 40 / 4 / 5 | 2,464.59 | 3,240.54 | 3,404.77 |
| Same diagnostic, combined | 40 / 4 / 5 | 2,482.31 | 3,163.99 | 3,307.11 |

Diagnostic inputs were 50-994 UTF-8 bytes; the full Tier-0 workload ranged from 11-17,415 bytes. Measurement includes per-request classifier/client/server time after client admission, excludes upstream/audit, and records percentiles separately by configuration. The CPU server's synchronous generation serializes work; concurrency adds queueing. Forty requests give coarse p99 estimates and are not a saturation study. See [full Tier-0 latency](benchmarks/results/tier0_latency.json), [model concurrency one](benchmarks/results/model_diagnostic_latency.json), and [concurrency four](benchmarks/results/model_diagnostic_latency_c4.json).

**The sub-15ms full-model target was not achieved on this hardware.** Heuristic speed cannot be reported as inference speed. GPU/quantized serving is a future optimization needing its own deployment and benchmark; no hardware configuration that achieves the target was established.

## Verification and CI

- Offline suite: 73 tests passed on local Python 3.14.3. Covers malformed/empty/invalid/truncated labels, HTTP/transport/timeouts/exceptions, policy context, benign examples, no downstream execution on uncertainty, training category mapping, reserved-name bypass prevention, native MCP client paths, nested outputs, unsupported proxy paths and streaming canaries split across content/tool deltas.
- Opt-in live suite: 3 tests passed against the loaded adapter. Validated a real benign classification, native MCP benign/heuristic-blocked calls and proxy inspection with an explicitly synthetic upstream. No real destructive tools or external upstream calls were used.
- Python sources and notebook Python cells parse for Python 3.10 grammar; source compilation, workflow/Compose YAML parsing and `git diff --check` pass.
- Ordinary Actions CI is deterministic/offline. Optional workflow runs only on manual dispatch on a trusted `guardrail-model` runner, requiring a ready adapter and supplied dataset/hardware. No remote Actions run or new container build is claimed.
- The corrected notebook has not been GPU-trained. Dependency/training reproducibility still requires a pinned training environment and dataset revisions; installation currently resolves version ranges. FastAPI startup emits existing `on_event` deprecation warnings.

Reproduction commands are in [benchmarks/README.md](benchmarks/README.md). Set `GUARDRAIL_RUN_MODEL_TESTS=1` and a suitable `GUARDRAIL_SLM_TIMEOUT_SECONDS` to run `python -m pytest -m model -q` against a ready server. Without the opt-in variable those three tests skip.

## Remaining trust boundaries and limitations

This is a defense layer, not a sandbox or authorization system. Valid model labels can still be wrong, as this diagnostic shows. Regex/entropy can miss paraphrased, encoded, multilingual and multi-step attacks and can block benign quoted examples. SSRF signatures do not replace DNS-aware destination restrictions. Credential regexes are not general PII detection. Images/audio are unsupported and rejected by the proxy's text contract; native protected MCP non-text outputs are rejected. The standalone MCP server exposes security tools only; enforcement requires middleware attachment to the real execution server. Untrusted clients must not bypass the gateway or classifier server.

Proxy egress is pattern-based, not a semantic classifier. Buffered streaming increases memory and first-token delay; no stream-size limit, auth/TLS, rate limiting, production capacity or cryptographically tamper-evident logs were added. Local audit writes are synchronous, may contain non-secret security snippets and need protected retention. Gateway health is liveness/configuration only; inference readiness must be checked separately. Client authorization keys are not forwarded; upstream credentials are configured server-side.

Removed static test-count/performance badges, broken LICENSE/file links and invented comparative product results. Historical design notes are explicitly labeled as targets; implemented serving is CPU Transformers/LoRA, logging is local JSONL, and AST/tracing/AWQ claims are not implementation evidence. No LICENSE file was invented.

## Defensible resume bullets

- Hardened an LLM security gateway with explicit indeterminate classifications and configurable conservative enforcement across FastAPI proxy and MCP tool execution.
- Added recursive MCP output checks and streaming secret-boundary tests, validated by 73 offline tests and three opt-in integrations against a loaded LoRA classifier.
- Built dataset leakage audits and tier-separated evaluation workflows; identified cross-split duplicates, a training-label mapping defect and a classifier that missed every threat in a 40-example diagnostic.

Do not claim 98.2% accuracy, sub-15ms model latency, AWQ/vLLM optimization, production readiness or successful corrected-model training from this audit.
