# Local evaluation inputs

No independent benchmark dataset was present in the original checkout. JSONL remains ignored by Git because source licenses and historical acquisition revisions are incomplete.

Supply provenance-reviewed data or reconstruct the local legacy diagnostic using `scripts/select_diagnostic.py`. Prepare future source-family holdouts with `scripts/prepare_evaluation.py`. See [methodology](../README.md) for exact commands, limitations and hashes. The legacy subset is not a new held-out dataset for the existing adapter.
