#!/usr/bin/env python3
"""
Emit a fresh bench-baseline.json by reading the just-completed Criterion
run's estimates files and merging them into the schema of the committed
baseline file. Prints the new JSON to stdout, framed with BEGIN/END
markers so a maintainer can copy it out of a CI log without dragging in
surrounding log noise.

Intended caller: the workflow_dispatch-only `bench-baseline-regen` CI
job, which runs on the pinned runner class with longer measurement time
than the per-PR bench-regression job. Never run this on a developer
machine and commit the result - dev-box baselines defeat the gate
(developer hardware varies wildly from CI runners, so a dev-box number
either flakes the gate or has to be loosened into uselessness).

Inputs (all overridable via env for local-dev verification):
  BASELINE_FILE  path to the committed schema (default: ./bench-baseline.json)
  CRIT_DIR       path to target/criterion    (default: ./target/criterion)

Exit codes:
  0  emitted to stdout
  2  baseline schema or estimates inputs missing/malformed

Python 3.8+ only. Preinstalled on the ubuntu-24.04 runner image.
"""

import json
import os
import sys
from pathlib import Path


def die(msg: str) -> None:
    print(f"bench-emit-baseline: {msg}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    baseline_path = Path(os.environ.get("BASELINE_FILE", "bench-baseline.json"))
    crit_dir = Path(os.environ.get("CRIT_DIR", "target/criterion"))

    if not baseline_path.is_file():
        die(f"schema file not found: {baseline_path}")

    try:
        baseline = json.loads(baseline_path.read_text())
    except json.JSONDecodeError as e:
        die(f"schema file is not valid JSON: {e}")

    tracked = baseline.get("tracked_benches", [])
    if not tracked:
        die(f"no tracked benches in {baseline_path}")

    new_baselines = {}
    for entry in tracked:
        group = entry["group"]
        name = entry["name"]
        param = entry["param"]
        key = f"{group}/{name}/{param}"
        est_path = crit_dir / group / name / param / "new" / "estimates.json"
        if not est_path.is_file():
            die(f"estimates missing for {key} at {est_path}")
        try:
            estimates = json.loads(est_path.read_text())
            median_ns = float(estimates["median"]["point_estimate"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            die(f"estimates malformed for {key}: {e}")
        new_baselines[key] = median_ns

    out = dict(baseline)
    out["pending_first_ci_baseline"] = False
    out["baselines_ns"] = new_baselines
    out["_comment"] = (
        "Committed baseline for the engine scrub Criterion bench. Median "
        "ns/iter per tracked bench, captured by the workflow_dispatch-only "
        "bench-baseline-regen CI job on the runner class named below. The "
        "CI bench-regression job fails iff any measured median exceeds "
        "regression_factor times the matching baselines_ns entry. "
        "Regenerate via the runbook when the pinned runner class flips."
    )

    print("----- BEGIN bench-baseline.json -----")
    print(json.dumps(out, indent=2, sort_keys=False))
    print("----- END bench-baseline.json -----")
    return 0


if __name__ == "__main__":
    sys.exit(main())
