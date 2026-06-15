#!/usr/bin/env python3
"""
Bench-regression tripwire. Reads the committed bench-baseline.json,
walks the per-bench Criterion estimates files, and fails iff any
tracked bench's measured median exceeds `regression_factor` times the
stored baseline.

Bootstrap: while the baseline file carries `pending_first_ci_baseline:
true`, the tripwire prints the informational table and exits clean.
That state is expected on the very first run of this script in CI, and
stays in effect until the workflow_dispatch baseline-regen job has
produced a real baseline and that file has been committed.

Inputs (all overridable via env for local-dev runs):
  BASELINE_FILE  path to bench-baseline.json (default: ./bench-baseline.json)
  CRIT_DIR       path to target/criterion    (default: ./target/criterion)

Exit codes:
  0  pass (or informational mode while baseline is pending)
  1  at least one tracked bench regressed past the configured factor
  2  baseline file missing or malformed
  3  bench output missing for a tracked bench (likely the bench did not run)

Python 3.8+ only. Preinstalled on the ubuntu-24.04 runner image and on
every supported developer OS, so no extra system deps are introduced.
"""

import json
import os
import sys
from pathlib import Path


def die(code: int, msg: str) -> None:
    print(f"bench-regression: {msg}", file=sys.stderr)
    sys.exit(code)


def main() -> int:
    baseline_path = Path(os.environ.get("BASELINE_FILE", "bench-baseline.json"))
    crit_dir = Path(os.environ.get("CRIT_DIR", "target/criterion"))

    if not baseline_path.is_file():
        die(2, f"baseline file not found: {baseline_path}")

    try:
        baseline = json.loads(baseline_path.read_text())
    except json.JSONDecodeError as e:
        die(2, f"baseline file is not valid JSON: {e}")

    factor = float(baseline.get("regression_factor", 2.0))
    runner = baseline.get("runner_class", "(unspecified)")
    tracked = baseline.get("tracked_benches", [])
    pending = bool(baseline.get("pending_first_ci_baseline", False))
    baselines_ns = baseline.get("baselines_ns", {})

    if not tracked:
        die(2, f"no tracked benches in {baseline_path}")

    rows = []
    measured_misses = []
    baseline_misses = []
    overall_pass = True

    for entry in tracked:
        group = entry["group"]
        name = entry["name"]
        param = entry["param"]
        key = f"{group}/{name}/{param}"
        est_path = crit_dir / group / name / param / "new" / "estimates.json"

        if not est_path.is_file():
            measured_misses.append((key, est_path))
            continue

        try:
            estimates = json.loads(est_path.read_text())
            measured = float(estimates["median"]["point_estimate"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            die(2, f"estimates malformed for {key}: {e}")

        if pending:
            rows.append((key, measured, None, None, "informational"))
            continue

        base = baselines_ns.get(key)
        if base is None:
            baseline_misses.append(key)
            rows.append((key, measured, None, None, "FAIL (baseline missing)"))
            overall_pass = False
            continue

        base = float(base)
        ratio = measured / base if base > 0 else float("inf")
        if ratio > factor:
            overall_pass = False
            verdict = "REGRESSED"
        else:
            verdict = "ok"
        rows.append((key, measured, base, ratio, verdict))

    # Print header + table.
    print()
    header = f'{"bench":<50} {"measured (ns)":>18} {"baseline (ns)":>18} {"ratio":>8}  verdict'
    print(header)
    print("-" * len(header))
    for key, measured, base, ratio, verdict in rows:
        measured_s = f"{measured:>18.1f}"
        if base is None:
            base_s = f"{'(pending)':>18}" if pending else f"{'(missing)':>18}"
            ratio_s = f"{'—':>8}"
        else:
            base_s = f"{base:>18.1f}"
            ratio_s = f"{ratio:>7.2f}x"
        print(f"{key:<50} {measured_s} {base_s} {ratio_s}  {verdict}")

    print()
    print(f"runner class: {runner}   regression factor: {factor}x")

    if measured_misses:
        for key, est_path in measured_misses:
            print(
                f"bench-regression: estimates file missing for {key}\n"
                f"  expected at: {est_path}\n"
                f"  did the bench actually run? confirm the bench name in benches/scrub.rs"
                f" matches the (group, name, param) entry in {baseline_path}.",
                file=sys.stderr,
            )
        return 3

    if pending:
        print(
            "BASELINE STATE: pending — first CI baseline has not been committed yet.\n"
            "Tripwire skipped. The numbers above are informational only.\n\n"
            "To set the baseline:\n"
            '  1. Trigger the "bench baseline regen" workflow (workflow_dispatch).\n'
            "  2. Copy the JSON block printed in that job's log over the committed\n"
            "     bench-baseline.json (or apply it via PR per docs/RUNBOOK_baseline_refresh.md).\n"
            f"  3. The next CI run on this branch will start enforcing the {factor}x tripwire."
        )
        return 0

    if overall_pass:
        print(f"RESULT: PASS — all tracked benches within {factor}x of baseline.")
        return 0

    print(
        f"RESULT: FAIL — at least one bench regressed past {factor}x baseline.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
