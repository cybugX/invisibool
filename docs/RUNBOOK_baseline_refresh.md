# Runbook: refresh the bench baseline

This runbook covers `bench-baseline.json` - the file the CI
`bench-regression` job compares each PR's measured Criterion medians
against. The bench-regression job fails iff a tracked bench's measured
median exceeds `regression_factor` (default `2.0`) times the matching
entry in `baselines_ns`.

## When to refresh

Refresh the baseline when one of the following is true. Do **not**
refresh as a routine activity - every refresh ratchets the gate's
sensitivity and a casual refresh hides a real regression.

1. **Runner-class deprecation.** GitHub announces deprecation of
   `ubuntu-24.04` (the value of `runner_class` in `bench-baseline.json`)
   and we move to a successor image. The new runner's CPU + scheduler
   profile is different, so the existing baseline is no longer the same
   measurement.
2. **Bench corpus change.** Someone edits the deterministic generator
   (`crates/invisibool-engine/examples/gen_bench_fixtures.rs`) and the
   committed fixture bytes change. The latency numbers depend on the
   exact input bytes, so any fixture edit and its baseline refresh
   travel together in the same PR.
3. **Deliberate engine speedup.** A merged change makes the engine
   meaningfully faster and you want the gate to start protecting the
   new floor. Confirm in review that the speedup is real and intended
   (not a measurement artefact) before refreshing.

## How to refresh

The refresh is a CI-only operation. Do not run `cargo bench` on a
developer machine and commit the resulting numbers - developer
hardware varies wildly from CI runners, so a dev-box baseline either
flakes the gate immediately or has to be loosened into uselessness.

1. **Trigger the regen workflow.** In the GitHub Actions UI, open the
   `CI` workflow and choose **Run workflow** on the branch the
   refresh should baseline. The `bench-baseline-regen` job runs only on
   this manual dispatch event; the per-PR jobs run too but are
   unaffected.
2. **Wait for the regen job to finish.** It runs the engine scrub
   bench with a longer measurement window than the per-PR job (15 s vs.
   5 s) so the medians it captures are tight enough to use as a
   baseline. Expect a few minutes wall-clock.
3. **Copy the JSON.** Open the regen job's log and find the step
   titled **Emit new baseline JSON**. It prints the new file framed
   like this:

       ----- BEGIN bench-baseline.json -----
       {
         "_comment": "...",
         "pending_first_ci_baseline": false,
         ...
         "baselines_ns": {
           "engine_scrub/prose_2kb_three_secrets/2048": 26012.4,
           ...
         }
       }
       ----- END bench-baseline.json -----

   Copy everything between (but not including) the marker lines.
4. **Open a PR.** Replace `bench-baseline.json` at the repo root with
   the copied JSON, commit, and open a pull request. The PR description
   should state which of the three refresh triggers above applies and
   include a diff of the old vs. new `baselines_ns` numbers - orders of
   magnitude apart between old and new means something is wrong (wrong
   runner class, wrong bench, wrong corpus); a few percent or low tens
   of percent is normal for a runner-class flip.
5. **Verify the diff sanity-checks.** Read the per-bench diff:
   - `engine_scrub/prose_2kb_three_secrets/2048` - the
     latency-critical case; the new median should still be well inside
     the project's per-call goal of p50 < 1 ms.
   - `engine_scrub/source_64kb_no_secrets/65536` - no-match fast path
     at moderate size; should be a small handful of microseconds.
   - `engine_scrub/log_1mb_no_secrets/1048576` - no-match path
     scaled; should be tens of microseconds, scaling roughly linearly
     with size from the 64 KB case.

   If any new number is outside its rough range, do not merge - the
   regen run was disturbed (a noisy neighbour on the shared runner is
   the most common cause). Re-run the dispatch and use the second
   run's JSON.
6. **Merge.** Once the PR is reviewed and merged, the next per-PR run
   of `bench-regression` will compare measurements against the new
   baselines and start failing on regressions past `regression_factor`.

## Bootstrap state

On a fresh repo, `bench-baseline.json` ships with
`pending_first_ci_baseline: true` and an empty `baselines_ns`. While
that flag is true, `bench-regression.py` prints the per-PR informational
table and exits zero - no tripwire fires. The first refresh per the
steps above flips the flag to `false` and populates `baselines_ns`,
which is when the gate goes live.
