# Interception-Proof Demo

**Deliverable:** prove that a `block` verdict actually prevents execution, with an
observable side effect.

**Script:** [`demo/intercept_check.py`](../demo/intercept_check.py) (repo root)
**Evidence:** [`evidence_interception.txt`](evidence_interception.txt)

```bash
python demo/intercept_check.py      # exits 0 only if every assertion holds
```

## What it proves

The demo creates a temporary marker file path and drives four scenarios through
the same guard (`check()` → `block` raises `BlockedByCodeGuard`; `allow` runs a
subprocess):

| # | Scenario | Assertion |
|---|---|---|
| 1 | **Malicious** snippet (fake AWS keys + POST to a TEST-NET endpoint) | verdict is `block`; the process is **never launched**; the marker file is **not** created |
| 2 | **Safe** snippet (writes a timestamped marker) | verdict is `allow`; the marker file **is** created (proves allowed code really runs) |
| 3 | **Fail-closed** — the analyzer is made to raise | result is still a valid `block` (`risk_score ≥ 0.5`), so execution is refused |
| 4 | **Schema validation** on garbage inputs (empty, `None`, binary, huge, int, list) | every response is a valid schema object |

Captured run (abridged):

```
══ Scenario 1: MALICIOUS snippet (must be blocked) ══
  [guard] BLOCKED (malicious)
    risk_score : 0.9899
    categories : ['secret_access', 'ssrf_network_exfil']
  ✓ malicious snippet was blocked
  ✓ marker file was NOT created          ← blocked code never executed
══ Scenario 2: SAFE snippet (must be allowed) ══
  ✓ safe snippet was allowed
  ✓ marker file created: …\codeguard_demo_safe_marker.txt   ← allowed code executed
══ Scenario 3: FAIL-CLOSED path ══
  ✓ fail-closed path returned block
══ Scenario 4: SCHEMA VALIDATION on garbage inputs ══
  ✓ (6/6 inputs) → valid allow responses
  ALL SCENARIOS PASSED ✓
```

## How interception works in the product

`codeguard/guard.py` performs the check **synchronously before** any runner is
invoked:

```python
from codeguard.guard import check, guarded, safe_exec, BlockedByCodeGuard

check(code)            # -> dict, never raises (fail-closed on error/timeout)
safe_exec(code)        # runs the runner ONLY after an `allow` verdict

@guarded               # decorator: fn(code) runs only if CodeGuard allows it
def run(code): ...
```

* `block` → `BlockedByCodeGuard` is raised; the runner is never called.
* Any guard error or timeout → `BlockedByCodeGuard` (fail-closed).
* `safe_exec(..., mode="http")` can check against the live `/check` endpoint.

The same guarantee applies to the HTTP surface: the organizer's harness decides
whether to execute based on the returned `verdict`; CodeGuard supplies a valid,
fail-closed verdict for **every** input, including malformed ones.
