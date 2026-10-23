"""
engine.py — Top-level CodeGuard analysis engine.

Orchestrates: preprocess → langid → segment → deobfuscate → parse → detectors
              → (ML per policy) → fusion → explain → finalize.

Guarantees:
  * analyze() never raises and always returns a valid response.
  * The pipeline runs inside a worker thread with a hard HARD_TIMEOUT_S timeout;
    a timeout or any exception yields a fail-closed BLOCK response.
  * A missing/corrupt ML model degrades to rules-only (never crashes).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from time import perf_counter
from typing import Any

from codeguard import config
from codeguard.detectors import Context, run_all_detectors
from codeguard.fusion import decide, fuse, thresholds_used
from codeguard.ml_model import MLModel
from codeguard.pipeline.deobfuscate import deobfuscate_layers, describe_layers
from codeguard.pipeline.langid import detect_language_scored
from codeguard.pipeline.parse import parse_all
from codeguard.pipeline.preprocess import preprocess
from codeguard.pipeline.segment import segment
from codeguard.schema import empty_input, fail_closed, finalize_response

# ── Worker pool for the hard timeout ─────────────────────────────────────────
_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="codeguard")


def _base_diag(timings: dict[str, float]) -> dict[str, Any]:
    return {
        "category_scores": {},
        "evidence": [],
        "deobfuscation_layers": 0,
        "deobfuscation": "",
        "ml_probs": {},
        "ml_ran": False,
        "language_confidence": 0.0,
        "timings_ms": {k: round(v, 3) for k, v in timings.items()},
        "thresholds_used": thresholds_used(),
    }


def _analyze_core(code: Any, model: MLModel | None) -> tuple[dict[str, Any], dict[str, Any]]:
    timings: dict[str, float] = {}

    def _lap(name: str, start: float) -> float:
        now = perf_counter()
        timings[f"{name}_ms"] = (now - start) * 1000.0
        return now

    if not isinstance(code, str):
        try:
            code = str(code)
        except Exception:
            code = ""

    # ── Preprocess ────────────────────────────────────────────────────────────
    t = perf_counter()
    norm, meta = preprocess(code)
    total_lines = max(1, len(norm.splitlines()))
    _lap("preprocess", t)

    if not norm.strip():
        return empty_input(), _base_diag(timings)

    # ── Language detection ────────────────────────────────────────────────────
    t = perf_counter()
    lang, lang_conf = detect_language_scored(norm)
    _lap("langid", t)

    # ── Segmentation ──────────────────────────────────────────────────────────
    t = perf_counter()
    segments = segment(norm, lang) if config.ENABLE_SEGMENTATION else []
    _lap("segment", t)

    # ── Deobfuscation ─────────────────────────────────────────────────────────
    t = perf_counter()
    if config.ENABLE_DEOBFUSCATION and len(norm) <= 65536:
        layers = deobfuscate_layers(norm)
        deob = layers[-1].text
    else:
        layers = []
        deob = norm
    _lap("deobfuscate", t)

    # ── Parsing ───────────────────────────────────────────────────────────────
    t = perf_counter()
    parsed = parse_all(norm, lang) if config.ENABLE_PARSING else {}
    _lap("parse", t)

    # ── Detectors ─────────────────────────────────────────────────────────────
    t = perf_counter()
    ctx = Context(code=norm, deob_code=deob, language=lang, segments=segments,
                  parsed=parsed, layers=layers, meta=meta)
    evidence, dampers = run_all_detectors(ctx)
    _lap("detectors", t)

    # ── ML per policy ─────────────────────────────────────────────────────────
    ml_proba: dict[str, float] = {}
    ml_ran = False
    decisive = any(
        getattr(ev, "hard_block", False) or ev.confidence >= config.DECISIVE_CONFIDENCE
        for ev in evidence
    )
    model_ready = model is not None and getattr(model, "_ready", False)
    run_ml = (
        config.ENABLE_ML
        and model_ready
        and (
            config.ML_POLICY == "always"
            or (config.ML_POLICY == "early_exit" and not decisive)
            or (config.ML_POLICY == "on_no_evidence" and not evidence)
        )
    )
    if run_ml:
        t = perf_counter()
        try:
            ml_proba = model.predict_proba(deob)
            ml_ran = True
        except Exception:
            ml_proba = {}
        _lap("ml", t)

    # ── Fusion + decision ─────────────────────────────────────────────────────
    t = perf_counter()
    fused = fuse(evidence, ml_proba, dampers)
    _lap("fusion", t)

    t = perf_counter()
    ml_max = max(ml_proba.values(), default=0.0)
    obf_summary = describe_layers(layers) if layers else ""
    categories, risk, vuln, reason = decide(fused, evidence, lang=lang, ml_max=ml_max,
                                            obfuscation=obf_summary)
    _lap("explain", t)

    response = finalize_response(
        verdict="block" if categories else "allow",
        risk_score=risk,
        categories=categories,
        code_language=lang,
        reason=reason,
        vulnerable_lines=vuln,
        total_lines=total_lines,
    )

    diag = {
        "category_scores": {k: round(v, 4) for k, v in fused.items()},
        "evidence": [ev.as_dict() for ev in evidence],
        "deobfuscation_layers": max(0, len(layers) - 1),
        "deobfuscation": describe_layers(layers) if layers else "",
        "ml_probs": {k: round(v, 4) for k, v in ml_proba.items()},
        "ml_ran": ml_ran,
        "language_confidence": lang_conf,
        "timings_ms": {k: round(v, 3) for k, v in timings.items()},
        "thresholds_used": thresholds_used(),
    }
    return response, diag


def _run_with_timeout(fn, *args):
    future = _EXECUTOR.submit(fn, *args)
    return future.result(timeout=config.HARD_TIMEOUT_S)


def analyze(code: Any, model: MLModel | None = None) -> dict[str, Any]:
    """Full analysis pipeline. Always returns a valid schema dict. Never raises."""
    try:
        response, _ = _run_with_timeout(_analyze_core, code, model)
        return response
    except FuturesTimeoutError:
        return fail_closed("Analysis timed out; failing closed.")
    except Exception as exc:
        return fail_closed(f"Analysis error (fail-closed): {str(exc)[:200]}")


def analyze_detailed(code: Any, model: MLModel | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Same as analyze() but also returns diagnostics. Never raises."""
    try:
        return _run_with_timeout(_analyze_core, code, model)
    except FuturesTimeoutError:
        return fail_closed("Analysis timed out; failing closed."), {"error": "timeout"}
    except Exception as exc:
        return fail_closed(f"Analysis error (fail-closed): {str(exc)[:200]}"), {"error": str(exc)[:200]}
