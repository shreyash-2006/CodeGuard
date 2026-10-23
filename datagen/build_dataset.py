"""
datagen.build_dataset — generate train/val/test JSONL with a family split.

    python datagen/build_dataset.py

Fills template placeholders, applies mutators, and splits by `family_id`
(GroupShuffleSplit semantics: no family straddles train/test).

Output rows: {id, family_id, language, code, categories, malicious, source}
"""
from __future__ import annotations

import base64
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datagen.benign import BENIGN
from datagen.mutators import mutate
from datagen.templates import TEMPLATES

OUT_DIR = Path(__file__).parent / "out"
VARIANTS_PER_FAMILY = 14
SEED = 2026

_B64_CMD = base64.b64encode(b"import os; os.system('id')").decode()

POOLS: dict[str, list[str]] = {
    "path": ["~/.aws/credentials", "~/.ssh/id_rsa", ".env", "/etc/shadow", "~/.docker/config.json"],
    "credp": ["~/.ssh", "~/.aws", "~/.config"],
    "host": ["198.51.100.7", "203.0.113.9", "attacker.example", "c2.example.invalid"],
    "url": ["http://198.51.100.7/collect", "https://evil.example/upload", "http://attacker.example/x"],
    "ip": ["198.51.100.7", "203.0.113.9"],
    "var": ["data", "payload", "tmp", "stage", "result"],
    "pkg": ["requests", "flask", "numpy"],
    "cmd": ["id", "whoami", "uname -a"],
    "key": ["AKIAIOSFODNN7EXAMPLEKEY"],
    "token": ["xoxb-1234567890-abcdefghij"],
    "b64": [_B64_CMD],
    "b64dec": [_B64_CMD],
    "port": ["4444", "8080", "1337"],
    "decimal_ip": ["3232235521"],
    "userinfo": ["user:pass", "anything"],
    "typo": ["colourama", "reqeusts", "nympy", "djano", "flassk"],
    "typo_npm": ["lodahs", "expresss", "crossenv"],
}


def _fill(template: str, rng: random.Random) -> str | None:
    chosen = {k: rng.choice(v) for k, v in POOLS.items()}
    try:
        return template.format(**chosen)
    except Exception:
        return None


def build_records(seed: int = SEED, variants: int = VARIANTS_PER_FAMILY) -> list[dict]:
    rng = random.Random(seed)
    records: list[dict] = []

    # ── malicious families ───────────────────────────────────────────────────
    for category, families in TEMPLATES.items():
        for idx, entry in enumerate(families):
            language = entry[0]
            template = entry[1]
            extra = entry[2] if len(entry) > 2 and entry[2] else None
            family_id = f"{category}_{idx:03d}"
            cats = sorted({category, *(extra or [])})
            for v in range(variants):
                code = _fill(template, rng)
                if code is None:
                    continue
                if v > 0:
                    code = mutate(code, language, rng=rng, structural=False)
                records.append({
                    "id": f"{family_id}#{v}",
                    "family_id": family_id,
                    "language": language,
                    "code": code,
                    "categories": cats,
                    "malicious": 1,
                    "source": "template",
                })

    # ── benign families ─────────────────────────────────────────────────────
    for idx, (language, code) in enumerate(BENIGN):
        family_id = f"benign_{idx:03d}"
        for v in range(variants):
            c = code if v == 0 else mutate(code, language, rng=rng, structural=False)
            records.append({
                "id": f"{family_id}#{v}",
                "family_id": family_id,
                "language": language,
                "code": c,
                "categories": [],
                "malicious": 0,
                "source": "benign",
            })
    return records


def _primary_cat(rec: dict) -> str:
    return rec["categories"][0] if rec.get("categories") else "benign"


def _split(records: list[dict], seed: int = SEED):
    """Stratified-by-category family split: every category reaches val and test."""
    from collections import defaultdict

    fam_repr: dict[str, dict] = {}
    for r in records:
        fam_repr.setdefault(r["family_id"], r)

    groups: dict[str, list[str]] = defaultdict(list)
    for fam, r in fam_repr.items():
        groups[_primary_cat(r)].append(fam)

    rng = random.Random(seed + 1)
    train_f: set[str] = set()
    val_f: set[str] = set()
    test_f: set[str] = set()

    for _cat, fams in groups.items():
        fams = sorted(fams)
        rng.shuffle(fams)
        n = len(fams)
        if n <= 2:
            n_val, n_test = 0, 0
        else:
            n_val = max(1, round(n * 0.15))
            n_test = max(1, round(n * 0.15))
            while n_val + n_test >= n:
                if n_val >= n_test and n_val > 1:
                    n_val -= 1
                elif n_test > 1:
                    n_test -= 1
                else:
                    break
        test_f.update(fams[:n_test])
        val_f.update(fams[n_test:n_test + n_val])
        train_f.update(fams[n_test + n_val:])

    out = {"train": [], "val": [], "test": []}
    for r in records:
        f = r["family_id"]
        bucket = "train" if f in train_f else ("val" if f in val_f else "test")
        out[bucket].append(r)
    return out


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = build_records()
    splits = _split(records)

    for name, rows in splits.items():
        path = OUT_DIR / f"{name}.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def counts(rows, label):
        from collections import Counter
        c = Counter()
        for r in rows:
            for cat in r["categories"]:
                c[cat] += 1
        mal = sum(r["malicious"] for r in rows)
        return f"{label}: {len(rows)} rows ({mal} malicious, {len(rows)-mal} benign)"

    print("dataset built →", OUT_DIR)
    for name in ("train", "val", "test"):
        print(" ", counts(splits[name], name))

    # per-category totals (all splits)
    from collections import Counter
    per_cat = Counter()
    for r in records:
        for cat in r["categories"]:
            per_cat[cat] += 1
    print("\nper-category positive counts (all splits):")
    for cat, n in sorted(per_cat.items()):
        print(f"  {cat:<30s} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
