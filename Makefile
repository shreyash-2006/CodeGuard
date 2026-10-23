# CodeGuard — one-command checks
# Usage: make check

PY ?= python

.PHONY: check test selfcheck demo latency adversarial serve

check: test selfcheck demo latency
	@echo "== all checks passed =="

test:
	$(PY) -X utf8 tests/test_schema.py
	$(PY) -X utf8 tests/test_guard.py
	$(PY) -X utf8 tests/test_deobfuscate.py
	$(PY) -X utf8 tests/test_langid.py
	$(PY) -X utf8 tests/test_fusion.py
	$(PY) -X utf8 tests/test_markdown_yaml_lines.py
	$(PY) -X utf8 tests/test_csv.py
	$(PY) -X utf8 tests/regressions/test_known_fixes.py
	$(PY) -X utf8 tests/fuzz_test.py

dataset:
	$(PY) -X utf8 datagen/build_dataset.py

train: dataset
	$(PY) -X utf8 -m codeguard.ml.train --data datagen/out --out models

selfcheck:
	$(PY) -X utf8 scripts/selfcheck.py

demo:
	$(PY) -X utf8 demo/intercept_check.py

latency:
	$(PY) -X utf8 eval/latency.py

adversarial:
	$(PY) -X utf8 eval/adversarial.py

serve:
	$(PY) -m uvicorn codeguard.app:app --host 0.0.0.0 --port 8000 --workers 1
