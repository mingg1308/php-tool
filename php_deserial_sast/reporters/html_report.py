"""
Interactive, standalone HTML Report Generator with modern glassmorphism UI.
"""

import json
from php_deserial_sast.models import ScanResult


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Deserialization SAST Security Audit Report</title>
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: rgba(23, 32, 54, 0.7);
            --bg-card-hover: rgba(30, 41, 69, 0.85);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-dim: #9ca3af;
            --primary: #6366f1;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #06b6d4;
            --info: #3b82f6;
            --success: #10b981;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            line-height: 1.6;
            padding: 2rem;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }

        .header-title h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a855f7, #6366f1, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            color: var(--text-dim);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: var(--primary);
        }

        .metric-num {
            font-size: 2.2rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }

        .metric-label {
            color: var(--text-dim);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .critical-text { color: var(--critical); }
        .high-text { color: var(--high); }
        .medium-text { color: var(--medium); }
        .chains-text { color: #c084fc; }

        .toolbar {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .search-input {
            flex: 1;
            min-width: 260px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            color: var(--text-main);
            outline: none;
            font-size: 0.95rem;
        }

        .search-input:focus {
            border-color: var(--primary);
        }

        .filter-btn {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-dim);
            padding: 0.75rem 1.25rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
        }

        .filter-btn.active, .filter-btn:hover {
            background: var(--primary);
            color: #fff;
            border-color: var(--primary);
        }

        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        .finding-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25);
            transition: border-color 0.2s ease;
        }

        .finding-card.severity-CRITICAL { border-left: 4px solid var(--critical); }
        .finding-card.severity-HIGH { border-left: 4px solid var(--high); }
        .finding-card.severity-MEDIUM { border-left: 4px solid var(--medium); }
        .finding-card.severity-LOW { border-left: 4px solid var(--low); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.75rem;
        }

        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
        }

        .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .badge-LOW { background: rgba(6, 182, 212, 0.2); color: var(--low); border: 1px solid var(--low); }

        .finding-title {
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 0.4rem;
        }

        .finding-meta {
            font-size: 0.85rem;
            color: var(--text-dim);
            margin-bottom: 1rem;
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
        }

        .code-block {
            background: #050811;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 1rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.88rem;
            overflow-x: auto;
            color: #e5e7eb;
            margin: 0.75rem 0;
            white-space: pre-wrap;
        }

        .trace-box {
            background: rgba(99, 102, 241, 0.05);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }

        .trace-step {
            padding: 0.4rem 0;
            border-bottom: 1px dashed rgba(255,255,255,0.08);
            font-size: 0.88rem;
        }

        .trace-step:last-child {
            border-bottom: none;
        }

        .remediation-box {
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-size: 0.9rem;
        }

        .remediation-box h4 {
            color: var(--success);
            margin-bottom: 0.4rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>PHP Insecure Deserialization SAST Report</h1>
                <p>Target: <strong>{{ target_path }}</strong> • Scanned {{ summary.total_files_scanned }} files in {{ summary.scan_duration_seconds }}s</p>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-num">{{ summary.total_findings }}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-num critical-text">{{ summary.critical_count }}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-num high-text">{{ summary.high_count }}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric-card">
                <div class="metric-num medium-text">{{ summary.medium_count }}</div>
                <div class="metric-label">Medium</div>
            </div>
            <div class="metric-card">
                <div class="metric-num chains-text">{{ summary.gadget_chains_found }}</div>
                <div class="metric-label">POP Gadget Chains</div>
            </div>
        </div>

        <div class="toolbar">
            <input type="text" id="searchInput" class="search-input" placeholder="Search findings by title, file, or rule ID..." onkeyup="filterFindings()">
            <button class="filter-btn active" onclick="setFilter('ALL')">All</button>
            <button class="filter-btn" onclick="setFilter('CRITICAL')">Critical</button>
            <button class="filter-btn" onclick="setFilter('HIGH')">High</button>
            <button class="filter-btn" onclick="setFilter('MEDIUM')">Medium</button>
            <button class="filter-btn" onclick="setFilter('POP')">POP Chains</button>
        </div>

        <div class="findings-list" id="findingsList">
            {% for f in findings %}
            <div class="finding-card severity-{{ f.severity.value }}" data-severity="{{ f.severity.value }}" data-type="{{ f.vuln_type.value }}" data-text="{{ f.title }} {{ f.location.file_path }} {{ f.rule_id }}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{{ f.title }}</div>
                        <div class="finding-meta">
                            <span><strong>Location:</strong> {{ f.location.file_path }}:{{ f.location.start_line }}</span>
                            <span><strong>Rule:</strong> {{ f.rule_id }}</span>
                            <span><strong>CWE:</strong> {{ f.cwe }}</span>
                        </div>
                    </div>
                    <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
                </div>
                <p>{{ f.description }}</p>

                {% if f.code_snippet %}
                <div class="code-block">{{ f.code_snippet }}</div>
                {% endif %}

                {% if f.dataflow_trace %}
                <div class="trace-box">
                    <strong>⚡ Dataflow Taint Trace:</strong>
                    {% for step in f.dataflow_trace %}
                    <div class="trace-step">
                        Step {{ loop.index }}: {{ step.description }} <br>
                        <code>{{ step.code_snippet }}</code>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}

                {% if f.gadget_chain %}
                <div class="trace-box" style="background: rgba(192, 132, 252, 0.08); border-color: rgba(192, 132, 252, 0.3);">
                    <strong>⛓ POP Gadget Chain Trace ({{ f.gadget_chain.steps|length }} steps):</strong>
                    {% for step in f.gadget_chain.steps %}
                    <div class="trace-step">
                        <strong>[{{ step.step_number }}] {{ step.class_name }}::{{ step.method_name }}()</strong> — {{ step.description }}
                    </div>
                    {% endfor %}
                    {% if f.gadget_chain.payload_blueprint %}
                    <div class="code-block" style="margin-top:0.5rem;">{{ f.gadget_chain.payload_blueprint }}</div>
                    {% endif %}
                </div>
                {% endif %}

                {% if f.remediation %}
                <div class="remediation-box">
                    <h4>💡 Remediation:</h4>
                    <div>{{ f.remediation }}</div>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </div>

    <script>
        let currentFilter = 'ALL';

        function setFilter(sev) {
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.toggle('active', btn.textContent.trim().toUpperCase() === (sev === 'POP' ? 'POP CHAINS' : sev));
            });
            filterFindings();
        }

        function filterFindings() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');

            cards.forEach(card => {
                const text = card.getAttribute('data-text').toLowerCase();
                const sev = card.getAttribute('data-severity');
                const type = card.getAttribute('data-type');

                let matchesFilter = true;
                if (currentFilter === 'POP') {
                    matchesFilter = (type === 'POP_GADGET_CHAIN');
                } else if (currentFilter !== 'ALL') {
                    matchesFilter = (sev === currentFilter);
                }

                const matchesQuery = !query || text.includes(query);
                card.style.display = (matchesFilter && matchesQuery) ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>
"""


class HTMLReporter:
    """Generates self-contained interactive HTML reports using Jinja2."""

    def generate_html(self, result: ScanResult) -> str:
        from jinja2 import Template
        template = Template(HTML_TEMPLATE)
        return template.render(
            target_path=result.target_path,
            summary=result.summary,
            findings=result.findings,
            gadget_chains=result.gadget_chains
        )

    def save_to_file(self, result: ScanResult, output_path: str):
        html_content = self.generate_html(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
