"""
Interactive, standalone HTML Report Generator with modern glassmorphism UI.
"""

import json
import os
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
        .low-text { color: var(--low); }
        .info-text { color: var(--info); }
        .chains-text { color: #c084fc; }

        .summary-note, .empty-state { color: var(--text-dim); margin: 0.75rem 0 1.5rem; }
        .evidence-details {
            margin-top: 1rem;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow-wrap: anywhere;
        }
        .evidence-details summary { cursor: pointer; font-weight: 600; }
        .evidence-details ul { margin: 0.5rem 0 0 1.25rem; }
        .evidence-details p { margin-top: 0.5rem; }
        .report-section { margin-top: 2rem; }
        .report-section h2 { margin-bottom: 0.75rem; }
        .compact-meta { color: var(--text-dim); font-size: 0.9rem; margin: 0.35rem 0 0.75rem; overflow-wrap: anywhere; }
        .status-line { margin-top: 0.7rem; font-size: 0.9rem; }
        .status-line strong { color: var(--text-main); }

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
        .finding-card.severity-INFO { border-left: 4px solid var(--info); }

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
        .badge-INFO { background: rgba(59, 130, 246, 0.2); color: var(--info); border: 1px solid var(--info); }

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

        .llm-box {
            background: rgba(99, 102, 241, 0.09);
            border: 1px solid rgba(99, 102, 241, 0.35);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }
        .llm-box h4 { margin-bottom: 0.55rem; color: #a5b4fc; }
        .llm-box p { margin-top: 0.4rem; }
        .llm-box ul { margin: 0.4rem 0 0 1.25rem; }
        .llm-verdict { font-weight: 700; }

        /* Reading layout */
        :root {
            --bg-main: #f4f6fa;
            --bg-card: #ffffff;
            --bg-card-hover: #f8faff;
            --border-color: #dce3ed;
            --text-main: #18243a;
            --text-dim: #52627b;
            --primary: #2458c8;
            --critical: #b52435;
            --high: #ad4b13;
            --medium: #8a6200;
            --low: #006d79;
            --info: #2458c8;
            --success: #166b49;
        }

        html { scroll-behavior: smooth; }
        body { padding: 2rem 1.25rem 4rem; line-height: 1.55; }
        .container { max-width: 1180px; }
        [hidden] { display: none !important; }
        button, input { font: inherit; }
        button:focus-visible, input:focus-visible, a:focus-visible, summary:focus-visible {
            outline: 3px solid #7aa5ff;
            outline-offset: 3px;
        }

        header {
            align-items: flex-start;
            gap: 2rem;
            margin-bottom: 1rem;
            padding: 2rem;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            background: linear-gradient(120deg, #ffffff 58%, #eaf0ff);
            box-shadow: 0 8px 32px rgba(29, 49, 86, 0.06);
        }
        .header-title { min-width: 0; }
        .header-title h1 {
            max-width: 720px;
            font-size: clamp(1.7rem, 3vw, 2.35rem);
            line-height: 1.2;
            color: var(--text-main);
            background: none;
            -webkit-text-fill-color: currentColor;
        }
        .eyebrow {
            color: var(--primary) !important;
            font-size: 0.7rem !important;
            font-weight: 800;
            letter-spacing: 0.12em;
            margin: 0 0 0.45rem !important;
        }
        .header-title .report-subtitle { max-width: 720px; margin: 0.8rem 0 1rem; font-size: 1rem; }
        .target-path { display: flex; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; }
        .target-path code {
            max-width: 100%;
            padding: 0.25rem 0.45rem;
            border-radius: 5px;
            background: #eaf0f8;
            color: #24436f;
            overflow-wrap: anywhere;
        }
        .header-title .scan-facts { margin-top: 0.9rem; font-size: 0.82rem; }
        .scan-warning { color: var(--critical) !important; font-weight: 700; }
        .report-status {
            flex: none;
            border-radius: 100px;
            padding: 0.45rem 0.7rem;
            font-size: 0.8rem;
            font-weight: 700;
            white-space: nowrap;
        }
        .status-complete { color: #116548; background: #dff6eb; }
        .status-incomplete { color: #9d2630; background: #ffe7e8; }

        .section-nav {
            position: sticky;
            top: 0;
            z-index: 10;
            display: flex;
            gap: 0.35rem;
            padding: 0.45rem;
            margin-bottom: 1.3rem;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.96);
            box-shadow: 0 4px 18px rgba(29, 49, 86, 0.06);
        }
        .section-nav a {
            padding: 0.55rem 0.85rem;
            border-radius: 8px;
            color: var(--text-main);
            font-size: 0.88rem;
            font-weight: 700;
            text-decoration: none;
        }
        .section-nav a:hover { background: #edf3ff; color: var(--primary); }
        .section-nav span, .heading-count { color: var(--text-dim); font-weight: 600; }

        .metrics-grid { grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 0.7rem; margin-bottom: 1.5rem; }
        .metric-card {
            padding: 0.95rem 0.7rem;
            border-radius: 12px;
            box-shadow: none;
            backdrop-filter: none;
            text-align: left;
        }
        .metric-card:hover { transform: none; border-color: #aebedb; }
        .metric-num { font-size: 1.75rem; line-height: 1.15; margin-bottom: 0.35rem; }
        .metric-label { font-size: 0.7rem; font-weight: 700; }

        .report-section { scroll-margin-top: 5rem; margin-top: 2.2rem; }
        .report-section h2 { font-size: 1.45rem; line-height: 1.25; }
        .section-heading { display: flex; justify-content: space-between; align-items: end; gap: 1rem; margin-bottom: 0.9rem; }
        .detail-actions { display: flex; gap: 0.4rem; }
        .detail-actions button, .empty-results button {
            border: 1px solid var(--border-color);
            border-radius: 7px;
            padding: 0.4rem 0.65rem;
            background: #fff;
            color: var(--primary);
            cursor: pointer;
            font-size: 0.78rem;
            font-weight: 700;
        }
        .detail-actions button:hover, .empty-results button:hover { background: #eaf0ff; }
        .toolbar {
            gap: 0.45rem;
            padding: 0.9rem;
            margin-bottom: 0;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            background: #fff;
        }
        .search-input { flex-basis: 100%; padding: 0.65rem 0.8rem; background: #f8faff; }
        .filter-btn { padding: 0.45rem 0.7rem; font-size: 0.79rem; border-radius: 7px; background: #f8faff; color: var(--text-main); }
        .filter-btn.active, .filter-btn:hover { background: var(--primary); color: #fff; }
        .summary-note { margin: 0.55rem 0 1rem; font-size: 0.85rem; }
        .empty-results { padding: 1.4rem; border: 1px dashed #b9c6da; border-radius: 10px; background: #fff; }

        .findings-list { gap: 0.8rem; }
        .finding-card { padding: 1.15rem 1.25rem; box-shadow: 0 3px 14px rgba(29, 49, 86, 0.04); backdrop-filter: none; }
        .finding-header { gap: 1rem; margin-bottom: 0.45rem; }
        .finding-title { font-size: 1.08rem; line-height: 1.35; margin: 0; }
        .compact-meta { margin: 0.35rem 0 0; font-size: 0.8rem; }
        .status-line { padding-top: 0.55rem; border-top: 1px solid var(--border-color); }
        .badge { flex: none; white-space: nowrap; }
        .badge-CRITICAL { background: #ffeaed; }
        .badge-HIGH { background: #fff0e5; }
        .badge-MEDIUM { background: #fff5d7; }
        .badge-LOW { background: #dff6f8; }
        .badge-INFO { background: #e7efff; }

        .evidence-details { background: #fbfcff; border-radius: 10px; padding: 0.75rem 0.95rem; }
        .evidence-details[open] { background: #fff; }
        .evidence-details summary { color: var(--text-main); line-height: 1.4; }
        .evidence-details summary:hover { color: var(--primary); }
        .evidence-details[open] > summary { margin-bottom: 0.7rem; }
        .evidence-details p, .evidence-details li { font-size: 0.87rem; }
        .code-block { background: #152137; color: #f3f6fa; }
        .trace-box { background: #f4f2ff; border-color: #d6d1ff; }
        .remediation-box { background: #eff9f3; border-color: #c9e7d5; }

        @media (max-width: 700px) {
            body { padding: 0.8rem 0.65rem 2rem; }
            header { padding: 1.25rem; display: block; }
            .report-status { display: inline-block; margin-top: 0.8rem; }
            .section-nav { overflow-x: auto; }
            .section-nav a { flex: none; }
            .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .section-heading { align-items: flex-start; flex-direction: column; }
            .finding-header { align-items: flex-start; }
            .finding-card { padding: 1rem; }
            .filter-btn { flex: 1 0 auto; }
        }

        @media print {
            body { padding: 0; background: #fff; }
            header, .finding-card, .metric-card { box-shadow: none; }
            .section-nav, .toolbar, .detail-actions, .empty-results { display: none !important; }
            .report-section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <p class="eyebrow">SECURITY SCAN REPORT</p>
                <h1>PHP Insecure Deserialization SAST Report</h1>
                <p class="report-subtitle">Static analysis results. Findings and candidate routes require review before treating them as exploitable.</p>
                <p class="target-path"><strong>Target</strong> <code>{{ target_path }}</code></p>
                <p class="scan-facts">{{ summary.total_files_scanned }}/{{ summary.total_files_discovered }} files scanned · {{ '%.2f'|format(summary.scan_duration_seconds) }}s · PHP {{ analysis.get('target_php_version', 'unknown') }} · Library mode: {{ analysis.get('library_mode', 'unknown') }} · Conditional API exposures: {{ summary.api_exposure_count }}</p>
                {% if errors %}
                <p class="scan-warning">Incomplete scan: {{ summary.files_with_errors }} file(s) had errors.</p>
                <ul>
                    {% for error in errors %}
                    <li>{{ error.file_path|e }} ({{ error.phase|e }}): {{ error.message|e }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            <span class="report-status {{ 'status-incomplete' if errors else 'status-complete' }}">{{ 'Incomplete scan' if errors else 'Scan complete' }}</span>
        </header>

        <nav class="section-nav" aria-label="Report sections">
            <a href="#findings">Findings <span>{{ summary.total_findings }}</span></a>
            <a href="#routes">Routes <span>{{ routes|length }}</span></a>
            <a href="#sinks">Sinks <span>{{ sink_inventory|length }}</span></a>
        </nav>

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
                <div class="metric-num low-text">{{ summary.low_count }}</div>
                <div class="metric-label">Low</div>
            </div>
            <div class="metric-card">
                <div class="metric-num info-text">{{ summary.info_count }}</div>
                <div class="metric-label">Info</div>
            </div>
            <div class="metric-card">
                <div class="metric-num chains-text">{{ summary.gadget_chains_found }}</div>
                <div class="metric-label">POP Gadget Chains</div>
            </div>
        </div>

        <section id="findings" class="report-section findings-section">
        <div class="section-heading"><div><p class="eyebrow">REVIEW QUEUE</p><h2>Findings</h2></div><div class="detail-actions"><button type="button" onclick="toggleFindingDetails(true)">Expand all</button><button type="button" onclick="toggleFindingDetails(false)">Collapse all</button></div></div>
        <div class="toolbar" role="group" aria-label="Finding filters">
            <input type="search" id="searchInput" class="search-input" aria-label="Search findings" placeholder="Search findings by title, file, or rule ID..." oninput="filterFindings()">
            <button type="button" class="filter-btn active" data-filter="ALL" aria-pressed="true" onclick="setFilter('ALL')">All</button>
            <button type="button" class="filter-btn" data-filter="CRITICAL" aria-pressed="false" onclick="setFilter('CRITICAL')">Critical</button>
            <button type="button" class="filter-btn" data-filter="HIGH" aria-pressed="false" onclick="setFilter('HIGH')">High</button>
            <button type="button" class="filter-btn" data-filter="MEDIUM" aria-pressed="false" onclick="setFilter('MEDIUM')">Medium</button>
            <button type="button" class="filter-btn" data-filter="LOW" aria-pressed="false" onclick="setFilter('LOW')">Low</button>
            <button type="button" class="filter-btn" data-filter="INFO" aria-pressed="false" onclick="setFilter('INFO')">Info</button>
            <button type="button" class="filter-btn" data-filter="POP" aria-pressed="false" onclick="setFilter('POP')">POP Chains</button>
        </div>
        <p id="visibleCount" class="summary-note" aria-live="polite">Showing {{ findings|length }} of {{ findings|length }} findings</p>
        <div id="noResults" class="empty-results" hidden>No findings match these filters. <button type="button" onclick="resetFilters()">Clear filters</button></div>

        <div class="findings-list" id="findingsList">
            {% for f in findings %}
            <div class="finding-card severity-{{ f.severity.value }}" data-severity="{{ f.severity.value }}" data-type="{{ f.vuln_type.value }}" data-text="{{ f.title }} {{ f.location.file_path }} {{ f.rule_id }}{% if f.llm_verification %} {{ f.llm_verification.verdict }} {{ f.llm_verification.reasoning }}{% endif %}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{{ f.title }}</div>
                        <p class="compact-meta">{{ f.location.file_path|basename }}:{{ f.location.start_line }} · {{ f.rule_id }}</p>
                    </div>
                    <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
                </div>
                <p>{{ f.description }}</p>
                {% if f.assessment %}
                <p class="status-line"><strong>Evidence:</strong> {{ f.assessment.evidence_level|replace('_', ' ') }};
                    <strong>Exploit verified:</strong> {{ f.assessment.exploitability_verified }}{% if f.assessment.review_priority %};
                    <strong>Review priority:</strong> {{ f.assessment.review_priority.score }}/100 ({{ f.assessment.review_priority.band }}, not CVSS){% endif %}</p>
                {% endif %}
                <details class="evidence-details"><summary>Full finding details</summary>
                <p><strong>Full location:</strong> {{ f.location.file_path }}:{{ f.location.start_line }}:{{ f.location.start_col }};
                   <strong>Rule:</strong> {{ f.rule_id }};
                   <strong>Confidence:</strong> {{ f.confidence.value }}{% if f.cwe %}; <strong>CWE:</strong> {{ f.cwe }}{% endif %}</p>
                {% if f.metadata.get('engine') == 'impact_candidate' %}
                <p><strong>Linked source finding:</strong> {{ f.metadata.source_finding_id }}
                   ({{ f.metadata.source_location.file_path }}:{{ f.metadata.source_location.start_line }});
                   <strong>Candidate class:</strong> {{ f.metadata.candidate_class }};
                   <strong>Class loading:</strong> {{ f.metadata.class_loading|join(', ') }}</p>
                {% if f.metadata.trigger_sites %}
                <p><strong>Possible triggers:</strong></p><ul>{% for trigger in f.metadata.trigger_sites %}
                    <li>{{ trigger.file_path }}:{{ trigger.start_line }}</li>{% endfor %}</ul>
                {% endif %}
                <p><strong>Linked routes:</strong> {{ f.metadata.route_ids|join(', ') }}</p>
                {% endif %}
                {% if f.assessment %}
                <p><strong>Static detection:</strong> {{ f.assessment.detection_level }};
                   <strong>Evidence:</strong> {{ f.assessment.evidence_level }};
                   <strong>Analysis:</strong> {{ f.assessment.analysis_completeness }};
                   {% if f.assessment.review_priority %}
                   <strong>Review priority:</strong> {{ f.assessment.review_priority.score }}/100
                   ({{ f.assessment.review_priority.band }}, static triage, not CVSS);
                   {% endif %}
                   <strong>Exploitability verified:</strong> {{ f.assessment.exploitability_verified }}</p>
                {% if f.assessment.limitations %}
                <details class="evidence-details"><summary>Analysis limitations ({{ f.assessment.limitations|length }})</summary>
                    <ul>{% for limitation in f.assessment.limitations %}<li>{{ limitation }}</li>{% endfor %}</ul>
                </details>
                {% endif %}
                {% endif %}

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

                {% if f.flow_evidence %}
                <details class="evidence-details"><summary>Retained source flows ({{ f.flow_evidence|length }})</summary>
                    {% for flow in f.flow_evidence %}
                    <p><strong>Source:</strong> {{ flow.source_kind }}: {{ flow.source_origin }};
                       <strong>Guard:</strong> {{ flow.guard_status }};
                       <strong>Uncertain:</strong> {{ flow.uncertain }}</p>
                    {% if flow.review_conditions %}<p><strong>Review conditions:</strong> {{ flow.review_conditions|join('; ') }}</p>{% endif %}
                    {% if flow.path_assumptions %}<p><strong>Path assumptions:</strong> {{ flow.path_assumptions|join('; ') }}</p>{% endif %}
                    {% endfor %}
                </details>
                {% endif %}

                {% if f.gadget_chain %}
                <div class="trace-box" style="background: rgba(192, 132, 252, 0.08); border-color: rgba(192, 132, 252, 0.3);">
                    <p><strong>Candidate chain confidence:</strong> {{ f.gadget_chain.confidence.value }};
                       <strong>Candidate serialized properties:</strong> {{ f.gadget_chain.candidate_serialized_properties|join(', ') or 'none identified' }}.
                       {{ f.gadget_chain.explanation }}</p>
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
                {% if f.llm_verification %}
                <section class="llm-box" aria-label="LLM assessment">
                    <h4>LLM assessment</h4>
                    <p><strong>Verdict:</strong> <span class="llm-verdict">{{ f.llm_verification.verdict }}</span>;
                       <strong>Model assessment:</strong> {{ 'Potentially vulnerable' if f.llm_verification.is_vulnerable else 'Not confirmed as vulnerable' }};
                       <strong>Confidence:</strong> {{ '%.0f'|format(f.llm_verification.confidence_score * 100) }}%</p>
                    <p><strong>Reachability:</strong> {{ f.llm_verification.reachability }};
                       <strong>Sanitization:</strong> {{ f.llm_verification.sanitization }};
                       <strong>Exploitability:</strong> {{ f.llm_verification.exploitability }}</p>
                    <p><strong>Exploitability assessment:</strong> {{ f.llm_verification.exploitability_assessment }}</p>
                    {% if f.llm_verification.reasoning %}<p><strong>Reasoning:</strong> {{ f.llm_verification.reasoning }}</p>{% endif %}
                    {% if f.llm_verification.prerequisites %}<p><strong>Prerequisites:</strong></p><ul>{% for item in f.llm_verification.prerequisites %}<li>{{ item }}</li>{% endfor %}</ul>{% endif %}
                    {% if f.llm_verification.suggested_poc %}<p><strong>Suggested PoC:</strong> {{ f.llm_verification.suggested_poc }}</p>{% endif %}
                    {% if f.llm_verification.remediation %}<p><strong>LLM remediation suggestion:</strong> {{ f.llm_verification.remediation }}</p>{% endif %}
                </section>
                {% endif %}
                </details>
            </div>
            {% endfor %}
        </div>
        </section>

        <section id="routes" class="report-section">
            <p class="eyebrow">PATHS TO REVIEW</p><h2>Route evidence <span class="heading-count">{{ routes|length }}</span></h2>
            <p class="summary-note">Each route is a static path or candidate. Open one to see its conditions; no route here confirms an exploit.</p>
            {% if routes %}
            {% for route in routes %}
            <details class="evidence-details">
                <summary>{{ route.entry_class or route.source_kind }} → {{ (route.impact or route.sink).file_path|basename }}:{{ (route.impact or route.sink).start_line }}{% if route.trigger %} via {{ route.trigger.file_path|basename }}:{{ route.trigger.start_line }}{% endif %} · {{ route.status }}</summary>
                <p><strong>Kind:</strong> {{ route.route_kind }}; <strong>Runtime verified:</strong> {{ route.runtime_verified }};
                   <strong>Source:</strong> {{ route.source_kind }}: {{ route.source_origin }}</p>
                <p><strong>Sink:</strong> {{ route.sink.file_path }}:{{ route.sink.start_line }}
                   {% if route.store %}<br><strong>Store:</strong> {{ route.store.file_path }}:{{ route.store.start_line }}{% endif %}
                   {% if route.trigger %}<br><strong>Trigger:</strong> {{ route.trigger.file_path }}:{{ route.trigger.start_line }}{% endif %}
                   {% if route.impact %}<br><strong>Impact:</strong> {{ route.impact.file_path }}:{{ route.impact.start_line }}{% endif %}
                   {% if route.session_key %}<br><strong>Session key:</strong> {{ route.session_key }}{% endif %}
                   {% if route.entry_class %}<br><strong>Entry class:</strong> {{ route.entry_class }}{% endif %}
                   {% if route.class_loading %}<br><strong>Class loading:</strong> {{ route.class_loading }}{% endif %}</p>
                {% if route.review_conditions %}<p><strong>Review conditions:</strong> {{ route.review_conditions|join('; ') }}</p>{% endif %}
                {% if route.path_assumptions %}<p><strong>Path assumptions:</strong> {{ route.path_assumptions|join('; ') }}</p>{% endif %}
                {% if route.missing_edges %}<p><strong>Missing edges:</strong> {{ route.missing_edges|join('; ') }}</p>{% endif %}
            </details>
            {% endfor %}
            {% else %}<p class="empty-state">No routes retained.</p>{% endif %}
        </section>

        <section id="sinks" class="report-section">
            <p class="eyebrow">ANALYSIS COVERAGE</p><h2>Sink inventory <span class="heading-count">{{ sink_inventory|length }}</span></h2>
            {% if sink_inventory %}
            {% for sink in sink_inventory %}
            <details class="evidence-details">
                <summary>{{ sink.sink_name }} · {{ sink.location.file_path|basename }}:{{ sink.location.start_line }} · {{ sink.disposition }}</summary>
                <p><strong>Full location:</strong> {{ sink.location.file_path }}:{{ sink.location.start_line }}:{{ sink.location.start_col }};
                   <strong>Sink argument:</strong> {{ sink.sink_argument }}{% if sink.source_assumption %};
                   <strong>Source assumption:</strong> {{ sink.source_assumption }}{% endif %}</p>
                {% if sink.note %}<p>{{ sink.note }}</p>{% endif %}
                {% if sink.evidence %}<p><strong>Evidence:</strong></p><ul>{% for step in sink.evidence %}<li>{{ step.description }} · {{ step.location.file_path|basename }}:{{ step.location.start_line }}</li>{% endfor %}</ul>{% endif %}
            </details>
            {% endfor %}
            {% else %}<p class="empty-state">No sinks inventoried.</p>{% endif %}
        </section>
    </div>

    <script>
        let currentFilter = 'ALL';

        function setFilter(sev) {
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                const active = btn.dataset.filter === sev;
                btn.classList.toggle('active', active);
                btn.setAttribute('aria-pressed', String(active));
            });
            filterFindings();
        }

        function resetFilters() {
            document.getElementById('searchInput').value = '';
            setFilter('ALL');
            document.getElementById('searchInput').focus();
        }

        function toggleFindingDetails(open) {
            document.querySelectorAll('.finding-card:not([hidden]) details').forEach(detail => {
                detail.open = open;
            });
        }

        function filterFindings() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            let visible = 0;

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
                const show = matchesFilter && matchesQuery;
                card.hidden = !show;
                if (show) visible++;
            });
            document.getElementById('visibleCount').textContent = 'Showing ' + visible + ' of ' + cards.length + ' findings';
            document.getElementById('noResults').hidden = visible !== 0;
        }

        document.getElementById('searchInput').addEventListener('keydown', event => {
            if (event.key === 'Escape') resetFilters();
        });
    </script>
</body>
</html>
"""


class HTMLReporter:
    """Generates self-contained interactive HTML reports using Jinja2."""

    def generate_html(self, result: ScanResult) -> str:
        from jinja2 import Environment, select_autoescape
        environment = Environment(
            autoescape=select_autoescape(default=True, default_for_string=True)
        )
        environment.filters["basename"] = os.path.basename
        template = environment.from_string(HTML_TEMPLATE)
        return template.render(
            target_path=result.target_path,
            summary=result.summary,
            analysis=result.analysis,
            findings=result.findings,
            routes=result.routes,
            sink_inventory=result.sink_inventory,
            gadget_chains=result.gadget_chains,
            errors=result.errors
        )

    def save_to_file(self, result: ScanResult, output_path: str):
        html_content = self.generate_html(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
