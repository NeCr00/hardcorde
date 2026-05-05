"""
Output and reporting system.

Supports multiple output formats:
- Terminal (colored, human-readable)
- JSON (machine-readable, for pipelines)
- CSV (spreadsheet-friendly)
- HTML (standalone report for sharing with clients)
"""

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import TextIO
try:
    from . import __version__
    from .analyzer import Finding
    from .rules import Severity
except ImportError:
    from hardcorde import __version__
    from hardcorde.analyzer import Finding
    from hardcorde.rules import Severity


# ANSI color codes (work on both modern Windows Terminal and Linux/macOS)
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


SEVERITY_COLORS = {
    "critical": Colors.BG_RED + Colors.WHITE,
    "high": Colors.RED,
    "medium": Colors.YELLOW,
    "low": Colors.CYAN,
    "info": Colors.GRAY,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _supports_color() -> bool:
    """Check if the terminal supports ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if sys.platform == "win32":
        return os.environ.get("TERM") == "xterm" or os.environ.get("WT_SESSION")
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(color: str, text: str, use_color: bool = True) -> str:
    """Wrap text in color codes if color is supported."""
    if not use_color:
        return text
    return f"{color}{text}{Colors.RESET}"


class TerminalReporter:
    """Human-readable colored terminal output."""

    def __init__(self, stream: TextIO = None, show_context: bool = True,
                 use_color: bool = None,
                 min_confidence: int = 0, verbose: bool = False):
        self.stream = stream or sys.stdout
        self.show_context = show_context
        self.use_color = use_color if use_color is not None else _supports_color()
        self.min_confidence = min_confidence
        self.verbose = verbose

    def _write(self, text: str):
        self.stream.write(text)

    def report_header(self, target: str, total_files: int):
        self._write("\n")
        self._write(_c(Colors.BOLD + Colors.CYAN,
                       "=" * 70 + "\n", self.use_color))
        self._write(_c(Colors.BOLD + Colors.CYAN,
                       "  HARDCORDE - Credential Discovery Report\n", self.use_color))
        self._write(_c(Colors.BOLD + Colors.CYAN,
                       "=" * 70 + "\n", self.use_color))
        self._write(f"  Target:     {target}\n")
        self._write(f"  Files:      {total_files} scanned\n")
        self._write(f"  Timestamp:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        self._write(_c(Colors.DIM, "-" * 70 + "\n\n", self.use_color))

    def report_finding(self, finding: Finding, index: int):
        if finding.confidence < self.min_confidence:
            return

        sev_color = SEVERITY_COLORS.get(finding.severity, "")
        sev_label = _c(sev_color, f" {finding.severity.upper()} ",
                       self.use_color)

        # Line 1: index, severity, rule name
        self._write(f"  [{index}] {sev_label} "
                     f"{_c(Colors.BOLD, finding.rule_name, self.use_color)}\n")
        # Line 2: file (with line number when applicable)
        if finding.line_number > 0:
            self._write(f"      {finding.file_path}:{finding.line_number}\n")
        else:
            self._write(f"      {finding.file_path}\n")
        # Line 3: secret value (always full — no masking)
        self._write(f"      Secret:     {_c(Colors.YELLOW, finding.secret_value, self.use_color)}\n")
        # Line 4: confidence bar
        self._write(f"      Confidence: {self._confidence_bar(finding.confidence)}\n")

        # Verbose: extra details only when asked
        if self.verbose:
            self._write(_c(Colors.DIM,
                           f"      Rule: {finding.rule_id}  |  "
                           f"Category: {finding.category}  |  "
                           f"Entropy: {finding.entropy:.2f}\n", self.use_color))
            if finding.score_breakdown:
                parts = ", ".join(
                    f"{k}: {'+' if v > 0 else ''}{v}"
                    for k, v in sorted(finding.score_breakdown.items(),
                                       key=lambda x: -abs(x[1]))
                )
                self._write(_c(Colors.DIM,
                               f"      Scoring: base=50, {parts}\n", self.use_color))

        # Context: trimmed lines only (skip for filename-only matches)
        if self.show_context and finding.line_content:
            for ctx in finding.context_before:
                self._write(_c(Colors.DIM, f"        | {ctx}\n", self.use_color))
            self._write(_c(Colors.YELLOW,
                           f"      > | {finding.line_content}\n", self.use_color))
            for ctx in finding.context_after:
                self._write(_c(Colors.DIM, f"        | {ctx}\n", self.use_color))

        self._write("\n")

    def _confidence_bar(self, confidence: int) -> str:
        filled = confidence // 5
        bar = "█" * filled + "░" * (20 - filled)
        if confidence >= 75:
            color = Colors.RED
        elif confidence >= 50:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
        return _c(color, f"[{bar}] {confidence}%", self.use_color)

    def report_summary(self, findings: list[Finding]):
        filtered = [f for f in findings if f.confidence >= self.min_confidence]
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in filtered:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1

        self._write(_c(Colors.BOLD + Colors.CYAN,
                       "-" * 70 + "\n", self.use_color))
        self._write(_c(Colors.BOLD, "  SUMMARY\n", self.use_color))
        self._write(_c(Colors.DIM, "-" * 70 + "\n", self.use_color))
        self._write(f"  Total findings: {len(filtered)}\n\n")

        if by_severity:
            self._write("  By Severity:\n")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_severity.get(sev, 0)
                if count:
                    sev_color = SEVERITY_COLORS.get(sev, "")
                    self._write(f"    {_c(sev_color, f'{sev.upper():>10}', self.use_color)}: {count}\n")
            self._write("\n")

        if by_category:
            self._write("  By Category:\n")
            for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
                self._write(f"    {cat:>22}: {count}\n")

        self._write("\n" + _c(Colors.BOLD + Colors.CYAN,
                              "=" * 70 + "\n\n", self.use_color))


class JSONReporter:
    """JSON output for machine consumption."""

    def __init__(self, stream: TextIO = None,
                 min_confidence: int = 0, indent: int = 2):
        self.stream = stream or sys.stdout
        self.min_confidence = min_confidence
        self.indent = indent

    def report(self, findings: list[Finding], target: str, total_files: int):
        filtered = [f for f in findings if f.confidence >= self.min_confidence]
        output = {
            "tool": "hardcorde",
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "files_scanned": total_files,
            "total_findings": len(filtered),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "line_content": f.line_content,
                    "secret": f.secret_value,
                    "confidence": f.confidence,
                    "entropy": round(f.entropy, 3),
                    "tags": f.tags,
                    "score_breakdown": f.score_breakdown,
                    "context_before": f.context_before,
                    "context_after": f.context_after,
                }
                for f in filtered
            ],
        }
        json.dump(output, self.stream, indent=self.indent, ensure_ascii=False)
        self.stream.write("\n")


class CSVReporter:
    """CSV output for spreadsheet analysis."""

    def __init__(self, stream: TextIO = None,
                 min_confidence: int = 0):
        self.stream = stream or sys.stdout
        self.min_confidence = min_confidence

    def report(self, findings: list[Finding], target: str, total_files: int):
        filtered = [f for f in findings if f.confidence >= self.min_confidence]
        writer = csv.writer(self.stream)
        writer.writerow([
            "rule_id", "rule_name", "category", "severity",
            "file_path", "line_number", "secret", "confidence",
            "entropy", "tags",
        ])
        for f in filtered:
            writer.writerow([
                f.rule_id, f.rule_name, f.category, f.severity,
                f.file_path, f.line_number,
                f.secret_value,
                f.confidence, round(f.entropy, 3),
                ";".join(f.tags),
            ])


class SARIFReporter:
    """
    SARIF 2.1.0 output for ingestion by GitHub Code Scanning, Azure
    DevOps, DefectDojo, and other security pipelines.
    """

    SARIF_LEVEL = {
        "critical": "error",
        "high":     "error",
        "medium":   "warning",
        "low":      "note",
        "info":     "note",
    }

    def __init__(self, stream: TextIO = None,
                 min_confidence: int = 0, indent: int = 2):
        self.stream = stream or sys.stdout
        self.min_confidence = min_confidence
        self.indent = indent

    def report(self, findings: list[Finding], target: str, total_files: int):
        filtered = [f for f in findings if f.confidence >= self.min_confidence]

        # Build a unique rule list for the run from the findings encountered
        rules_seen: dict[str, dict] = {}
        for f in filtered:
            if f.rule_id in rules_seen:
                continue
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.description or f.rule_name},
                "defaultConfiguration": {
                    "level": self.SARIF_LEVEL.get(f.severity, "warning"),
                },
                "properties": {
                    "category": f.category,
                    "tags": f.tags,
                    "security-severity": self._security_severity(f.severity),
                },
            }

        results = []
        for f in filtered:
            uri = f.file_path.replace("\\", "/")
            region = {"startLine": max(1, f.line_number)}
            if f.line_content:
                region["snippet"] = {"text": f.line_content}
            result = {
                "ruleId": f.rule_id,
                "level": self.SARIF_LEVEL.get(f.severity, "warning"),
                "message": {
                    "text": f"{f.rule_name}: {f.description}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": region,
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "entropy": round(f.entropy, 3),
                    "category": f.category,
                    "severity": f.severity,
                    "tags": f.tags,
                    "secret": f.secret_value,
                },
            }
            results.append(result)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "hardcorde",
                        "version": __version__,
                        "informationUri": "https://github.com/yourusername/hardcorde",
                        "rules": list(rules_seen.values()),
                    }
                },
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    "properties": {
                        "target": target,
                        "files_scanned": total_files,
                    },
                }],
                "results": results,
            }],
        }
        json.dump(sarif, self.stream, indent=self.indent, ensure_ascii=False)
        self.stream.write("\n")

    @staticmethod
    def _security_severity(sev: str) -> str:
        # Maps to GitHub Code Scanning's 0.0–10.0 score
        return {
            "critical": "9.5",
            "high":     "8.0",
            "medium":   "5.5",
            "low":      "3.0",
            "info":     "1.0",
        }.get(sev, "5.0")


class HTMLReporter:
    """Standalone HTML report for client delivery."""

    def __init__(self, stream: TextIO = None,
                 min_confidence: int = 0):
        self.stream = stream or sys.stdout
        self.min_confidence = min_confidence

    def report(self, findings: list[Finding], target: str, total_files: int):
        filtered = [f for f in findings if f.confidence >= self.min_confidence]

        by_severity: dict[str, int] = {}
        for f in filtered:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        sev_colors_html = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#0891b2",
            "info": "#6b7280",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HARDCORDE Report - {self._esc(target)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  h1 {{ color: #38bdf8; margin-bottom: 0.5rem; font-size: 1.8rem; }}
  .meta {{ color: #94a3b8; margin-bottom: 2rem; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem;
           flex: 1; min-width: 150px; text-align: center; }}
  .stat .number {{ font-size: 2rem; font-weight: bold; }}
  .stat .label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
  .finding {{ background: #1e293b; border-radius: 8px; padding: 1.5rem;
              margin-bottom: 1rem; border-left: 4px solid; }}
  .finding.critical {{ border-color: #dc2626; }}
  .finding.high {{ border-color: #ea580c; }}
  .finding.medium {{ border-color: #ca8a04; }}
  .finding.low {{ border-color: #0891b2; }}
  .finding.info {{ border-color: #6b7280; }}
  .finding-header {{ display: flex; justify-content: space-between;
                     align-items: center; margin-bottom: 0.75rem; }}
  .severity {{ padding: 2px 10px; border-radius: 4px; font-size: 0.75rem;
               font-weight: bold; text-transform: uppercase; color: white; }}
  .confidence-bar {{ width: 120px; height: 8px; background: #334155;
                     border-radius: 4px; overflow: hidden; display: inline-block;
                     vertical-align: middle; }}
  .confidence-fill {{ height: 100%; border-radius: 4px; }}
  .detail {{ font-size: 0.85rem; color: #94a3b8; margin: 2px 0; }}
  .detail strong {{ color: #cbd5e1; }}
  .context {{ background: #0f172a; border-radius: 4px; padding: 0.75rem;
              margin-top: 0.75rem; font-family: 'JetBrains Mono', 'Fira Code',
              monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre; }}
  .context .highlight {{ color: #fbbf24; font-weight: bold; }}
  .context .dim {{ color: #64748b; }}
  .secret {{ font-family: monospace; background: #334155; padding: 2px 6px;
             border-radius: 3px; }}
  .filters {{ margin-bottom: 1.5rem; }}
  .filters button {{ background: #334155; border: none; color: #e2e8f0;
                     padding: 6px 14px; border-radius: 4px; cursor: pointer;
                     margin-right: 4px; margin-bottom: 4px; font-size: 0.8rem; }}
  .filters button.active {{ background: #3b82f6; }}
  .filters button:hover {{ background: #475569; }}
</style>
</head>
<body>
<div class="container">
  <h1>HARDCORDE - Credential Discovery Report</h1>
  <div class="meta">
    Target: {self._esc(target)} | Files scanned: {total_files} | {timestamp}
  </div>
  <div class="summary">
    <div class="stat">
      <div class="number" style="color: #f87171">{len(filtered)}</div>
      <div class="label">Total Findings</div>
    </div>
"""
        for sev in ["critical", "high", "medium", "low"]:
            count = by_severity.get(sev, 0)
            html += f"""    <div class="stat">
      <div class="number" style="color: {sev_colors_html[sev]}">{count}</div>
      <div class="label">{sev.upper()}</div>
    </div>
"""

        html += """  </div>
  <div class="filters">
    <button class="active" onclick="filterSev('all')">All</button>
    <button onclick="filterSev('critical')">Critical</button>
    <button onclick="filterSev('high')">High</button>
    <button onclick="filterSev('medium')">Medium</button>
    <button onclick="filterSev('low')">Low</button>
  </div>
  <div id="findings">
"""

        for i, f in enumerate(filtered, 1):
            secret_display = f.secret_value
            conf_color = "#dc2626" if f.confidence >= 75 else (
                "#ca8a04" if f.confidence >= 50 else "#22c55e")

            ctx_html = ""
            for cl in f.context_before:
                ctx_html += f'<span class="dim">{self._esc(cl)}</span>\n'
            ctx_html += f'<span class="highlight">{self._esc(f.line_content)}</span>\n'
            for cl in f.context_after:
                ctx_html += f'<span class="dim">{self._esc(cl)}</span>\n'

            html += f"""    <div class="finding {f.severity}" data-severity="{f.severity}">
      <div class="finding-header">
        <span><strong>#{i}</strong> {self._esc(f.rule_name)}</span>
        <span class="severity" style="background:{sev_colors_html.get(f.severity, '#6b7280')}">{f.severity}</span>
      </div>
      <div class="detail"><strong>File:</strong> {self._esc(f.file_path)}</div>
      <div class="detail"><strong>Line:</strong> {f.line_number}</div>
      <div class="detail"><strong>Category:</strong> {f.category}</div>
      <div class="detail"><strong>Secret:</strong> <span class="secret">{self._esc(secret_display)}</span></div>
      <div class="detail"><strong>Confidence:</strong>
        <div class="confidence-bar"><div class="confidence-fill" style="width:{f.confidence}%;background:{conf_color}"></div></div>
        {f.confidence}%
      </div>
      <div class="detail"><strong>Entropy:</strong> {f.entropy:.2f}</div>
      <div class="context">{ctx_html.rstrip()}</div>
    </div>
"""

        html += """  </div>
</div>
<script>
function filterSev(sev) {
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    el.style.display = (sev === 'all' || el.dataset.severity === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>"""

        self.stream.write(html)

    def _esc(self, text: str) -> str:
        """HTML-escape text."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
