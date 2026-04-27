"""
Core scanning engine.

Orchestrates file discovery, rule matching, confidence scoring,
deduplication, and result collection. Supports multi-threaded scanning
and uses keyword pre-filtering to skip irrelevant lines.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Callable
try:
    from .scanner import FileInfo, ScanConfig, discover_files, read_file_lines
    from .rules import ALL_RULES, Rule
    from .analyzer import Finding, analyze_line, deduplicate_findings
except ImportError:
    from hardcorde.scanner import FileInfo, ScanConfig, discover_files, read_file_lines
    from hardcorde.rules import ALL_RULES, Rule
    from hardcorde.analyzer import Finding, analyze_line, deduplicate_findings


@dataclass
class ScanStats:
    """Statistics for a completed scan."""
    target: str = ""
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_error: int = 0
    lines_scanned: int = 0
    findings_raw: int = 0
    findings_final: int = 0
    elapsed_seconds: float = 0.0
    rules_loaded: int = 0


@dataclass
class EngineConfig:
    """Configuration for the scanning engine."""
    scan_config: ScanConfig = field(default_factory=ScanConfig)
    min_confidence: int = 25
    threads: int = 4
    context_window: int = 3
    rule_ids: Optional[list[str]] = None      # Only run these rules
    exclude_rules: Optional[list[str]] = None  # Skip these rules
    categories: Optional[list[str]] = None     # Only these categories
    tags: Optional[list[str]] = None           # Only rules with these tags
    severity_min: str = "info"                 # Minimum severity to report


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _filter_rules(config: EngineConfig) -> list[Rule]:
    """Filter the rule set based on engine configuration."""
    rules = list(ALL_RULES)

    if config.rule_ids:
        ids = set(config.rule_ids)
        rules = [r for r in rules if r.id in ids]

    if config.exclude_rules:
        ids = set(config.exclude_rules)
        rules = [r for r in rules if r.id not in ids]

    if config.categories:
        cats = set(config.categories)
        rules = [r for r in rules if r.category.value in cats]

    if config.tags:
        tag_set = set(config.tags)
        rules = [r for r in rules if tag_set & set(r.tags)]

    min_rank = SEVERITY_RANK.get(config.severity_min, 4)
    rules = [r for r in rules if SEVERITY_RANK.get(r.severity.value, 4) <= min_rank]

    return rules


def _prepare_rules(rules: list[Rule]) -> list[tuple[Rule, list[str]]]:
    """
    Prepare rules with lowercased fast keywords for efficient pre-filtering.
    Returns list of (rule, lowered_keywords) tuples.
    """
    prepared = []
    for rule in rules:
        lowered = [kw.lower() for kw in rule.fast_keywords]
        prepared.append((rule, lowered))
    return prepared


def _line_might_match(line_lower: str, keywords: list[str]) -> bool:
    """
    Fast pre-filter: check if any keyword appears in the lowercased line.
    If the rule has no keywords, always return True (try the regex).
    """
    if not keywords:
        return True
    for kw in keywords:
        if kw in line_lower:
            return True
    return False


def _scan_file(
    file_info: FileInfo,
    prepared_rules: list[tuple[Rule, list[str]]],
    context_window: int,
    min_confidence: int,
) -> tuple[list[Finding], int, Optional[str]]:
    """
    Scan a single file against all rules.
    Returns (findings, lines_scanned, error_message).
    """
    try:
        lines = read_file_lines(file_info.path)
    except Exception as e:
        return [], 0, str(e)

    if not lines:
        return [], 0, None

    findings: list[Finding] = []
    for line_num_0, line in enumerate(lines):
        line_num = line_num_0 + 1  # 1-based

        # Quick pre-filter: skip very short lines
        stripped = line.strip()
        if len(stripped) < 4:
            continue

        # Lowercase once for all keyword checks on this line
        line_lower = stripped.lower()

        for rule, keywords in prepared_rules:
            # Fast keyword pre-filter: skip regex if no keyword present
            if not _line_might_match(line_lower, keywords):
                continue

            finding = analyze_line(
                rule=rule,
                line=line,
                line_number=line_num,
                file_path=file_info.path,
                lines=lines,
                context_window=context_window,
            )
            if finding and finding.confidence >= min_confidence:
                findings.append(finding)

    return findings, len(lines), None


def run_scan(
    target: str,
    config: EngineConfig,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> tuple[list[Finding], ScanStats]:
    """
    Run a full credential scan on a target path.

    Args:
        target: Root directory or file path to scan
        config: Engine configuration
        progress_callback: Optional callback(file_path, files_done, files_total)

    Returns:
        (findings, stats)
    """
    start_time = time.time()
    stats = ScanStats(target=os.path.abspath(target))

    rules = _filter_rules(config)
    stats.rules_loaded = len(rules)

    if not rules:
        return [], stats

    # Pre-compute lowercased keywords for fast filtering
    prepared_rules = _prepare_rules(rules)

    # Phase 1: Discover files
    if os.path.isfile(target):
        from pathlib import Path
        ext = Path(target).suffix.lower()
        files = [FileInfo(
            path=os.path.abspath(target),
            size=os.path.getsize(target),
            extension=ext,
            filename=os.path.basename(target),
            is_high_value=True,
        )]
    else:
        files = list(discover_files(target, config.scan_config))

    stats.files_discovered = len(files)

    if not files:
        stats.elapsed_seconds = time.time() - start_time
        return [], stats

    # Phase 2: Scan files
    all_findings: list[Finding] = []
    files_done = 0

    if config.threads <= 1:
        # Single-threaded
        for fi in files:
            findings, lines, error = _scan_file(
                fi, prepared_rules, config.context_window, config.min_confidence
            )
            if error:
                stats.files_error += 1
            else:
                stats.files_scanned += 1
                stats.lines_scanned += lines
                all_findings.extend(findings)
            files_done += 1
            if progress_callback:
                progress_callback(fi.path, files_done, len(files))
    else:
        # Multi-threaded
        with ThreadPoolExecutor(max_workers=config.threads) as pool:
            future_to_file = {
                pool.submit(
                    _scan_file, fi, prepared_rules, config.context_window, config.min_confidence
                ): fi
                for fi in files
            }
            for future in as_completed(future_to_file):
                fi = future_to_file[future]
                try:
                    findings, lines, error = future.result()
                    if error:
                        stats.files_error += 1
                    else:
                        stats.files_scanned += 1
                        stats.lines_scanned += lines
                        all_findings.extend(findings)
                except Exception:
                    stats.files_error += 1

                files_done += 1
                if progress_callback:
                    progress_callback(fi.path, files_done, len(files))

    stats.findings_raw = len(all_findings)

    # Phase 3: Deduplicate
    all_findings = deduplicate_findings(all_findings)
    stats.findings_final = len(all_findings)
    stats.files_skipped = stats.files_discovered - stats.files_scanned - stats.files_error
    stats.elapsed_seconds = time.time() - start_time

    return all_findings, stats
