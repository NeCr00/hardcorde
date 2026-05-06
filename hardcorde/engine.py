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
    passwords_only: bool = False               # Restrict to password-class rules


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def is_password_rule(rule: Rule) -> bool:
    """
    A rule counts as a 'password rule' (for --passwords-only) when it
    targets actual hardcoded password material. We include:

      - Category.PASSWORD               — direct password assignments
      - Category.HASH                   — password hashes (shadow, NTLM,
                                          htpasswd, LDIF userPassword) —
                                          these are passwords-at-rest
      - rules tagged with "password"    — connection strings with embedded
                                          passwords (DATABASE_URI tagged
                                          via `password` are kept this way)

    We deliberately EXCLUDE:
      API keys, OAuth tokens, JWTs, bearer tokens, GitHub/GitLab/Slack
      tokens, PEM private keys, env-secret blobs (`MY_SECRET=`), generic
      high-entropy strings, certificate files, credential-store files.
    """
    if rule.category.value in {"password", "hash"}:
        return True
    if "password" in rule.tags:
        return True
    return False


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

    if config.passwords_only:
        rules = [r for r in rules if is_password_rule(r)]

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


def _scan_multiline(
    file_info: FileInfo,
    lines: list[str],
    multiline_rules: list[tuple[Rule, list[str]]],
    context_window: int,
    min_confidence: int,
) -> list[Finding]:
    """
    Apply multi-line rules to the joined file content. Each match's line
    number is computed from the byte offset where the secret starts.
    """
    if not multiline_rules or not lines:
        return []
    # Joined file content; remember newline offsets so we can map back to line numbers.
    joined = "".join(lines)
    joined_lower = joined.lower()
    # Precompute cumulative line lengths for offset → line_number lookup
    line_starts = [0]
    for ln in lines:
        line_starts.append(line_starts[-1] + len(ln))

    def offset_to_line(off: int) -> int:
        # Binary search: find largest index i such that line_starts[i] <= off
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1  # 1-based

    findings: list[Finding] = []
    for rule, keywords in multiline_rules:
        if keywords and not any(kw in joined_lower for kw in keywords):
            continue
        for m in rule.pattern.finditer(joined):
            # Pick the secret group by the same logic as analyze_line
            try:
                gd = m.groupdict()
            except IndexError:
                gd = {}
            secret_value = None
            secret_group_used = None
            for name in sorted(
                (n for n in gd if n == "secret" or n.startswith("secret")),
                key=lambda n: (0 if n == "secret" else 1, n),
            ):
                v = gd.get(name)
                if v:
                    secret_value = v
                    secret_group_used = name
                    break
            if not secret_value:
                secret_value = m.group(0)

            # Line number of the secret's start (or the whole match if no secret group).
            # Use the actual matched group name — if `secret_unquoted` matched
            # but `secret` didn't, we want the offset of `secret_unquoted`.
            if secret_group_used:
                try:
                    secret_start = m.start(secret_group_used)
                except (IndexError, ValueError):
                    secret_start = m.start()
            else:
                secret_start = m.start()
            line_no = offset_to_line(secret_start)

            # Synthesize a single-line "line" string for the analyzer.
            # For multi-line patterns we collapse internal newlines so the
            # reported line_content stays readable.
            matched_text = m.group(0).replace("\n", " ").strip()

            # Reuse compute_confidence by constructing a fake "line" that
            # contains the matched span; analyze_line is line-oriented so
            # we'd have to bypass it. Inline the scoring here:
            try:
                from .analyzer import (compute_confidence, _trim_context_line,
                                       _trim_line_around_secret, _mask_secret)
            except ImportError:
                from hardcorde.analyzer import (compute_confidence,
                                                _trim_context_line,
                                                _trim_line_around_secret,
                                                _mask_secret)

            ctx_start = max(0, line_no - 1 - context_window)
            ctx_end = min(len(lines), line_no + context_window)
            context_before_raw = [l.rstrip("\n\r") for l in lines[ctx_start:line_no - 1]]
            context_after_raw = [l.rstrip("\n\r") for l in lines[line_no:ctx_end]]

            confidence, entropy, breakdown = compute_confidence(
                rule=rule, secret_value=secret_value, line=matched_text,
                file_path=file_info.path,
                context_lines=context_before_raw + context_after_raw,
            )
            if confidence < min_confidence:
                continue

            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category.value,
                severity=rule.severity.value,
                description=rule.description,
                file_path=file_info.path,
                line_number=line_no,
                line_content=_trim_line_around_secret(matched_text, secret_value),
                secret_value=secret_value,
                secret_masked=_mask_secret(secret_value),
                confidence=confidence,
                entropy=entropy,
                context_before=[_trim_context_line(l) for l in context_before_raw],
                context_after=[_trim_context_line(l) for l in context_after_raw],
                tags=list(rule.tags),
                score_breakdown=breakdown,
            ))
    return findings


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

    Two passes:
      1. Single-line rules — applied to each line independently with the
         fast-keyword pre-filter.
      2. Multi-line rules — applied to the joined file content; line
         numbers are recovered from match offsets.
    """
    try:
        lines = read_file_lines(file_info.path)
    except Exception as e:
        return [], 0, str(e)

    if not lines:
        return [], 0, None

    # Partition rules. Multi-line rules are matched against the joined file
    # content in a separate pass; line-by-line patterns can't catch them.
    line_rules = [(r, kw) for (r, kw) in prepared_rules if not r.multiline]
    multiline_rules = [(r, kw) for (r, kw) in prepared_rules if r.multiline]

    findings: list[Finding] = []

    # Pass 1: line-by-line
    for line_num_0, line in enumerate(lines):
        line_num = line_num_0 + 1  # 1-based

        # Quick pre-filter: skip very short lines
        stripped = line.strip()
        if len(stripped) < 4:
            continue

        # Lowercase once for all keyword checks on this line
        line_lower = stripped.lower()

        for rule, keywords in line_rules:
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

    # Pass 2: multi-line
    findings.extend(_scan_multiline(
        file_info=file_info,
        lines=lines,
        multiline_rules=multiline_rules,
        context_window=context_window,
        min_confidence=min_confidence,
    ))

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
