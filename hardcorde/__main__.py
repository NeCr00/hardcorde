"""
CLI entry point for hardcorde.

A credential-discovery tool for authorized penetration tests, internal
audits, and red-team engagements. On launch:

  - Auto-detects the host OS (Windows / Linux), or honors --os.
  - Runs all default checks for that OS unless they're disabled with
    a matching --no-* flag.
  - When a TARGET_PATH is supplied, also recurses through it.
  - Emits findings to text / JSON / CSV / SARIF.

Usage:
    credfinder                              # auto-detect, scan OS defaults
    credfinder /home                        # + recurse /home
    credfinder C:\\Users --os windows
    credfinder /etc --no-cred-stores --no-filename-patterns
    credfinder . -f sarif -o findings.sarif
"""

import argparse
import os
import platform
import sys
import threading

try:
    from . import __version__
    from .engine import EngineConfig, run_scan, SEVERITY_RANK
    from .scanner import ScanConfig
    from .reporter import (
        TerminalReporter, JSONReporter, CSVReporter, HTMLReporter,
        SARIFReporter, Colors, _c, _supports_color,
    )
    from .common_paths import (
        get_windows_common_paths, get_linux_common_paths,
        resolve_common_paths, ScanTarget,
    )
    from .cred_stores import (
        discover_cred_stores, discover_filename_patterns, hit_to_finding,
    )
except ImportError:
    from hardcorde import __version__
    from hardcorde.engine import EngineConfig, run_scan, SEVERITY_RANK
    from hardcorde.scanner import ScanConfig
    from hardcorde.reporter import (
        TerminalReporter, JSONReporter, CSVReporter, HTMLReporter,
        SARIFReporter, Colors, _c, _supports_color,
    )
    from hardcorde.common_paths import (
        get_windows_common_paths, get_linux_common_paths,
        resolve_common_paths, ScanTarget,
    )
    from hardcorde.cred_stores import (
        discover_cred_stores, discover_filename_patterns, hit_to_finding,
    )


# ── OS detection ─────────────────────────────────────────────────────

def detect_os(override: str = "auto") -> str:
    """
    Resolve the OS for default-check selection.
    Returns one of: "windows", "linux".

    macOS maps to "linux" because the Linux defaults (dotfiles, /etc,
    SSH keys, shell history) cover the same ground on Darwin.
    """
    if override and override != "auto":
        return override
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    # linux, darwin, freebsd, etc → use the linux check set
    return "linux"


def _init_windows_ansi():
    """Enable ANSI escape codes on Windows 10+ terminals."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            handle = kernel32.GetStdHandle(-12)
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


# ── Argument parser ──────────────────────────────────────────────────

def _add_bool_flag(parser, name: str, default: bool, help_on: str, help_off: str = None):
    """
    Add a paired --foo / --no-foo flag with a single dest.
    The default is `default`; the user can flip it either way.
    """
    dest = name.replace("-", "_")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        f"--{name}", dest=dest, action="store_true", default=default,
        help=help_on + (" (default)" if default else ""),
    )
    grp.add_argument(
        f"--no-{name}", dest=dest, action="store_false",
        help=help_off or f"disable: {help_on.lower()}",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="credfinder",
        description=(
            "HARDCORDE v{ver} — credential discovery for authorized\n"
            "penetration tests, internal audits, and red-team engagements.\n"
            "\n"
            "Detects hardcoded passwords, API keys, tokens, connection\n"
            "strings, password-manager databases, and credential-suggestive\n"
            "filenames on Windows and Linux."
        ).format(ver=__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              auto-detect OS, scan defaults
  %(prog)s /home                        + recurse /home
  %(prog)s C:\\Users --os windows
  %(prog)s /etc --no-cred-stores
  %(prog)s . -f sarif -o report.sarif
  %(prog)s /var/www --add-ext .erb,.go
  %(prog)s /opt --ext .env,.yml,.json   only these extensions
""",
    )

    # ── Positional ──
    p.add_argument(
        "target", nargs="?", metavar="TARGET_PATH", default=None,
        help="Optional root directory to recurse into (e.g. C:\\Users, /home). "
             "If omitted, only the OS-default-location checks run.",
    )

    # ── OS / scope ──
    scope = p.add_argument_group("scope")
    scope.add_argument(
        "--os", choices=["windows", "linux", "auto"], default="auto",
        help="Override OS detection (default: auto).",
    )

    # ── Default checks (paired --foo / --no-foo) ──
    checks = p.add_argument_group(
        "default checks (all on; disable with the matching --no-* flag)"
    )
    # OS-default-location checks: each is ON by default but only fires
    # when the resolved OS matches. The handler enforces that.
    _add_bool_flag(checks, "win-common", True,
                   "scan well-known Windows credential locations (registry "
                   "exports, unattend, IIS, .aws, PSReadLine, etc.)")
    _add_bool_flag(checks, "linux-common", True,
                   "scan well-known Linux credential locations (dotfiles, "
                   "/etc, SSH keys, shell history, /var/www, etc.)")
    _add_bool_flag(checks, "scan-target", True,
                   "recursive content scan of TARGET_PATH (active only when "
                   "TARGET_PATH is provided)")
    _add_bool_flag(checks, "cred-stores", True,
                   "discover password-manager / vault files by extension "
                   "(.kdbx, .psafe3, .agilekeychain, .keychain, …)")
    _add_bool_flag(checks, "filename-patterns", True,
                   "flag files whose name suggests credentials (password, "
                   "secret, id_rsa, htpasswd, …)")

    # ── Output ──
    out = p.add_argument_group("output options")
    out.add_argument(
        "-f", "--format",
        choices=["text", "terminal", "json", "csv", "sarif", "html"],
        default="text",
        help="Output format. 'text' (alias 'terminal') is the default; "
             "'sarif' produces SARIF 2.1.0 for security pipelines.",
    )
    out.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    out.add_argument("--no-color", action="store_true", help="Disable colored output.")
    out.add_argument("--no-context", action="store_true",
                     help="Hide context lines around findings.")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Suppress progress output.")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Show confidence-score breakdown for each finding.")

    # ── Filtering ──
    filt = p.add_argument_group("filtering options")
    filt.add_argument("--min-confidence", type=int, default=25, metavar="N",
                      help="Minimum confidence to report (0-100, default: 25).")
    filt.add_argument(
        "--severity", default="info",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: info).")
    filt.add_argument("--category", nargs="+", metavar="CAT",
                      help="Only report these categories (password, api_key, "
                           "token, …).")
    filt.add_argument("--tags", nargs="+", metavar="TAG",
                      help="Only run rules with these tags.")
    filt.add_argument("--rules", nargs="+", metavar="ID",
                      help="Only run these rule IDs.")
    filt.add_argument("--exclude-rules", nargs="+", metavar="ID",
                      help="Exclude these rule IDs.")

    # ── Tuning ──
    tune = p.add_argument_group("tuning options")
    tune.add_argument(
        "--max-size", type=int, default=10 * 1024 * 1024, metavar="BYTES",
        help="Skip files larger than this (default: 10485760 = 10 MB).")
    tune.add_argument(
        "--include-binary", action="store_true",
        help="Include binary files in content scanning (default: skip).")
    tune.add_argument(
        "--ext", metavar="LIST",
        help="Override the default extension allowlist for content scanning. "
             "Comma- or space-separated, e.g. '.env,.yml,.json'.")
    tune.add_argument(
        "--add-ext", metavar="LIST",
        help="Extend the default extension allowlist. Same syntax as --ext.")
    tune.add_argument(
        "--max-depth", type=int, default=50, metavar="N",
        help="Maximum directory recursion depth (default: 50).")
    tune.add_argument("--follow-symlinks", action="store_true",
                      help="Follow symbolic links.")
    tune.add_argument("--high-value-only", action="store_true",
                      help="Only scan files with high-value extensions/names.")
    tune.add_argument("--skip-dirs", nargs="+", metavar="DIR", default=[],
                      help="Additional directory names to skip.")
    tune.add_argument("--skip-ext", nargs="+", metavar="EXT", default=[],
                      help="Additional extensions to skip (e.g. .log .tmp).")
    tune.add_argument("--include-dirs", nargs="+", metavar="DIR", default=[],
                      help="Override the built-in skip list for these dirs.")
    tune.add_argument("-t", "--threads", type=int, default=4, metavar="N",
                      help="Concurrent scanner workers (default: 4).")

    # ── Misc ──
    p.add_argument("--list-rules", action="store_true",
                   help="List all detection rules and exit.")
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


# ── List rules helper ────────────────────────────────────────────────

def _list_rules():
    """Print all available detection rules."""
    try:
        from .rules import ALL_RULES
    except ImportError:
        from hardcorde.rules import ALL_RULES
    use_color = _supports_color()
    sev_colors = {
        "critical": Colors.BG_RED + Colors.WHITE,
        "high":     Colors.RED,
        "medium":   Colors.YELLOW,
        "low":      Colors.CYAN,
        "info":     Colors.GRAY,
    }
    print(f"\n{'ID':<45} {'SEVERITY':<12} {'CATEGORY':<22} TAGS")
    print("-" * 110)
    for r in sorted(ALL_RULES, key=lambda x: (SEVERITY_RANK.get(x.severity.value, 4), x.id)):
        sev = r.severity.value
        sev_display = _c(sev_colors.get(sev, ""), sev.upper(), use_color)
        tags = ", ".join(r.tags) if r.tags else ""
        padding = " " * (12 - len(sev))
        print(f"  {r.id:<43} {sev_display}{padding} {r.category.value:<22} {tags}")
    print(f"\nTotal: {len(ALL_RULES)} rules\n")


def _progress_printer(quiet: bool, use_color: bool):
    """Return a progress callback function."""
    lock = threading.Lock()

    def callback(file_path: str, done: int, total: int):
        if quiet:
            return
        with lock:
            pct = (done / total * 100) if total else 0
            display_path = file_path
            if len(display_path) > 60:
                display_path = "..." + display_path[-57:]
            bar_len = 30
            filled = int(bar_len * done / total) if total else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            line = f"\r  [{bar}] {pct:5.1f}% ({done}/{total}) {display_path:<62}"
            sys.stderr.write(line)
            sys.stderr.flush()
            if done == total:
                sys.stderr.write("\n")

    return callback


# ── Helpers for --ext / --add-ext parsing ────────────────────────────

def _parse_ext_list(raw: str) -> frozenset[str]:
    """Parse '.env,.yml .json' → {'.env', '.yml', '.json'} (lowercased, dot-prefixed)."""
    if not raw:
        return frozenset()
    out = set()
    for tok in raw.replace(",", " ").split():
        tok = tok.strip().lower()
        if not tok:
            continue
        if not tok.startswith("."):
            tok = "." + tok
        out.add(tok)
    return frozenset(out)


# ── Main ─────────────────────────────────────────────────────────────

def main(argv: list[str] = None) -> int:
    _init_windows_ansi()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _list_rules()
        return 0

    # Validate target
    if args.target and not os.path.exists(args.target):
        print(f"Error: path does not exist: {args.target}", file=sys.stderr)
        return 1

    use_color = not args.no_color and _supports_color()
    # Translate "terminal" → "text" without breaking older invocations
    fmt = "text" if args.format == "terminal" else args.format

    # Resolve OS
    target_os = detect_os(args.os)

    # Decide which OS-default-location check actually runs.
    # The check is gated on BOTH the --(no-)*-common flag AND the
    # active OS — we never run Linux defaults on a Windows host
    # unless the user explicitly --os linux + --linux-common.
    do_win_common = args.win_common and target_os == "windows"
    do_linux_common = args.linux_common and target_os == "linux"

    do_target = args.scan_target and bool(args.target)
    do_cred_stores = args.cred_stores
    do_filename_patterns = args.filename_patterns

    # If the user disabled literally everything, bail with a clear msg
    if not any([do_win_common, do_linux_common, do_target,
                do_cred_stores, do_filename_patterns]):
        parser.error(
            "all checks are disabled — nothing to do. Pass a TARGET_PATH "
            "or re-enable at least one check."
        )

    # Banner (only for the human-facing format)
    if not args.quiet and fmt == "text" and not args.output:
        sys.stderr.write(_c(Colors.BOLD + Colors.CYAN, """
  ██╗  ██╗ █████╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
  ███████║███████║██████╔╝██║  ██║██║     ██║   ██║██████╔╝██║  ██║█████╗
  ██╔══██║██╔══██║██╔══██╗██║  ██║██║     ██║   ██║██╔══██╗██║  ██║██╔══╝
  ██║  ██║██║  ██║██║  ██║██████╔╝╚██████╗╚██████╔╝██║  ██║██████╔╝███████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
""", use_color))
        sys.stderr.write(_c(
            Colors.DIM,
            f"  v{__version__} — Credential Discovery for Authorized Assessments\n"
            f"  OS: {target_os} (detected={detect_os('auto')}"
            f"{', user-overridden' if args.os != 'auto' else ''})\n\n",
            use_color,
        ))
        # Brief summary of which checks are active
        active = []
        if do_win_common:        active.append("win-common")
        if do_linux_common:      active.append("linux-common")
        if do_target:            active.append(f"scan-target={args.target}")
        if do_cred_stores:       active.append("cred-stores")
        if do_filename_patterns: active.append("filename-patterns")
        sys.stderr.write(_c(Colors.DIM, f"  Active checks: {', '.join(active)}\n\n", use_color))

    # ── Build base scan config ───────────────────────────────────────
    ext_override = _parse_ext_list(args.ext) if args.ext else frozenset()
    ext_extra    = _parse_ext_list(args.add_ext) if args.add_ext else frozenset()

    base_scan_config = ScanConfig(
        max_file_size=args.max_size,
        max_depth=args.max_depth,
        follow_symlinks=args.follow_symlinks,
        extra_skip_dirs=args.skip_dirs,
        extra_skip_extensions=[e if e.startswith(".") else f".{e}"
                               for e in args.skip_ext],
        include_dirs=args.include_dirs,
        only_high_value=args.high_value_only,
        include_binary=args.include_binary,
        ext_override=ext_override,
        ext_extra=ext_extra,
    )

    base_engine_config = EngineConfig(
        scan_config=base_scan_config,
        min_confidence=args.min_confidence,
        threads=args.threads,
        rule_ids=args.rules,
        exclude_rules=args.exclude_rules,
        categories=args.category,
        tags=args.tags,
        severity_min=args.severity,
    )

    progress = _progress_printer(args.quiet, use_color)

    all_findings = []
    total_files = 0
    scanned_roots: set[str] = set()
    cred_store_roots: list[str] = []

    # ── Phase 1: User TARGET_PATH ─────────────────────────────────────
    if do_target:
        abspath = os.path.abspath(args.target)
        scanned_roots.add(abspath)
        cred_store_roots.append(abspath)

        if not args.quiet:
            sys.stderr.write(f"  [scan-target] Scanning: {abspath}\n")

        findings, stats = run_scan(args.target, base_engine_config,
                                   progress_callback=progress)
        all_findings.extend(findings)
        total_files += stats.files_scanned

        if not args.quiet:
            sys.stderr.write(
                f"  Files: {stats.files_scanned} scanned, "
                f"{stats.files_error} errors, "
                f"{stats.lines_scanned:,} lines, "
                f"{stats.elapsed_seconds:.1f}s\n"
            )

    # ── Phase 2: OS-default credential locations ─────────────────────
    common_targets: list[ScanTarget] = []
    if do_win_common:
        common_targets.extend(get_windows_common_paths())
    if do_linux_common:
        common_targets.extend(get_linux_common_paths())

    if common_targets:
        resolved = resolve_common_paths(common_targets)

        if not args.quiet and resolved:
            label = []
            if do_win_common:   label.append("Windows")
            if do_linux_common: label.append("Linux")
            sys.stderr.write(
                f"  [common] {' + '.join(label)}: "
                f"{len(resolved)} paths matched\n"
            )

        for path, target in resolved:
            if path in scanned_roots:
                continue
            if any(path.startswith(s + os.sep) or path == s for s in scanned_roots):
                continue
            scanned_roots.add(path)
            cred_store_roots.append(path)

            target_scan_config = ScanConfig(
                max_file_size=base_scan_config.max_file_size,
                max_depth=target.max_depth,
                follow_symlinks=False,
                extra_skip_dirs=base_scan_config.extra_skip_dirs,
                extra_skip_extensions=list(base_scan_config.extra_skip_extensions),
                include_dirs=list(base_scan_config.include_dirs),
                only_high_value=target.high_value_only,
                include_binary=base_scan_config.include_binary,
                ext_override=base_scan_config.ext_override,
                ext_extra=base_scan_config.ext_extra,
            )
            target_engine_config = EngineConfig(
                scan_config=target_scan_config,
                min_confidence=base_engine_config.min_confidence,
                threads=base_engine_config.threads,
                rule_ids=base_engine_config.rule_ids,
                exclude_rules=base_engine_config.exclude_rules,
                categories=base_engine_config.categories,
                tags=base_engine_config.tags,
                severity_min=base_engine_config.severity_min,
            )

            if not args.quiet:
                display = path
                if len(display) > 55:
                    display = "..." + display[-52:]
                sys.stderr.write(f"  [{target.category}] {display}\n")

            findings, stats = run_scan(path, target_engine_config, progress_callback=None)
            all_findings.extend(findings)
            total_files += stats.files_scanned

    # ── Phase 3: Credential-store file discovery ─────────────────────
    # Scopes:
    #   - explicit TARGET_PATH (if any)
    #   - resolved OS-default roots (if any)
    if do_cred_stores and cred_store_roots:
        if not args.quiet:
            sys.stderr.write(f"  [cred-stores] scanning {len(cred_store_roots)} root(s) "
                             f"for password-manager files\n")
        store_hits = discover_cred_stores(
            cred_store_roots,
            max_depth=args.max_depth,
            follow_symlinks=args.follow_symlinks,
            extra_skip_dirs=args.skip_dirs,
        )
        if not args.quiet and store_hits:
            sys.stderr.write(f"             {len(store_hits)} store file(s) found\n")
        for hit in store_hits:
            all_findings.append(hit_to_finding(hit))

    # ── Phase 4: Suspicious filename-pattern discovery ───────────────
    if do_filename_patterns and cred_store_roots:
        if not args.quiet:
            sys.stderr.write(
                f"  [filename-patterns] scanning {len(cred_store_roots)} root(s) "
                "for credential-suggestive filenames\n"
            )
        # Dedup: don't double-flag a file that's already a cred-store hit.
        already = {f.file_path for f in all_findings if f.rule_id == "CRED_STORE_FILE"}
        name_hits = discover_filename_patterns(
            cred_store_roots,
            max_depth=args.max_depth,
            follow_symlinks=args.follow_symlinks,
            max_size=args.max_size,
            include_binary=args.include_binary,
            extra_skip_dirs=args.skip_dirs,
        )
        kept = [h for h in name_hits if h.path not in already]
        if not args.quiet and kept:
            sys.stderr.write(f"                       {len(kept)} filename match(es)\n")
        for hit in kept:
            all_findings.append(hit_to_finding(hit))

    # Final ordering: severity then confidence
    all_findings.sort(
        key=lambda f: (SEVERITY_RANK.get(f.severity, 4), -f.confidence)
    )

    # ── Output ───────────────────────────────────────────────────────
    output_stream = sys.stdout
    if args.output:
        output_stream = open(args.output, "w", encoding="utf-8")

    try:
        parts = []
        if args.target:
            parts.append(os.path.abspath(args.target))
        if do_win_common:
            parts.append("[Windows OS defaults]")
        if do_linux_common:
            parts.append("[Linux OS defaults]")
        target_display = ", ".join(parts) if parts else "[no targets]"

        if fmt == "text":
            reporter = TerminalReporter(
                stream=output_stream,
                show_context=not args.no_context,
                use_color=use_color and not args.output,
                min_confidence=args.min_confidence,
                verbose=args.verbose,
            )
            reporter.report_header(target_display, total_files)
            for i, finding in enumerate(all_findings, 1):
                reporter.report_finding(finding, i)
            reporter.report_summary(all_findings)
        elif fmt == "json":
            JSONReporter(stream=output_stream, min_confidence=args.min_confidence
                         ).report(all_findings, target_display, total_files)
        elif fmt == "csv":
            CSVReporter(stream=output_stream, min_confidence=args.min_confidence
                        ).report(all_findings, target_display, total_files)
        elif fmt == "sarif":
            SARIFReporter(stream=output_stream, min_confidence=args.min_confidence
                          ).report(all_findings, target_display, total_files)
        elif fmt == "html":
            HTMLReporter(stream=output_stream, min_confidence=args.min_confidence
                         ).report(all_findings, target_display, total_files)
    finally:
        if args.output and output_stream is not sys.stdout:
            output_stream.close()
            if not args.quiet:
                sys.stderr.write(f"\n  Report written to: {args.output}\n")

    # Exit code: 1 if any high+ findings remained, else 0.
    high_plus = [
        f for f in all_findings
        if f.confidence >= args.min_confidence
        and SEVERITY_RANK.get(f.severity, 4) <= 1
    ]
    return 1 if high_plus else 0


if __name__ == "__main__":
    sys.exit(main())
