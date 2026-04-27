"""
CLI entry point for hardcorde.

Usage:
    python -m hardcorde /path/to/scan
    hardcorde /path/to/scan --format json --output report.json
    hardcorde --linux-common
    hardcorde --win-common /path/to/scan
"""

import argparse
import os
import sys
import threading

try:
    from . import __version__
    from .engine import EngineConfig, run_scan, SEVERITY_RANK
    from .scanner import ScanConfig
    from .reporter import (
        TerminalReporter, JSONReporter, CSVReporter, HTMLReporter,
        Colors, _c, _supports_color,
    )
    from .common_paths import (
        get_windows_common_paths, get_linux_common_paths,
        resolve_common_paths, ScanTarget,
    )
except ImportError:
    from hardcorde import __version__
    from hardcorde.engine import EngineConfig, run_scan, SEVERITY_RANK
    from hardcorde.scanner import ScanConfig
    from hardcorde.reporter import (
        TerminalReporter, JSONReporter, CSVReporter, HTMLReporter,
        Colors, _c, _supports_color,
    )
    from hardcorde.common_paths import (
        get_windows_common_paths, get_linux_common_paths,
        resolve_common_paths, ScanTarget,
    )


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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardcorde",
        description=(
            "HARDCORDE v{ver} - High-confidence credential discovery\n"
            "for authorized penetration tests and legal lab environments.\n"
            "\n"
            "Recursively scans filesystems for hardcoded credentials,\n"
            "API keys, tokens, connection strings, and other secrets."
        ).format(ver=__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/www                    # Scan web root
  %(prog)s C:\\inetpub /home           # Scan multiple paths
  %(prog)s . -f json -o report.json    # JSON output to file
  %(prog)s --linux-common              # Scan common Linux cred locations
  %(prog)s --win-common                # Scan common Windows cred locations
  %(prog)s /opt --linux-common         # User path + Linux common locations
  %(prog)s . --win-common -f html -o r.html
  %(prog)s /etc --severity high        # Only HIGH and CRITICAL
  %(prog)s . --high-value-only         # Only config/secret files
  %(prog)s . --verbose                 # Show scoring breakdown
""",
    )

    p.add_argument(
        "targets", nargs="*", metavar="PATH",
        help="File or directory paths to scan",
    )

    # Common location scanning
    common = p.add_argument_group("common credential locations")
    common.add_argument(
        "--win-common", action="store_true",
        help="Add common Windows credential locations to the scan",
    )
    common.add_argument(
        "--linux-common", action="store_true",
        help="Add common Linux credential locations to the scan",
    )

    # Output options
    out = p.add_argument_group("output options")
    out.add_argument(
        "-f", "--format", choices=["terminal", "json", "csv", "html"],
        default="terminal", help="Output format (default: terminal)",
    )
    out.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write output to file instead of stdout",
    )
    out.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    out.add_argument(
        "--no-context", action="store_true",
        help="Hide context lines around findings",
    )
    out.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress output",
    )
    out.add_argument(
        "--verbose", action="store_true",
        help="Show confidence score breakdown for each finding",
    )

    # Filtering options
    filt = p.add_argument_group("filtering options")
    filt.add_argument(
        "--min-confidence", type=int, default=25, metavar="N",
        help="Minimum confidence score to report (0-100, default: 25)",
    )
    filt.add_argument(
        "--severity", default="info",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: info)",
    )
    filt.add_argument(
        "--category", nargs="+", metavar="CAT",
        help="Only report these categories (e.g., password api_key token)",
    )
    filt.add_argument(
        "--tags", nargs="+", metavar="TAG",
        help="Only run rules with these tags (e.g., aws cloud)",
    )
    filt.add_argument(
        "--rules", nargs="+", metavar="ID",
        help="Only run these rule IDs",
    )
    filt.add_argument(
        "--exclude-rules", nargs="+", metavar="ID",
        help="Exclude these rule IDs",
    )

    # Scanner options
    scan = p.add_argument_group("scanner options")
    scan.add_argument(
        "--max-size", type=int, default=10, metavar="MB",
        help="Maximum file size in MB (default: 10)",
    )
    scan.add_argument(
        "--max-depth", type=int, default=50, metavar="N",
        help="Maximum directory depth (default: 50)",
    )
    scan.add_argument(
        "--follow-symlinks", action="store_true",
        help="Follow symbolic links",
    )
    scan.add_argument(
        "--high-value-only", action="store_true",
        help="Only scan files with high-value extensions/names",
    )
    scan.add_argument(
        "--skip-dirs", nargs="+", metavar="DIR", default=[],
        help="Additional directories to skip",
    )
    scan.add_argument(
        "--skip-ext", nargs="+", metavar="EXT", default=[],
        help="Additional extensions to skip (e.g., .log .tmp)",
    )
    scan.add_argument(
        "--include-dirs", nargs="+", metavar="DIR", default=[],
        help="Don't skip these directories (overrides built-in skip list)",
    )

    # Performance options
    perf = p.add_argument_group("performance options")
    perf.add_argument(
        "-t", "--threads", type=int, default=4, metavar="N",
        help="Number of scanner threads (default: 4)",
    )

    # Misc
    p.add_argument(
        "-v", "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    p.add_argument(
        "--list-rules", action="store_true",
        help="List all detection rules and exit",
    )

    return p


def _list_rules():
    """Print all available detection rules."""
    try:
        from .rules import ALL_RULES
    except ImportError:
        from hardcorde.rules import ALL_RULES
    use_color = _supports_color()
    sev_colors = {
        "critical": Colors.BG_RED + Colors.WHITE,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.CYAN,
        "info": Colors.GRAY,
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


def main(argv: list[str] = None):
    _init_windows_ansi()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _list_rules()
        return 0

    # Must have at least a target or a --*-common flag
    has_common = args.win_common or args.linux_common
    if not args.targets and not has_common:
        parser.error("provide at least one PATH or use --win-common / --linux-common")

    # Validate user-supplied targets
    for target in args.targets:
        if not os.path.exists(target):
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            return 1

    use_color = not args.no_color and _supports_color()

    # Print banner
    if not args.quiet and args.format == "terminal":
        sys.stderr.write(_c(Colors.BOLD + Colors.CYAN, """
  ██╗  ██╗ █████╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
  ███████║███████║██████╔╝██║  ██║██║     ██║   ██║██████╔╝██║  ██║█████╗
  ██╔══██║██╔══██║██╔══██╗██║  ██║██║     ██║   ██║██╔══██╗██║  ██║██╔══╝
  ██║  ██║██║  ██║██║  ██║██████╔╝╚██████╗╚██████╔╝██║  ██║██████╔╝███████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
""", use_color))
        sys.stderr.write(
            _c(Colors.DIM, f"  v{__version__} - Credential Discovery for Authorized Assessments\n\n",
               use_color)
        )

    # Base scan config from CLI args
    base_scan_config = ScanConfig(
        max_file_size=args.max_size * 1024 * 1024,
        max_depth=args.max_depth,
        follow_symlinks=args.follow_symlinks,
        extra_skip_dirs=args.skip_dirs,
        extra_skip_extensions=[e if e.startswith(".") else f".{e}" for e in args.skip_ext],
        include_dirs=args.include_dirs,
        only_high_value=args.high_value_only,
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
    scanned_roots: set[str] = set()  # dedup across user paths + common paths

    # ── Phase 1: Scan user-supplied targets ──
    for target in args.targets:
        abspath = os.path.abspath(target)
        if abspath in scanned_roots:
            continue
        scanned_roots.add(abspath)

        if not args.quiet:
            sys.stderr.write(f"  Scanning: {abspath}\n")

        findings, stats = run_scan(target, base_engine_config, progress_callback=progress)
        all_findings.extend(findings)
        total_files += stats.files_scanned

        if not args.quiet:
            sys.stderr.write(
                f"  Files: {stats.files_scanned} scanned, "
                f"{stats.files_error} errors, "
                f"{stats.lines_scanned:,} lines, "
                f"{stats.elapsed_seconds:.1f}s\n"
            )

    # ── Phase 2: Scan common credential locations ──
    common_targets: list[ScanTarget] = []
    if args.win_common:
        common_targets.extend(get_windows_common_paths())
    if args.linux_common:
        common_targets.extend(get_linux_common_paths())

    if common_targets:
        resolved = resolve_common_paths(common_targets)

        if not args.quiet and resolved:
            scope = []
            if args.win_common:
                scope.append("Windows")
            if args.linux_common:
                scope.append("Linux")
            sys.stderr.write(
                f"  Common locations ({' + '.join(scope)}): "
                f"{len(resolved)} paths found\n"
            )

        for path, target in resolved:
            # Skip if already scanned by a user-supplied target
            if path in scanned_roots:
                continue
            # Skip if a parent of this path was already scanned
            if any(path.startswith(s + os.sep) or path == s for s in scanned_roots):
                continue
            scanned_roots.add(path)

            # Build per-target config that respects the ScanTarget's constraints
            target_scan_config = ScanConfig(
                max_file_size=base_scan_config.max_file_size,
                max_depth=target.max_depth,
                follow_symlinks=False,  # never follow symlinks in common paths
                extra_skip_dirs=base_scan_config.extra_skip_dirs,
                extra_skip_extensions=list(base_scan_config.extra_skip_extensions),
                include_dirs=list(base_scan_config.include_dirs),
                only_high_value=target.high_value_only,
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
                # Show category in progress
                display = path
                if len(display) > 55:
                    display = "..." + display[-52:]
                sys.stderr.write(
                    f"  [{target.category}] {display}\n"
                )

            findings, stats = run_scan(path, target_engine_config, progress_callback=None)
            all_findings.extend(findings)
            total_files += stats.files_scanned

    # Sort by severity then confidence
    all_findings.sort(
        key=lambda f: (SEVERITY_RANK.get(f.severity, 4), -f.confidence)
    )

    # Output
    output_stream = sys.stdout
    if args.output:
        output_stream = open(args.output, "w", encoding="utf-8")

    try:
        # Build target display string
        parts = [os.path.abspath(t) for t in args.targets]
        if args.win_common:
            parts.append("[Windows common locations]")
        if args.linux_common:
            parts.append("[Linux common locations]")
        target_display = ", ".join(parts) if parts else "[common locations]"

        if args.format == "terminal":
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

        elif args.format == "json":
            reporter = JSONReporter(
                stream=output_stream,
                min_confidence=args.min_confidence,
            )
            reporter.report(all_findings, target_display, total_files)

        elif args.format == "csv":
            reporter = CSVReporter(
                stream=output_stream,
                min_confidence=args.min_confidence,
            )
            reporter.report(all_findings, target_display, total_files)

        elif args.format == "html":
            reporter = HTMLReporter(
                stream=output_stream,
                min_confidence=args.min_confidence,
            )
            reporter.report(all_findings, target_display, total_files)
    finally:
        if args.output and output_stream is not sys.stdout:
            output_stream.close()
            if not args.quiet:
                sys.stderr.write(f"\n  Report written to: {args.output}\n")

    # Exit code: 0 if no high+ findings, 1 if any
    high_plus = [f for f in all_findings
                 if f.confidence >= args.min_confidence
                 and SEVERITY_RANK.get(f.severity, 4) <= 1]
    return 1 if high_plus else 0


if __name__ == "__main__":
    sys.exit(main())
