"""
CLI entry point for hardcorde.

A focused tool for finding hardcoded **passwords** and password+username
pairs in source, configs, scripts, and OS-default credential locations.
By design it does NOT search for API keys, OAuth tokens, JWTs, PEM private
keys, generic high-entropy secrets, or vault files — that's what generic
secret scanners do, and they generate too much noise on real engagements.

Usage:
    hardcorde                              # auto-detect OS, scan defaults
    hardcorde /home                        # + recurse /home
    hardcorde C:\\Users --os windows
    hardcorde /etc --no-linux-common
    hardcorde . -f sarif -o out.sarif
"""

import argparse
import os
import platform
import sys
import threading

# Force UTF-8 on the Windows console so the box-drawing glyphs in the
# banner / progress bar don't crash with cp1252 encode errors.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

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


# ── OS detection ─────────────────────────────────────────────────────

def detect_os(override: str = "auto") -> str:
    """
    Resolve the OS for default-check selection.
    Returns one of: "windows", "linux".
    macOS and other Unix-likes map to "linux" (the dotfile / /etc layout
    is the same).
    """
    if override and override != "auto":
        return override
    s = platform.system().lower()
    if s == "windows":
        return "windows"
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

def _add_bool_flag(parser, name: str, default: bool, help_on: str):
    """Paired --foo / --no-foo flag with a single dest."""
    dest = name.replace("-", "_")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        f"--{name}", dest=dest, action="store_true", default=default,
        help=help_on + (" (default)" if default else ""),
    )
    grp.add_argument(
        f"--no-{name}", dest=dest, action="store_false", default=default,
        help=f"disable: {help_on.lower()}",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardcorde",
        description=(
            "HARDCORDE v{ver} — hardcoded password discovery for authorized\n"
            "penetration tests. Finds passwords and password+username pairs\n"
            "in source code, configs, scripts, and OS-default credential\n"
            "locations on Windows and Linux. Does NOT scan for API keys,\n"
            "tokens, JWTs, or PEM private keys."
        ).format(ver=__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              auto-detect OS, scan defaults
  %(prog)s /home                        + recurse /home
  %(prog)s C:\\Users --os windows
  %(prog)s /etc --no-linux-common       only scan /etc, skip OS sweep
  %(prog)s . -f sarif -o report.sarif
  %(prog)s /opt --severity high -q      high+ only, quiet
""",
    )

    # ── Positional ──
    p.add_argument(
        "target", nargs="?", metavar="TARGET_PATH", default=None,
        help="Optional root directory to recurse into (e.g. C:\\Users, /home). "
             "If omitted, only the OS-default-location sweep runs.",
    )

    # ── Scope ──
    scope = p.add_argument_group("scope")
    scope.add_argument(
        "--os", choices=["windows", "linux", "auto"], default="auto",
        help="Override OS detection (default: auto).",
    )
    _add_bool_flag(scope, "win-common", True,
                   "scan well-known Windows password locations (registry "
                   "exports, unattend, IIS, .aws, PSReadLine, PuTTY/WinSCP, "
                   "SYSVOL/GPP, …)")
    _add_bool_flag(scope, "linux-common", True,
                   "scan well-known Linux password locations (shadow, "
                   "sudoers, .pgpass, .netrc, .my.cnf, shell history, "
                   "/etc, /var/www, web/auth-server configs, …)")
    _add_bool_flag(scope, "scan-target", True,
                   "recursive content scan of TARGET_PATH (active only "
                   "when TARGET_PATH is provided)")

    # ── Output ──
    out = p.add_argument_group("output")
    out.add_argument(
        "-f", "--format",
        choices=["text", "terminal", "json", "csv", "sarif", "html"],
        default="text",
        help="Output format (default: text).")
    out.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.")
    out.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colors.")
    out.add_argument("--no-context", action="store_true",
                     help="Hide surrounding context lines.")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Suppress progress output.")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Show confidence-score breakdown for each finding.")

    # ── Filtering ──
    filt = p.add_argument_group("filtering")
    filt.add_argument("--min-confidence", type=int, default=25, metavar="N",
                      help="Minimum confidence (0-100, default: 25).")
    filt.add_argument(
        "--severity", default="info",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: info).")

    # ── Tuning ──
    tune = p.add_argument_group("tuning")
    tune.add_argument(
        "--max-size", type=int, default=10 * 1024 * 1024, metavar="BYTES",
        help="Skip files larger than this (default: 10 MB).")
    tune.add_argument(
        "--max-depth", type=int, default=50, metavar="N",
        help="Maximum directory recursion depth (default: 50).")
    tune.add_argument(
        "--include-binary", action="store_true",
        help="Include binary files in content scanning.")
    tune.add_argument(
        "--ext", metavar="LIST",
        help="Override the default extension allowlist for content scanning. "
             "Comma- or space-separated, e.g. '.env,.yml,.json'.")
    tune.add_argument(
        "--add-ext", metavar="LIST",
        help="Extend the default extension allowlist.")
    tune.add_argument("--skip-dirs", nargs="+", metavar="DIR", default=[],
                      help="Additional directory names to skip.")
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
    """Print all available password detection rules."""
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
    print(f"\n{'ID':<45} {'SEVERITY':<12} TAGS")
    print("-" * 100)
    for r in sorted(ALL_RULES, key=lambda x: (SEVERITY_RANK.get(x.severity.value, 4), x.id)):
        sev = r.severity.value
        sev_display = _c(sev_colors.get(sev, ""), sev.upper(), use_color)
        tags = ", ".join(r.tags) if r.tags else ""
        padding = " " * (12 - len(sev))
        print(f"  {r.id:<43} {sev_display}{padding} {tags}")
    print(f"\nTotal: {len(ALL_RULES)} password rules\n")


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


def _parse_ext_list(raw: str) -> frozenset[str]:
    """Parse '.env,.yml .json' → {'.env', '.yml', '.json'}."""
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

    if args.target and not os.path.exists(args.target):
        print(f"Error: path does not exist: {args.target}", file=sys.stderr)
        return 1

    use_color = not args.no_color and _supports_color()
    fmt = "text" if args.format == "terminal" else args.format

    target_os = detect_os(args.os)

    # OS-default sweeps are gated on BOTH the flag and the active OS.
    do_win_common = args.win_common and target_os == "windows"
    do_linux_common = args.linux_common and target_os == "linux"
    do_target = args.scan_target and bool(args.target)

    if not (do_win_common or do_linux_common or do_target):
        parser.error(
            "nothing to scan — pass a TARGET_PATH or re-enable an "
            "OS-default sweep (--win-common / --linux-common)."
        )

    # Banner (only for the human-facing format, no --output redirect)
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
            f"  v{__version__} — Hardcoded Password Discovery (passwords only)\n"
            f"  OS: {target_os}"
            f"{' (user-overridden)' if args.os != 'auto' else ''}\n\n",
            use_color,
        ))

    # ── Build scan config ────────────────────────────────────────────
    ext_override = _parse_ext_list(args.ext) if args.ext else frozenset()
    ext_extra    = _parse_ext_list(args.add_ext) if args.add_ext else frozenset()

    base_scan_config = ScanConfig(
        max_file_size=args.max_size,
        max_depth=args.max_depth,
        follow_symlinks=False,
        extra_skip_dirs=args.skip_dirs,
        include_binary=args.include_binary,
        ext_override=ext_override,
        ext_extra=ext_extra,
    )

    base_engine_config = EngineConfig(
        scan_config=base_scan_config,
        min_confidence=args.min_confidence,
        threads=args.threads,
        severity_min=args.severity,
    )

    progress = _progress_printer(args.quiet, use_color)

    all_findings = []
    total_files = 0
    scanned_roots: set[str] = set()

    # ── Phase 1: explicit TARGET_PATH ────────────────────────────────
    if do_target:
        abspath = os.path.abspath(args.target)
        scanned_roots.add(abspath)

        if not args.quiet:
            sys.stderr.write(f"  [scan-target] {abspath}\n")

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

    # ── Phase 2: OS-default password locations ───────────────────────
    common_targets: list[ScanTarget] = []
    if do_win_common:
        common_targets.extend(get_windows_common_paths())
    if do_linux_common:
        common_targets.extend(get_linux_common_paths())

    if common_targets:
        resolved = resolve_common_paths(common_targets)
        if not args.quiet and resolved:
            label = "Windows" if do_win_common else "Linux"
            sys.stderr.write(
                f"  [common] {label}: {len(resolved)} paths matched\n"
            )

        for path, target in resolved:
            if path in scanned_roots:
                continue
            if any(path.startswith(s + os.sep) or path == s for s in scanned_roots):
                continue
            scanned_roots.add(path)

            target_scan_config = ScanConfig(
                max_file_size=base_scan_config.max_file_size,
                max_depth=target.max_depth,
                follow_symlinks=False,
                extra_skip_dirs=base_scan_config.extra_skip_dirs,
                only_high_value=target.high_value_only,
                include_binary=base_scan_config.include_binary,
                ext_override=base_scan_config.ext_override,
                ext_extra=base_scan_config.ext_extra,
            )
            target_engine_config = EngineConfig(
                scan_config=target_scan_config,
                min_confidence=base_engine_config.min_confidence,
                threads=base_engine_config.threads,
                severity_min=base_engine_config.severity_min,
            )

            if not args.quiet:
                display = path if len(path) <= 55 else "..." + path[-52:]
                sys.stderr.write(f"  [{target.category}] {display}\n")

            findings, stats = run_scan(path, target_engine_config, progress_callback=None)
            all_findings.extend(findings)
            total_files += stats.files_scanned

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
