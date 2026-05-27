"""Command-line interface for HardenInspector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import scan_apk


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardeninspector",
        description="Static Android APK hardening-technique detector",
    )
    parser.add_argument("apk", type=Path, help="APK file to scan")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("-o", "--output", type=Path, help="write report to this file")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = scan_apk(args.apk)
    except Exception as exc:  # noqa: BLE001 - CLI should return a clean error
        print(f"hardeninspector: {exc}", file=sys.stderr)
        return 2

    output = (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        if args.json
        else report.to_text()
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
