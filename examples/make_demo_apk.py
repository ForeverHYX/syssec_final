from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.fixtures import build_hardened_apk  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    output = Path(args[0]) if args else ROOT / "samples" / "demo_hardened.apk"
    output.parent.mkdir(parents=True, exist_ok=True)
    build_hardened_apk(output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

