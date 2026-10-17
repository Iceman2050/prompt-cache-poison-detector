"""CLI: run cross-tenant poisoning detection against all (or chosen) cache schemes."""
from __future__ import annotations

import argparse
import sys

from .cache_schemes import SCHEMES
from .detector import run_detection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect cache-isolation failures in multi-tenant LLM prompt caches."
    )
    parser.add_argument(
        "--scheme",
        action="append",
        default=None,
        choices=sorted(SCHEMES),
        help="Test only this scheme (repeatable). Default: all schemes.",
    )
    parser.add_argument(
        "--list-schemes", action="store_true", help="List available cache schemes and exit."
    )
    args = parser.parse_args(argv)

    if args.list_schemes:
        for name in sorted(SCHEMES):
            print(f"{name:15s} {SCHEMES[name].description}")
        return 0

    result = run_detection(args.scheme)
    print(result.report())
    return 0 if result.summary()["CONFIRMED"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
