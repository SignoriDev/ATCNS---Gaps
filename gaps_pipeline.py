"""
GAPS analysis pipeline
"""

import argparse
import os
from pathlib import Path

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GAPS analysis pipeline",
    )

    parser.add_argument(
        "--apk-limit",
        type=int,
        default=67,
        help="Number of APKs to process (default: %(default)s).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=6,
        help="Number of paraller workers (default: %(default)s).",
    )
    parser.add_argument(
        "--gaps-dir",
        type=Path,
        default=Path(os.environ.get("GAPS_DIR", "GAPS-main")),
        metavar="PATH",
        help="Root directory of the GAPS tool (default: %(default)s).",
    )
    parser.add_argument(
        "--gaps-output-dir",
        type=Path,
        default=Path(os.environ.get("GAPS_OUTPUT_DIR", "gaps_output")),
        metavar="PATH",
        help="Directory where GAPS writes its output (default: %(default)s).",
    )
    parser.add_argument(
        "--gaps-path-limit",
        type=int,
        default=int(os.environ.get("GAPS_PATH_LIMIT", 1000)),
        help="Max paths for GAPS static analysis (default: %(default)s).",
    )
    parser.add_argument(
        "--parser-use-conditional",
        action=argparse.BooleanOptionalAction,
        default=bool(int(os.environ.get("GAPS_USE_CONDITIONAL", 1))),
        help="Pass -cond flag to GAPS static (default: enabled).",
    )
    parser.add_argument(
        "--gaps-manual-setup",
        action=argparse.BooleanOptionalAction,
        default=bool(int(os.environ.get("GAPS_MANUAL_SETUP", 0))),
        help="Pass -ms flag to GAPS dynamic (default: disabled).",
    )
    parser.add_argument(
        "--adb-serial",
        default=os.environ.get("ADB_SERIAL", "emulator-5554"),
        metavar="SERIAL",
        help="ADB device serial (default: %(default)s).",
    )
    parser.add_argument(
        "--apks-dir",
        type=Path,
        default=Path("apks"),
        metavar="PATH",
        help="Directory containing input APK files (default: %(default)s).",
    )
    parser.add_argument(
        "--gt-dir",
        type=Path,
        default=Path("all_gen_gt_classes"),
        metavar="PATH",
        help="Directory containing ground truth class files (default: %(default)s).",
    )

    return parser.parse_args()

def main() -> int:
    args = parse_args()
    print("gaps_pipeline: OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())