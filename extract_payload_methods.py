#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


APK_SUFFIX = "_app-release.apk"
GT_SUFFIX = "_app.conf.gt.txt"
DEFAULT_FAILURES_FILE = "extract_payload_methods_failures.txt"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Decode APKs with apktool and extract method signatures from the "
            "payload classes listed in all_gen_gt_classes."
        )
    )
    parser.add_argument("--apks-dir", default="apks", type=Path)
    parser.add_argument("--gt-dir", default="all_gen_gt_classes", type=Path)
    parser.add_argument("--output-dir", default="output", type=Path)
    parser.add_argument("--temp-root", default=".tmp_payload_extract", type=Path)
    parser.add_argument("--framework-dir", default=".apktool-home", type=Path)
    parser.add_argument("--workers", default=max(1, min(8, os.cpu_count() or 1)), type=int)
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional random seed for reproducible APK selection order.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate outputs even if the output file already exists.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N matched applications, for testing.",
    )
    parser.add_argument(
        "--app",
        action="append",
        default=[],
        help="Specific application stem to process. Can be passed multiple times.",
    )
    parser.add_argument(
        "--failures-file",
        default=DEFAULT_FAILURES_FILE,
        type=Path,
        help="Path to write per-app extraction failures.",
    )
    return parser.parse_args()


def app_stem_from_name(name: str, suffix: str) -> str | None:
    if not name.endswith(suffix):
        return None
    return name[: -len(suffix)]


def collect_pairs(apks_dir: Path, gt_dir: Path) -> list[tuple[str, Path, Path]]:
    apk_map = {}
    for entry in apks_dir.iterdir():
        stem = app_stem_from_name(entry.name, APK_SUFFIX)
        if stem:
            apk_map[stem] = entry

    gt_map = {}
    for entry in gt_dir.iterdir():
        stem = app_stem_from_name(entry.name, GT_SUFFIX)
        if stem:
            gt_map[stem] = entry

    missing_gt = sorted(set(apk_map) - set(gt_map))
    if missing_gt:
        raise SystemExit(f"Missing localization files for {len(missing_gt)} APKs")

    pairs = [(stem, apk_map[stem], gt_map[stem]) for stem in sorted(apk_map)]
    return pairs


def normalize_class_descriptor(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    if value.startswith("#"):
        return None
    if value.startswith("L"):
        value = value[1:]
    if value.endswith(";"):
        value = value[:-1]
    return value.strip("/")


def read_target_classes(gt_path: Path) -> list[str]:
    classes = []
    seen = set()
    for line in gt_path.read_text(encoding="utf-8").splitlines():
        descriptor = normalize_class_descriptor(line)
        if descriptor and descriptor not in seen:
            seen.add(descriptor)
            classes.append(descriptor)
    return classes


def apktool_env(root: Path, framework_dir: Path, temp_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["XDG_DATA_HOME"] = str((root / framework_dir).resolve())
    env["TMPDIR"] = str((root / temp_root).resolve())
    return env


def find_smali_file(decoded_dir: Path, class_name: str) -> Path | None:
    rel_path = Path(*class_name.split("/")).with_suffix(".smali")
    for smali_dir in sorted(decoded_dir.glob("smali*")):
        candidate = smali_dir / rel_path
        if candidate.is_file():
            return candidate
    return None


def extract_signatures_from_smali(smali_path: Path) -> list[str]:
    lines = smali_path.read_text(encoding="utf-8").splitlines()
    class_descriptor = None
    signatures = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(".class ") and class_descriptor is None:
            class_descriptor = stripped.split()[-1]
            continue

        if stripped.startswith(".method ") and class_descriptor:
            signatures.append(f"{class_descriptor}->{stripped.split()[-1]}")
            continue

    return signatures


def process_one(
    root: Path,
    framework_dir: Path,
    temp_root: Path,
    output_dir: Path,
    stem: str,
    apk_path: Path,
    gt_path: Path,
) -> tuple[str, int, int]:
    target_classes = read_target_classes(gt_path)
    output_path = output_dir / f"{stem}_methods.smali"

    temp_root_abs = (root / temp_root).resolve()
    temp_root_abs.mkdir(parents=True, exist_ok=True)
    decoded_dir = Path(
        tempfile.mkdtemp(prefix=f"{stem}_", dir=str(temp_root_abs))
    )

    try:
        env = apktool_env(root, framework_dir, temp_root)
        cmd = ["apktool", "d", "-f", "-r", "-o", str(decoded_dir), str(apk_path)]
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        found_count = 0
        signatures = []
        seen_signatures = set()
        for class_name in target_classes:
            smali_path = find_smali_file(decoded_dir, class_name)
            if not smali_path:
                continue
            extracted = extract_signatures_from_smali(smali_path)
            if not extracted:
                continue
            found_count += 1
            for signature in extracted:
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    signatures.append(signature)

        output_path.write_text("\n".join(signatures).strip() + ("\n" if signatures else ""), encoding="utf-8")
        return stem, len(target_classes), found_count
    finally:
        shutil.rmtree(decoded_dir, ignore_errors=True)


def output_path_for(output_dir: Path, stem: str) -> Path:
    return output_dir / f"{stem}_methods.smali"


def main() -> int:
    args = parse_args()
    root = Path.cwd()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (root / args.framework_dir).mkdir(parents=True, exist_ok=True)
    (root / args.temp_root).mkdir(parents=True, exist_ok=True)

    pairs = collect_pairs(args.apks_dir, args.gt_dir)

    if args.app:
        requested = set(args.app)
        pairs = [pair for pair in pairs if pair[0] in requested]
        missing = requested - {pair[0] for pair in pairs}
        if missing:
            raise SystemExit(f"Requested apps not found: {', '.join(sorted(missing))}")

    if not args.overwrite:
        pairs = [
            pair
            for pair in pairs
            if not output_path_for(args.output_dir, pair[0]).exists()
        ]

    random.Random(args.seed).shuffle(pairs)

    if args.limit is not None:
        pairs = pairs[: args.limit]

    if not pairs:
        print("No APKs to process.", flush=True)
        return 0

    failures = []
    total_targets = 0
    total_found = 0
    completed_stems = set()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(
                process_one,
                root,
                args.framework_dir,
                args.temp_root,
                args.output_dir,
                stem,
                apk_path,
                gt_path,
            ): stem
            for stem, apk_path, gt_path in pairs
        }
        for future in as_completed(future_map):
            stem = future_map[future]
            try:
                stem, target_count, found_count = future.result()
                completed_stems.add(stem)
                total_targets += target_count
                total_found += found_count
                print(f"{stem}: matched {found_count}/{target_count} classes", flush=True)
            except Exception as exc:  # noqa: BLE001
                failures.append((stem, str(exc)))
                print(f"{stem}: FAILED: {exc}", file=sys.stderr, flush=True)

    expected_stems = {stem for stem, _, _ in pairs}
    missing_outputs = []
    for stem in sorted(expected_stems):
        output_path = output_path_for(args.output_dir, stem)
        if stem not in completed_stems or not output_path.is_file():
            missing_outputs.append((stem, "missing output file"))

    all_failures = failures + missing_outputs
    args.failures_file.parent.mkdir(parents=True, exist_ok=True)
    if all_failures:
        args.failures_file.write_text(
            "".join(f"{stem}\t{message}\n" for stem, message in all_failures),
            encoding="utf-8",
        )
    elif args.failures_file.exists():
        args.failures_file.unlink()

    print(
        f"Processed {len(pairs)} apps, matched {total_found}/{total_targets} payload classes.",
        flush=True,
    )
    if all_failures:
        print(f"Failures: {len(all_failures)}", file=sys.stderr, flush=True)
        for stem, message in all_failures[:20]:
            print(f"  {stem}: {message}", file=sys.stderr, flush=True)
        print(
            f"Failure details written to {args.failures_file}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
