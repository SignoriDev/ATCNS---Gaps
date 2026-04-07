#!/usr/bin/env python3
"""
gaps_pipeline.py — End-to-end GAPS Android analysis pipeline.

Pipeline stages:
  1. Auto-detect tool paths (android.jar, build-tools, AndroLog jar) and cache them.
  2. Collect and randomly sample APK + ground-truth class file pairs.
  3. Extract payload method signatures from each APK (parallel, via apktool).
  4. For each selected app:
       a. Instrument the APK with AndroLog.
       b. Run GAPS static analysis.
       c. Run GAPS dynamic analysis on the connected device.
       d. Uninstall the app and delete the instrumented APK immediately.
  5. Run get_stats.py to produce the final statistics CSV.

All transient files (apktool framework cache, androlog config, android platform stubs,
instrumented APKs, seed files) are kept in a single temp directory that is wiped on exit.
The only persisted outputs are the gaps_output/ directory and pipeline_failures.txt (if any).
"""
from __future__ import annotations

import argparse
import atexit
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).resolve().parent
CONFIG_FILE  = SCRIPT_DIR / ".gaps_pipeline_config.json"
APK_SUFFIX   = "_app-release.apk"   # suffix on every input APK file
GT_SUFFIX    = "_app.conf.gt.txt"   # suffix on every ground-truth class file
TMP_DIR_NAME = "_pipeline_tmp"      # temp workspace, wiped on exit

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)

def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr, flush=True)

def die(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Tool path auto-detection & config cache
# ──────────────────────────────────────────────────────────────────────────────

def _sdk_root() -> Path:
    return Path(os.environ.get("ANDROID_HOME", Path.home() / "Android/Sdk"))

def _detect_android_jar() -> Optional[Path]:
    platforms = _sdk_root() / "platforms"
    if not platforms.exists():
        return None
    candidates = sorted(
        platforms.glob("android-*/android.jar"),
        key=lambda p: int(re.search(r"android-(\d+)", str(p)).group(1)),
    )
    return candidates[-1] if candidates else None

def _detect_build_tools_dir() -> Optional[Path]:
    build_tools = _sdk_root() / "build-tools"
    if not build_tools.exists():
        return None
    candidates = [
        d for d in build_tools.iterdir() if d.is_dir()
        and re.match(r"\d+\.\d+\.\d+", d.name)
    ]
    return max(candidates, key=lambda p: tuple(int(x) for x in p.name.split(".")), default=None)

def _detect_androlog_jar() -> Optional[Path]:
    search_dirs = [
        Path.home() / "Downloads/AndroLog/target",
        Path.home() / "androlog/target",
        Path("/opt/androlog"),
    ]
    for d in search_dirs:
        if not d.exists():
            continue
        candidates = list(d.glob("androlog-*-jar-with-dependencies.jar"))
        if candidates:
            return candidates[0]
    return None

def load_config(reconfigure: bool = False) -> dict[str, Path]:
    """
    Return a dict with keys android_jar, build_tools_dir, androlog_jar.
    Values are loaded from the JSON cache if they still exist on disk;
    otherwise they are re-detected and the cache is updated.
    Passing reconfigure=True forces re-detection of all paths.
    """
    cached: dict = {}
    if CONFIG_FILE.exists() and not reconfigure:
        try:
            cached = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass

    spec = {
        "android_jar":     (_detect_android_jar,     "android.jar"),
        "build_tools_dir": (_detect_build_tools_dir, "build-tools directory"),
        "androlog_jar":    (_detect_androlog_jar,     "androlog jar"),
    }
    config: dict[str, Optional[Path]] = {}
    dirty = False

    for key, (detector, label) in spec.items():
        cached_val = cached.get(key)
        if cached_val and Path(cached_val).exists():
            config[key] = Path(cached_val)
        else:
            log(f"Auto-detecting {label}...")
            found = detector()
            if found:
                log(f"  -> {found}")
            config[key] = found
            dirty = True

    if dirty:
        serialisable = {k: str(v) for k, v in config.items() if v is not None}
        CONFIG_FILE.write_text(json.dumps(serialisable, indent=2) + "\n")

    return config  # type: ignore[return-value]

# ──────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="End-to-end GAPS Android analysis pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--reconfigure", action="store_true",
        help="Force re-detection of all tool paths and refresh the config cache.",
    )
    p.add_argument(
        "--apk-limit", type=int, default=67, metavar="N",
        help="Number of APKs to process (randomly sampled).",
    )
    p.add_argument(
        "--workers", type=int, default=6, metavar="N",
        help="Parallel workers used during payload extraction.",
    )
    p.add_argument(
        "--apks-dir", type=Path, default=SCRIPT_DIR / "apks",
        help="Directory containing input APK files.",
    )
    p.add_argument(
        "--gt-dir", type=Path, default=SCRIPT_DIR / "all_gen_gt_classes",
        help="Directory containing ground-truth class files.",
    )
    p.add_argument(
        "--gaps-dir", type=Path,
        default=Path(os.environ.get("GAPS_DIR", SCRIPT_DIR / "GAPS-main")),
        help="Root directory of the GAPS tool (must contain .venv/bin/gaps).",
    )
    p.add_argument(
        "--gaps-output-dir", type=Path,
        default=Path(os.environ.get("GAPS_OUTPUT_DIR", SCRIPT_DIR / "gaps_output")),
        help="Directory where GAPS writes its output.",
    )
    p.add_argument(
        "--gaps-path-limit", type=int,
        default=int(os.environ.get("GAPS_PATH_LIMIT", "1000")),
        help="Maximum paths computed by GAPS static analysis.",
    )
    p.add_argument(
        "--gaps-use-conditional", action=argparse.BooleanOptionalAction,
        default=bool(int(os.environ.get("GAPS_USE_CONDITIONAL", "1"))),
        help="Pass -cond to 'gaps static'.",
    )
    p.add_argument(
        "--gaps-manual-setup", action=argparse.BooleanOptionalAction,
        default=bool(int(os.environ.get("GAPS_MANUAL_SETUP", "0"))),
        help="Pass -ms to 'gaps run'.",
    )
    p.add_argument(
        "--adb-serial", default=os.environ.get("ADB_SERIAL", "emulator-5554"),
        help="ADB device serial number.",
    )
    p.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducible APK selection.",
    )
    p.add_argument(
        "--skip-stats", action="store_true",
        help="Skip the get_stats.py step.",
    )
    return p.parse_args()

# ──────────────────────────────────────────────────────────────────────────────
# Payload extraction helpers
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_class_descriptor(raw: str) -> Optional[str]:
    """Convert a Smali class descriptor to a bare path like com/example/Foo."""
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    if value.startswith("L"):
        value = value[1:]
    if value.endswith(";"):
        value = value[:-1]
    return value.strip("/") or None

def _read_target_classes(gt_path: Path) -> list[str]:
    classes, seen = [], set()
    for line in gt_path.read_text(encoding="utf-8").splitlines():
        desc = _normalize_class_descriptor(line)
        if desc and desc not in seen:
            seen.add(desc)
            classes.append(desc)
    return classes

def _find_smali_file(decoded_dir: Path, class_name: str) -> Optional[Path]:
    rel = Path(*class_name.split("/")).with_suffix(".smali")
    for smali_dir in sorted(decoded_dir.glob("smali*")):
        candidate = smali_dir / rel
        if candidate.is_file():
            return candidate
    return None

def _extract_signatures_from_smali(smali_path: Path) -> list[str]:
    """Return a list of method signatures in Smali format: Lcom/Foo;->bar()V"""
    class_descriptor: Optional[str] = None
    signatures: list[str] = []
    for line in smali_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(".class ") and class_descriptor is None:
            class_descriptor = stripped.split()[-1]
        elif stripped.startswith(".method ") and class_descriptor:
            signatures.append(f"{class_descriptor}->{stripped.split()[-1]}")
    return signatures

def extract_methods_for_app(
    stem: str,
    apk_path: Path,
    gt_path: Path,
    output_path: Path,
    framework_dir: Path,   # XDG_DATA_HOME for apktool (its framework cache)
    apktool_tmp: Path,     # TMPDIR for apktool's own temp files
) -> tuple[int, int]:
    """
    Decode the APK with apktool, find Smali files for every target class listed
    in the ground-truth file, and write extracted method signatures to output_path.

    Returns (number_of_target_classes, number_of_classes_found).
    Raises on any unrecoverable error.
    """
    target_classes = _read_target_classes(gt_path)

    # Give apktool a private temp directory so parallel workers don't collide
    work_dir = Path(tempfile.mkdtemp(prefix=f"{stem}_", dir=apktool_tmp))
    try:
        env = {
            **os.environ,
            "XDG_DATA_HOME": str(framework_dir),
            "TMPDIR": str(apktool_tmp),
        }
        subprocess.run(
            ["apktool", "d", "-f", "-r", "-o", str(work_dir), str(apk_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        signatures: list[str] = []
        seen: set[str] = set()
        found_count = 0

        for class_name in target_classes:
            smali_path = _find_smali_file(work_dir, class_name)
            if smali_path is None:
                continue
            sigs = _extract_signatures_from_smali(smali_path)
            if not sigs:
                continue
            found_count += 1
            for sig in sigs:
                if sig not in seen:
                    seen.add(sig)
                    signatures.append(sig)

        content = "\n".join(signatures)
        output_path.write_text(
            (content + "\n") if content else "",
            encoding="utf-8",
        )
        return len(target_classes), found_count
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

# ──────────────────────────────────────────────────────────────────────────────
# ADB / APK helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_package_name(apk_path: Path, aapt: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            [str(aapt), "dump", "badging", str(apk_path)],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("package: name="):
                return line.split("'")[1]
    except Exception:
        pass
    return None

def uninstall_app(apk_path: Path, aapt: Path, adb_serial: str) -> None:
    pkg = get_package_name(apk_path, aapt)
    if not pkg:
        warn(f"Could not get package name for {apk_path.name} — skipping uninstall")
        return
    subprocess.run(
        ["adb", "-s", adb_serial, "uninstall", pkg],
        capture_output=True,  # suppress output; failure is non-fatal
    )

def is_already_analyzed(gaps_output_dir: Path, app_id: str) -> bool:
    """Return True if stats.csv already has a non-empty PoR entry for this app.

    GAPS dynamic writes PoR as the 8th column (index 7).  On re-runs the CSV
    row has 8 values so gaps_run.py's internal check does row[8] which is an
    IndexError.  We detect this situation here and skip the dynamic step so we
    never trigger that crash.
    """
    stats_csv = gaps_output_dir / "stats.csv"
    if not stats_csv.is_file():
        return False
    try:
        with stats_csv.open(newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            next(reader, None)  # skip header
            for row in reader:
                if row and row[0] == app_id and len(row) >= 8 and row[7].strip():
                    return True
    except Exception:
        pass
    return False

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:  # noqa: C901  (complexity is acceptable for a top-level pipeline)
    args = parse_args()

    # ── Validate required directories and binaries ────────────────────────────

    if not args.apks_dir.is_dir():
        die(f"APKs directory not found: {args.apks_dir}")
    if not args.gt_dir.is_dir():
        die(f"Ground-truth directory not found: {args.gt_dir}")

    gaps_bin = args.gaps_dir / ".venv/bin/gaps"
    if not gaps_bin.is_file():
        die(f"GAPS binary not found: {gaps_bin}  (did you install GAPS in its venv?)")

    get_stats_script = args.gaps_dir / "scripts/stats/get_stats.py"
    if not get_stats_script.is_file():
        die(f"get_stats.py not found: {get_stats_script}")

    for cmd in ("java", "apktool", "adb"):
        if not shutil.which(cmd):
            die(f"Required command not found: {cmd}")

    # ── Load / auto-detect tool paths ─────────────────────────────────────────

    config = load_config(reconfigure=args.reconfigure)

    android_jar  = config.get("android_jar")
    build_tools  = config.get("build_tools_dir")
    androlog_jar = config.get("androlog_jar")

    if not android_jar:
        die("Could not find android.jar — set $ANDROID_HOME or run with --reconfigure")
    if not build_tools:
        die("Could not find build-tools directory — set $ANDROID_HOME or run with --reconfigure")
    if not androlog_jar:
        die("Could not find androlog jar — expected at ~/Downloads/AndroLog/target/")

    aapt      = build_tools / "aapt"
    apksigner = build_tools / "apksigner"
    zipalign  = build_tools / "zipalign"

    for tool in (aapt, apksigner, zipalign):
        if not tool.is_file():
            die(f"Required build tool not found: {tool}")

    # ── ADB device check ──────────────────────────────────────────────────────

    try:
        subprocess.run(
            ["adb", "-s", args.adb_serial, "get-state"],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError:
        die(f"ADB device not available: {args.adb_serial}")

    # ── Create output directory (wipe any previous run's results) ───────────────

    if args.gaps_output_dir.exists():
        log(f"Wiping previous output in {args.gaps_output_dir} ...")
        shutil.rmtree(args.gaps_output_dir)
    args.gaps_output_dir.mkdir(parents=True, exist_ok=True)

    # ── Set up temp workspace (auto-wiped on exit) ────────────────────────────
    #
    # Layout:
    #   _pipeline_tmp/
    #     apktool_home/    - apktool framework cache (XDG_DATA_HOME)
    #     apktool_tmp/     - apktool scratch files   (TMPDIR)
    #     androlog_cfg/    - androlog config.properties
    #     platforms/       - fake Android SDK platforms (required by AndroLog)
    #     methods/         - extracted .smali seed files, one per app
    #     instrumented/    - instrumented APKs (deleted per-app after GAPS dynamic)
    #     seeds/           - .seed files for get_stats.py  (named {stem}.seed)
    #     apks_for_stats/  - symlinks named {stem}.apk → apks/{stem}_app-release.apk

    tmp_root = SCRIPT_DIR / TMP_DIR_NAME
    if tmp_root.exists():
        shutil.rmtree(tmp_root)
    tmp_root.mkdir()
    atexit.register(shutil.rmtree, tmp_root, True)  # clean up even on error/Ctrl-C

    apktool_home   = tmp_root / "apktool_home"
    apktool_tmp    = tmp_root / "apktool_tmp"
    androlog_cfg   = tmp_root / "androlog_cfg"
    platforms      = tmp_root / "platforms"
    methods_dir    = tmp_root / "methods"
    instrumented   = tmp_root / "instrumented"
    seeds_dir      = tmp_root / "seeds"
    apks_for_stats = tmp_root / "apks_for_stats"

    for d in (apktool_home, apktool_tmp, androlog_cfg, platforms,
              methods_dir, instrumented, seeds_dir, apks_for_stats):
        d.mkdir()

    # androlog needs apksigner and zipalign paths
    (androlog_cfg / "config.properties").write_text(
        f"apksignerPath={apksigner}\nzipalignPath={zipalign}\n"
    )

    # AndroLog requires one android.jar per API level; we symlink them all to
    # the single real android.jar instead of shipping 36 copies.
    for level in range(1, 37):
        level_dir = platforms / f"android-{level}"
        level_dir.mkdir()
        (level_dir / "android.jar").symlink_to(android_jar)

    # Augment PATH so build-tool wrappers (aapt, etc.) are reachable by subprocesses
    augmented_env = {
        **os.environ,
        "PATH": f"{build_tools}:{os.environ.get('PATH', '')}",
    }

    # ── Collect APK / ground-truth pairs ──────────────────────────────────────

    apk_stems = {
        p.name[: -len(APK_SUFFIX)]: p
        for p in args.apks_dir.iterdir()
        if p.name.endswith(APK_SUFFIX)
    }
    gt_stems = {
        p.name[: -len(GT_SUFFIX)]: p
        for p in args.gt_dir.iterdir()
        if p.name.endswith(GT_SUFFIX)
    }

    common = sorted(set(apk_stems) & set(gt_stems))
    if not common:
        die("No matching APK + ground-truth pairs found.")

    rng = random.Random(args.seed)
    rng.shuffle(common)
    selected: list[str] = common[: args.apk_limit]
    log(f"Selected {len(selected)} of {len(common)} available apps.")

    # ── Stage 1: Extract payload methods (parallel) ───────────────────────────

    log(f"Extracting payload methods ({args.workers} workers)...")

    extract_failures: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                extract_methods_for_app,
                stem,
                apk_stems[stem],
                gt_stems[stem],
                methods_dir / f"{stem}.smali",
                apktool_home,
                apktool_tmp,
            ): stem
            for stem in selected
        }
        for fut in as_completed(futures):
            stem = futures[fut]
            try:
                target_count, found_count = fut.result()
                print(f"  {stem}: {found_count}/{target_count} classes", flush=True)
            except Exception as exc:
                warn(f"  {stem}: extraction failed — {exc}")
                extract_failures.append((stem, f"extraction: {exc}"))

    # ── Stages 2–4: Instrument+Static (parallel) → Dynamic (sequential) ─────────
    #
    # Notes on naming:
    #   • Input APK:              apks/{stem}_app-release.apk
    #   • Instrumented APK:       _pipeline_tmp/instrumented/{stem}_app-release.apk
    #   • GAPS output dir:        gaps_output/{stem}_app-release/
    #   • GAPS stats.csv APP col: {stem}_app-release  (GAPS uses the full APK basename)
    #   • get_stats.py seed:      seeds/{stem}_app-release.seed
    #   • get_stats.py APK link:  apks_for_stats/{stem}_app-release.apk → apks/{stem}_app-release.apk

    static_failures:  list[tuple[str, str]] = []
    dynamic_failures: list[tuple[str, str]] = []

    # Pre-create stats.csv with the correct header so that concurrent GAPS static
    # workers don't race on the "create header if missing" check inside gaps.py.
    stats_csv_path = args.gaps_output_dir / "stats.csv"
    with stats_csv_path.open("w", newline="", encoding="utf-8") as _fh:
        csv.writer(_fh).writerow([
            "APP", "TIME", "REACHED METHODS", "TOT. REACHABLE PATHS",
            "REACHABLE CONDITIONAL PATHS", "AVG. REACHABLE PATHS", "UNIQUE PATHS",
        ])

    # ── Phase 1: Instrument + GAPS static (parallel, args.workers workers) ───────

    # Only process apps that had methods extracted successfully.
    to_instrument = []
    for stem in selected:
        mp = methods_dir / f"{stem}.smali"
        if mp.is_file() and mp.stat().st_size > 0:
            to_instrument.append(stem)
        else:
            warn(f"  {stem}: skipping — no methods extracted")
            static_failures.append((stem, "no methods extracted"))

    def _instrument_and_static(stem: str) -> tuple[str, bool, str]:
        """Instrument one app with AndroLog then run GAPS static on it.
        Returns (stem, success, error_message).
        Runs inside a thread-pool worker — only uses per-stem paths, no shared state.
        """
        methods_path     = methods_dir / f"{stem}.smali"
        apk_path         = apk_stems[stem]
        instrumented_apk = instrumented / f"{stem}_app-release.apk"
        app_id           = f"{stem}_app-release"
        instructions     = args.gaps_output_dir / app_id / f"{app_id}-instr.json"

        # Seed file + APK symlink consumed by get_stats.py later.
        # get_stats.py constructs these paths as f"{row['APP']}.seed" / f"{row['APP']}.apk"
        # where row["APP"] is the full APK basename that GAPS static writes to stats.csv,
        # i.e. "{stem}_app-release" — so both files must carry that suffix.
        shutil.copy2(methods_path, seeds_dir / f"{stem}_app-release.seed")
        apk_link = apks_for_stats / f"{stem}_app-release.apk"
        if not apk_link.exists():
            apk_link.symlink_to(apk_path.resolve())

        # 2. Instrument with AndroLog
        try:
            subprocess.run(
                [
                    "java",
                    "-cp", f"{androlog_cfg}:{androlog_jar}",
                    "com.jordansamhi.androlog.Main",
                    "-p", str(platforms),
                    "-a", str(apk_path),
                    "-o", str(instrumented),
                    "-l", "GAPS",
                    "-m", "-n",
                ],
                check=True,
                capture_output=True,
                text=True,
                env=augmented_env,
            )
        except subprocess.CalledProcessError as e:
            return stem, False, f"androlog: {e.stderr[:300].strip()}"

        if not instrumented_apk.is_file():
            return stem, False, "instrumented APK missing"

        # 3. GAPS static
        static_cmd = [
            str(gaps_bin), "static",
            "-i",    str(instrumented_apk),
            "-seed", str(methods_path),
            "-o",    str(args.gaps_output_dir),
            "-l",    str(args.gaps_path_limit),
        ]
        if args.gaps_use_conditional:
            static_cmd.append("-cond")

        try:
            subprocess.run(
                static_cmd,
                check=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            instrumented_apk.unlink(missing_ok=True)
            err = f"gaps static failed (exit {e.returncode})"
            if e.stderr and e.stderr.strip():
                err += f"\n    stderr: {e.stderr.strip()[-600:]}"
            return stem, False, err

        if not instructions.is_file():
            instrumented_apk.unlink(missing_ok=True)
            return stem, False, "instructions file missing after GAPS static"

        return stem, True, ""

    static_ok: set[str] = set()

    log(f"Instrument + GAPS static ({args.workers} workers, {len(to_instrument)} apps)...")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_instrument_and_static, stem): stem
            for stem in to_instrument
        }
        for fut in as_completed(futures):
            stem = futures[fut]
            try:
                _, ok, err = fut.result()
            except Exception as exc:
                ok, err = False, f"unexpected error: {exc}"
            if ok:
                log(f"  {stem}: instrument+static done")
                static_ok.add(stem)
            else:
                warn(f"  {stem}: {err}")
                static_failures.append((stem, err))

    # ── Phase 2: GAPS dynamic (sequential — device is shared) ────────────────────

    for stem in selected:
        if stem not in static_ok:
            continue

        instrumented_apk = instrumented / f"{stem}_app-release.apk"
        app_id           = f"{stem}_app-release"
        instructions     = args.gaps_output_dir / app_id / f"{app_id}-instr.json"

        # ── 4. GAPS dynamic analysis ──────────────────────────────────────────
        if is_already_analyzed(args.gaps_output_dir, app_id):
            log(f"GAPS dynamic {stem}... skipped (already analyzed)")
        else:
            log(f"GAPS dynamic {stem}...")
            dynamic_cmd = [
                str(gaps_bin), "run",
                "-i",    str(instrumented_apk),
                "-instr", str(instructions),
                "-o",    str(args.gaps_output_dir),
            ]
            if args.gaps_manual_setup:
                dynamic_cmd.append("-ms")

            try:
                subprocess.run(
                    dynamic_cmd,
                    check=True,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                warn(f"  {stem}: GAPS dynamic failed (exit {e.returncode})")
                if e.stdout and e.stdout.strip():
                    warn(f"  stdout: {e.stdout.strip()[-600:]}")
                if e.stderr and e.stderr.strip():
                    warn(f"  stderr: {e.stderr.strip()[-600:]}")
                dynamic_failures.append((stem, f"gaps dynamic failed (exit {e.returncode})"))
                # Fall through: still uninstall and clean up

        # Uninstall from device, then delete instrumented APK — it's no longer needed
        uninstall_app(instrumented_apk, aapt, args.adb_serial)
        instrumented_apk.unlink(missing_ok=True)

    # ── Stage 5: Collect statistics ───────────────────────────────────────────
    #
    # GAPS writes stats.csv to gaps_output/.
    # get_stats.py reads that CSV, enriches it with app names (via aapt), and
    # writes final_stats.csv to the same directory.
    #
    # Argument mapping:
    #   argv[1]  csv_file         → gaps_output/stats.csv
    #   argv[2]  app_directory    → _pipeline_tmp/apks_for_stats/  (symlinks {stem}.apk)
    #   argv[3]  seeds_directory  → _pipeline_tmp/seeds/           (files {stem}.seed)

    if not args.skip_stats:
        gaps_csv = args.gaps_output_dir / "stats.csv"
        if gaps_csv.is_file():
            log("Running get_stats.py...")
            try:
                subprocess.run(
                    [sys.executable, str(get_stats_script),
                     str(gaps_csv),
                     str(apks_for_stats),
                     str(seeds_dir)],
                    check=True,
                    env=augmented_env,  # aapt must be on PATH
                )
                log(f"Final stats: {args.gaps_output_dir / 'final_stats.csv'}")
            except subprocess.CalledProcessError as e:
                warn(f"get_stats.py exited with code {e.returncode}")
        else:
            warn("gaps_output/stats.csv not found — skipping stats step")

    # ── Report failures ───────────────────────────────────────────────────────

    all_failures = extract_failures + static_failures + dynamic_failures

    if all_failures:
        failures_path = SCRIPT_DIR / "pipeline_failures.txt"
        failures_path.write_text(
            "".join(f"{stem}\t{msg}\n" for stem, msg in all_failures),
            encoding="utf-8",
        )
        warn(f"{len(all_failures)} failure(s) — see {failures_path}")
        return 1

    log("Pipeline completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
