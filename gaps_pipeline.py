"""
GAPS analysis pipeline
"""

import argparse
import os
from pathlib import Path
import json
import shutil
import subprocess

# Config cache (~/.config/gaps_pipeline/config.json)
CONFIG_PATH = Path.cwd() / ".gaps_pipeline_config.json"

# Keys stored in the cache file
_CACHE_KEYS = ("android_jar", "build_tools_dir", "androlog_jar")

def _load_cache() -> dict[str, str]:
    """Return the cached config dict or {} if the file doesn't exist"""
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save_cache(data: dict[str, str]) -> None:
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


# Auto detection helpers
def _sdk_root() -> Path | None:
    """Return the Android SDK root from standard env vars, if set and valid."""
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(var)
        if value:
            p = Path(value)
            if p.is_dir():
                return p
    return None
 
 
def _latest_subdir(parent: Path) -> Path | None:
    """Return the lexicographically last subdirectory of *parent*, or None."""
    if not parent.is_dir():
        return None
    subdirs = sorted(d for d in parent.iterdir() if d.is_dir())
    return subdirs[-1] if subdirs else None

def detect_androlog_jar() -> Path | None:
    """
    Look for the AndroLog jar in:
    1. $ANDROLOG_JAR env var
    2. Common locations relative to HOME and CWD 
    """
    if val := os.environ.get("ANDROLOG_JARA"):
        return Path(val)
    
    jar_name = "androlog-0.1-jar-with-dependencies.jar"
    search_roots = [Path.home() / "Downloads", Path.home(), Path.cwd()]
    for root in search_roots:
        for jar in root.rglob(jar_name):
            if jar.is_file():
                return jar
    return None

def detect_android_jar() -> Path | None:
    """
    Look for android.jar in:
      1. $ANDROID_JAR env var
      2. $ANDROID_HOME/platforms/android-<latest>/android.jar
      3. ~/Android/Sdk/platforms/...     (Linux default)
      4. ~/Library/Android/sdk/...       (macOS default)
      5. ~/AppData/Local/Android/Sdk/... (Windows default)
    """
    if val := os.environ.get("ANDROID_JAR"):
        return Path(val)
 
    candidates: list[Path] = []
    if sdk := _sdk_root():
        candidates.append(sdk / "platforms")
    candidates += [
        Path.home() / "Android" / "Sdk" / "platforms",
        Path.home() / "Library" / "Android" / "sdk" / "platforms",
        Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platforms",
    ]
    for platforms_dir in candidates:
        if latest := _latest_subdir(platforms_dir):
            jar = latest / "android.jar"
            if jar.is_file():
                return jar
    return None

def detect_build_tools_dir() -> Path | None:
    """
    Look for the build-tools directory in:
      1. $BUILD_TOOLS_DIR env var
      2. $ANDROID_HOME/build-tools/<latest>
      3. Conventional SDK locations (same order as android.jar detection)
    """
    if val := os.environ.get("BUILD_TOOLS_DIR"):
        return Path(val)
 
    candidates: list[Path] = []
    if sdk := _sdk_root():
        candidates.append(sdk / "build-tools")
    candidates += [
        Path.home() / "Android" / "Sdk" / "build-tools",
        Path.home() / "Library" / "Android" / "sdk" / "build-tools",
        Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools",
    ]
    for bt_parent in candidates:
        if latest := _latest_subdir(bt_parent):
            return latest
    return None

# Resolve tool paths: cache -> detect -> warn + redetect if stale
def resolve_tool_paths(reconfigure: bool = False) -> dict[str, Path | None]:
    """
    Return resolved paths for android_jar, androlog_jar and build_tools_dir
    """
    detectors = {
        "android_jar": detect_android_jar,
        "build_tools_dir": detect_build_tools_dir,
        "androlog_jar": detect_androlog_jar,
    }

    if reconfigure:
        print("[*] Reconfiguring: running fresh detection...")
        resolved = {key: fn() for key, fn in detectors.items()}
        _save_cache({k: str(v) for k, v in resolved.items() if v is not None})
        print("[*] Config saved to {CONFIG_PATH}")
        return resolved
    
    cache = _load_cache()
    resolved: dict[str, Path | None] = {}
    updated = False

    if cache:
        for key, detector in detectors.items():
            cached_val = cache.get(key)
            if cached_val is None:
                result = detector()
                resolved[key] = result
                if result is not None:
                    cache[key] = str(result)
                    updated = True
            else:
                p = Path(cached_val)
                if p.exists():
                    resolved[key] = p
                else:
                    print(f"[!] Cached path for '{key}' no longer exists: {p}")
                    print(f"    Re-detecting...")
                    result = detector()
                    resolved[key] = result
                    if result is not None:
                        cache[key] = str(result)
                        print(f"    Found: {result}")
                    else:
                        cache.pop(key, None)
                        print(f"    Not found. Use --reconfigure or set the env var.")
                    updated = True
    else:
        # no cache at all — first run
        print("[*] No config cache found, detecting tool paths...")
        for key, detector in detectors.items():
            resolved[key] = detector()
        _save_cache({k: str(v) for k, v in resolved.items() if v is not None})
        print(f"[*] Config saved to {CONFIG_PATH}")
        return resolved
 
    if updated:
        _save_cache({k: str(v) for k, v in cache.items()})
 
    return resolved

# Argument parser
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GAPS analysis pipeline",
    )
    parser.add_argument(
        "--reconfigure",
        action="store_true",
        default=False,
        help=f"Force re-detection of tool paths and update {CONFIG_PATH}.",
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
        "--gaps-use-conditional",
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

def print_config(args):
    print(f"  apk_limit         = {args.apk_limit}")
    print(f"  workers           = {args.workers}")
    print(f"  gaps_dir          = {args.gaps_dir}")
    print(f"  gaps_output_dir   = {args.gaps_output_dir}")
    print(f"  gaps_path_limit   = {args.gaps_path_limit}")
    print(f"  gaps_use_cond     = {args.gaps_use_conditional}")
    print(f"  gaps_manual_setup = {args.gaps_manual_setup}")
    print(f"  adb_serial        = {args.adb_serial}")
    print(f"  apks_dir          = {args.apks_dir}")
    print(f"  gt_dir            = {args.gt_dir}")
    print()
    return 0

# Environment validation
def validate_environment(args: argparse.Namespace, tools: dict[str, Path | None]) -> bool:
    """
    Check all prerequisites.
    Returns True if OK, False if anything failed
    """
    errors: list[str] = []

    # commands that must be on PATH
    for cmd in ("java", "apktool", "adb"):
        if not shutil.which(cmd):
            errors.append(f"Command not found on PATH: '{cmd}'")
    
    # auto detect tool paths
    for key, label, kind in (
        ("android_jar",     "android.jar",      "file"),
        ("build_tools_dir", "build-tools dir",  "dir"),
        ("androlog_jar",    "androlog jar",      "file"),
    ):
        p = tools.get(key)
        if p is None:
            errors.append(
                f"Could not find {label}. "
                f"Set the {key.upper()} env var or run --reconfigure."
            )
        elif kind == "file" and not p.is_file():
            errors.append(f"{label} path does not exist: {p}")
        elif kind == "dir" and not p.is_dir():
            errors.append(f"{label} path does not exist: {p}")

    # build-tools binaries
    bt = tools.get("build_tools_dir")
    if bt and bt.is_dir():
        for binary in ("apksigner", "zipalign", "aapt"):
            if not (bt / binary).is_file():
                errors.append(f"Missing binary in build-tools dir: '{binary}' (looked in {bt})")
 
    # GAPS dir and binary
    gaps_dir: Path = args.gaps_dir
    if not gaps_dir.is_dir():
        errors.append(f"GAPS directory not found: {gaps_dir}")
    else:
        gaps_bin = gaps_dir / ".venv" / "bin" / "gaps"
        if not gaps_bin.is_file():
            errors.append(f"GAPS binary not found: {gaps_bin}")
        elif not os.access(gaps_bin, os.X_OK):
            errors.append(f"GAPS binary is not executable: {gaps_bin}")
 
    # input directories
    for attr, label in (("apks_dir", "APKs directory"), ("gt_dir", "ground-truth directory")):
        p: Path = getattr(args, attr)
        if not p.is_dir():
            errors.append(f"{label} not found: {p}")
 
    # ADB device reachability
    try:
        result = subprocess.run(
            ["adb", "-s", args.adb_serial, "get-state"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            errors.append(
                f"ADB device not reachable: {args.adb_serial} "
                f"(adb get-state exited {result.returncode})"
            )
    except FileNotFoundError:
        pass  # already caught by the PATH check above
    except subprocess.TimeoutExpired:
        errors.append(f"ADB device timed out: {args.adb_serial}")
 
    if errors:
        print("[!] Environment validation failed:")
        for err in errors:
            print(f"    • {err}")
        return False
 
    print("[*] Environment OK.")
    return True

# Cleanup and setup workspace
# Directories created fresh on every run
_WORK_DIRS = (
    "androlog_config",
    "instrumented_apks",
    "android_platforms_stub",
    "output",
)
 
# Scratch dirs that are just deleted (not recreated)
_SCRATCH_DIRS = (
    ".tmp_payload_extract",
    ".apktool-home",
)
 
# Files cleaned up before each run
_CLEAN_FILES = (
    "selected_apps.txt",
    "instrumented_apks_failures.txt",
    "extract_payload_methods_failures.txt",
    "gaps_static_failures.txt",
    "gaps_dynamic_failures.txt",
)

def setup_workspace(root: Path, args: argparse.Namespace, tools: dict[str, Path | None]) -> None:
    """
    Wipe all artifacts from previous runs and create a clean workspace.
    Also writes androlog_config/config.properties and builds the
    android_platforms_stub directory tree.
    """
    print("[*] Cleaning previous artifacts...")
 
    # remove work dirs and scratch dirs
    for name in (*_WORK_DIRS, *_SCRATCH_DIRS):
        p = root / name
        if p.exists():
            shutil.rmtree(p)
 
    # remove the GAPS output dir (comes from args, may live outside root)
    gaps_out: Path = args.gaps_output_dir
    if gaps_out.exists():
        shutil.rmtree(gaps_out)
 
    # remove leftover flat files
    for name in _CLEAN_FILES:
        p = root / name
        if p.exists():
            p.unlink()
 
    # recreate work dirs and gaps output dir
    for name in _WORK_DIRS:
        (root / name).mkdir(parents=True)
    gaps_out.mkdir(parents=True)
 
    # write androlog config
    bt: Path = tools["build_tools_dir"]
    config_props = root / "androlog_config" / "config.properties"
    config_props.write_text(
        f"apksignerPath={bt / 'apksigner'}\n"
        f"zipalignPath={bt / 'zipalign'}\n",
        encoding="utf-8",
    )
 
    # build android_platforms_stub:
    # create android-1 … android-N dirs, each with a symlink android.jar
    # pointing to the real android.jar — this tricks AndroLog into thinking
    # a full SDK is present for every API level.
    android_jar: Path = tools["android_jar"]
    stub_root = root / "android_platforms_stub"
    api_levels = 36
    print(f"[*] Building android_platforms_stub (API 1-{api_levels})...")
    for i in range(1, api_levels + 1):
        api_dir = stub_root / f"android-{i}"
        api_dir.mkdir(parents=True)
        link = api_dir / "android.jar"
        # on Windows os.symlink needs privilege; use a copy as fallback
        try:
            link.symlink_to(android_jar)
        except (OSError, NotImplementedError):
            import shutil as _shutil
            _shutil.copy2(android_jar, link)
 
    print("[*] Workspace ready.")
 

def main() -> int:
    args = parse_args()
    print_config(args)
    tools = resolve_tool_paths(reconfigure=args.reconfigure)
    print(f"  android_jar       = {tools['android_jar']}")
    print(f"  build_tools_dir   = {tools['build_tools_dir']}")
    print(f"  androlog_jar      = {tools['androlog_jar']}")

    if not validate_environment(args, tools):
        return 1

    root = Path(__file__).parent.resolve()
    setup_workspace(root, args, tools)

    print("[*] Starting pipeline...")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())