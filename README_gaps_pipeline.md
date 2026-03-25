# gaps_pipeline.py

An end-to-end automation script that runs the full GAPS Android analysis pipeline:
payload method extraction → APK instrumentation (AndroLog) → GAPS static analysis → GAPS dynamic analysis.

---

## Overview

The pipeline processes a batch of Android APKs against ground-truth class files to identify and exercise payload methods. For each app it:

1. **Extracts payload methods** — uses `extract_payload_methods.py` to match ground-truth classes to Smali methods inside each APK.
2. **Instruments the APK** — runs [AndroLog](https://github.com/JordanSamhi/AndroLog) to inject logging hooks around the extracted methods.
3. **Runs GAPS static analysis** — uses the `gaps static` command to compute execution paths from the instrumented APK and the seed method list.
4. **Runs GAPS dynamic analysis** — uses `gaps run` to replay those paths on a connected Android device/emulator and collect runtime traces.

Failures at any stage are logged to separate files so the batch continues rather than aborting on the first error.

---

## Prerequisites

### System commands (must be on `PATH`)

| Command    | Purpose                                      |
|------------|----------------------------------------------|
| `java`     | Run AndroLog                                 |
| `apktool`  | Disassemble APKs during payload extraction   |
| `adb`      | Communicate with the Android device/emulator |

### Android SDK components

| Component          | Used for                                     |
|--------------------|----------------------------------------------|
| `android.jar`      | AndroLog classpath / platforms stub          |
| `build-tools/`     | `apksigner`, `zipalign`, `aapt`              |

### External tools

| Tool                                        | Used for                        |
|---------------------------------------------|---------------------------------|
| `androlog-0.1-jar-with-dependencies.jar`    | APK instrumentation             |
| GAPS tool (`GAPS-main/` with `.venv/bin/gaps`) | Static and dynamic analysis  |

### Python

Python 3.10+.

The only non-stdlib dependency is `extract_payload_methods.py`, which must live in the same directory as `gaps_pipeline.py`.

---

## Tool path resolution

The script auto-detects `android.jar`, the build-tools directory, and the AndroLog jar on first run, then caches the results in `.gaps_pipeline_config.json` in the current working directory.

If a cached path no longer exists the script re-detects it automatically. Pass `--reconfigure` to force fresh detection for all paths.

---

## Usage

```bash
python gaps_pipeline.py [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--reconfigure` | off | Force re-detection of all tool paths and overwrite the config cache. |
| `--apk-limit N` | `67` | Number of APKs to process (randomly sampled from the available pairs). |
| `--workers N` | `6` | Parallel workers used during payload extraction. |
| `--gaps-dir PATH` | `GAPS-main` | Root directory of the GAPS tool (must contain `.venv/bin/gaps`). Also settable via `$GAPS_DIR`. |
| `--gaps-output-dir PATH` | `gaps_output` | Directory where GAPS writes its output. Also settable via `$GAPS_OUTPUT_DIR`. |
| `--gaps-path-limit N` | `1000` | Maximum number of paths computed by GAPS static analysis. Also settable via `$GAPS_PATH_LIMIT`. |
| `--gaps-use-conditional` / `--no-gaps-use-conditional` | enabled | Pass `-cond` to `gaps static`. Also settable via `$GAPS_USE_CONDITIONAL` (1/0). |
| `--gaps-manual-setup` / `--no-gaps-manual-setup` | disabled | Pass `-ms` to `gaps run`. Also settable via `$GAPS_MANUAL_SETUP` (1/0). |
| `--adb-serial SERIAL` | `emulator-5554` | ADB device serial number. Also settable via `$ADB_SERIAL`. |
| `--apks-dir PATH` | `apks/` | Directory containing input `.apk` files. |
| `--gt-dir PATH` | `all_gen_gt_classes/` | Directory containing ground-truth class files. |

All options that have an environment variable equivalent honour that variable as the default, so you can configure the pipeline without repeating flags every run.

### Examples

```bash
# Basic run with defaults
python gaps_pipeline.py

# Process 20 APKs using 4 workers, against a custom device
python gaps_pipeline.py --apk-limit 20 --workers 4 --adb-serial emulator-5556

# Force tool re-detection (e.g. after upgrading the Android SDK)
python gaps_pipeline.py --reconfigure

# Disable conditional-path analysis and point to a non-default GAPS install
python gaps_pipeline.py --no-gaps-use-conditional --gaps-dir /opt/GAPS
```
