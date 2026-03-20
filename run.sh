#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT_DIR"

APK_LIMIT=${APK_LIMIT:-67}
WORKERS=${WORKERS:-6}
ANDROLOG_JAR=${ANDROLOG_JAR:-/home/unknown/Downloads/AndroLog/target/androlog-0.1-jar-with-dependencies.jar}
ANDROID_JAR=${ANDROID_JAR:-/home/unknown/Android/Sdk/platforms/android-36/android.jar}
BUILD_TOOLS_DIR=${BUILD_TOOLS_DIR:-/home/unknown/Android/Sdk/build-tools/36.1.0}
GAPS_DIR=${GAPS_DIR:-$ROOT_DIR/GAPS-main}
GAPS_BIN=${GAPS_BIN:-$GAPS_DIR/.venv/bin/gaps}
GAPS_OUTPUT_DIR=${GAPS_OUTPUT_DIR:-$ROOT_DIR/gaps_output}
GAPS_PATH_LIMIT=${GAPS_PATH_LIMIT:-1000}
GAPS_USE_CONDITIONAL=${GAPS_USE_CONDITIONAL:-1}
GAPS_MANUAL_SETUP=${GAPS_MANUAL_SETUP:-0}
ADB_SERIAL=${ADB_SERIAL:-emulator-5554}

export PATH="$BUILD_TOOLS_DIR:$PATH"

log() {
  printf '[*] %s\n' "$1"
}

fail() {
  printf '[!] %s\n' "$1" >&2
  exit 1
}

require_file() {
  local path=$1
  [ -f "$path" ] || fail "Required file not found: $path"
}

require_dir() {
  local path=$1
  [ -d "$path" ] || fail "Required directory not found: $path"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

run_gaps() {
  "$GAPS_BIN" "$@"
}

adb_cmd() {
  adb -s "$ADB_SERIAL" "$@"
}

get_package_name() {
  local apk_path=$1
  "$BUILD_TOOLS_DIR/aapt" dump badging "$apk_path" \
    | awk -F"'" '/package: name=/{print $2; exit}'
}

uninstall_app() {
  local apk_path=$1
  local package_name

  package_name=$(get_package_name "$apk_path")
  [ -n "$package_name" ] || fail "Could not determine package name for $apk_path"

  log "Uninstalling $package_name from $ADB_SERIAL"
  adb_cmd uninstall "$package_name" >/dev/null 2>&1 || true
}

log "Setting up environment..."

require_command python3
require_command java
require_command apktool
require_command shuf
require_file "$BUILD_TOOLS_DIR/apksigner"
require_file "$BUILD_TOOLS_DIR/zipalign"
require_file "$BUILD_TOOLS_DIR/aapt"
require_file "$ANDROID_JAR"
require_file "$ANDROLOG_JAR"
require_file "$ROOT_DIR/extract_payload_methods.py"
require_dir "$GAPS_DIR"
require_file "$GAPS_BIN"
require_dir "$ROOT_DIR/apks"
require_dir "$ROOT_DIR/all_gen_gt_classes"
require_command adb
adb_cmd get-state >/dev/null 2>&1 || fail "ADB device not available: $ADB_SERIAL"

log "Cleaning previous generated artifacts..."
rm -rf \
  androlog_config \
  instrumented_apks \
  android_platforms_stub \
  output \
  "$GAPS_OUTPUT_DIR" \
  .tmp_payload_extract \
  .apktool-home
rm -f \
  selected_67_apps.txt \
  instrumented_apks_failures.txt \
  extract_payload_methods_failures.txt \
  gaps_static_failures.txt \
  gaps_dynamic_failures.txt

mkdir -p androlog_config instrumented_apks android_platforms_stub output "$GAPS_OUTPUT_DIR"

cat > androlog_config/config.properties <<EOF
apksignerPath=$BUILD_TOOLS_DIR/apksigner
zipalignPath=$BUILD_TOOLS_DIR/zipalign
EOF

for i in $(seq 1 36); do
  mkdir -p "android_platforms_stub/android-$i"
  ln -sfn "$ANDROID_JAR" "android_platforms_stub/android-$i/android.jar"
done

run_marker=$(mktemp "$ROOT_DIR/.run_marker.XXXXXX")
trap 'rm -f "$run_marker"' EXIT

log "Extracting payload methods..."
python3 extract_payload_methods.py \
  --workers "$WORKERS" \
  --limit "$APK_LIMIT" \
  --overwrite \
  --failures-file extract_payload_methods_failures.txt

generated_count=$(find output -maxdepth 1 -name '*_methods.smali' -newer "$run_marker" | wc -l | tr -d ' ')
[ "$generated_count" -ge "$APK_LIMIT" ] || fail "Expected at least $APK_LIMIT generated method files, found $generated_count"

find output -maxdepth 1 -name '*_methods.smali' -newer "$run_marker" \
  | shuf -n "$APK_LIMIT" \
  | sed 's#^output/##; s/_methods\.smali$//' \
  > selected_67_apps.txt

selected_count=$(grep -cve '^[[:space:]]*$' selected_67_apps.txt || true)
[ "$selected_count" -eq "$APK_LIMIT" ] || fail "Expected $APK_LIMIT selected apps, found $selected_count"

log "Instrumenting selected APKs..."
while read -r stem; do
  [ -n "$stem" ] || continue

  apk_path="apks/${stem}_app-release.apk"
  methods_path="output/${stem}_methods.smali"
  instrumented_apk_path="$ROOT_DIR/instrumented_apks/${stem}_app-release.apk"
  instructions_path="$GAPS_OUTPUT_DIR/${stem}_app-release/${stem}_app-release-instr.json"
  static_args=(static -i "$instrumented_apk_path" -seed "$ROOT_DIR/$methods_path" -o "$GAPS_OUTPUT_DIR" -l "$GAPS_PATH_LIMIT")
  dynamic_args=(run -i "$instrumented_apk_path" -instr "$instructions_path" -o "$GAPS_OUTPUT_DIR")

  if [ "$GAPS_USE_CONDITIONAL" = "1" ]; then
    static_args+=(-cond)
  fi

  if [ "$GAPS_MANUAL_SETUP" = "1" ]; then
    dynamic_args+=(-ms)
  fi

  [ -f "$methods_path" ] || {
    printf '%s\tmissing methods file\n' "$stem" >> instrumented_apks_failures.txt
    continue
  }

  [ -f "$apk_path" ] || {
    printf '%s\tmissing apk file\n' "$stem" >> instrumented_apks_failures.txt
    continue
  }

  log "Instrumenting $stem"
  java -cp "$ROOT_DIR/androlog_config:$ANDROLOG_JAR" \
    com.jordansamhi.androlog.Main \
    -p "$ROOT_DIR/android_platforms_stub" \
    -a "$apk_path" \
    -o "$ROOT_DIR/instrumented_apks" \
    -l GAPS \
    -m -n \
    || {
      printf '%s\tandrolog failed\n' "$stem" >> instrumented_apks_failures.txt
      continue
    }

  [ -f "$instrumented_apk_path" ] || {
    printf '%s\tinstrumented apk missing\n' "$stem" >> instrumented_apks_failures.txt
    continue
  }

  log "Running GAPS static for $stem"
  if ! run_gaps "${static_args[@]}" < /dev/null; then
    printf '%s\tgaps static failed\n' "$stem" >> gaps_static_failures.txt
    continue
  fi

  [ -f "$instructions_path" ] || {
    printf '%s\tmissing instructions file\n' "$stem" >> gaps_static_failures.txt
    continue
  }

  log "Running GAPS dynamic for $stem"
  if ! run_gaps "${dynamic_args[@]}" < /dev/null; then
    printf '%s\tgaps dynamic failed\n' "$stem" >> gaps_dynamic_failures.txt
    uninstall_app "$instrumented_apk_path"
    continue
  fi

  uninstall_app "$instrumented_apk_path"
done < selected_67_apps.txt

if [ -s instrumented_apks_failures.txt ]; then
  fail "Instrumentation completed with failures. See $ROOT_DIR/instrumented_apks_failures.txt"
fi

if [ -s gaps_static_failures.txt ]; then
  fail "GAPS static completed with failures. See $ROOT_DIR/gaps_static_failures.txt"
fi

if [ -s gaps_dynamic_failures.txt ]; then
  fail "GAPS dynamic completed with failures. See $ROOT_DIR/gaps_dynamic_failures.txt"
fi

log "Completed successfully."