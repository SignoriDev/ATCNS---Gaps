#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APKS_DIR="${ROOT_DIR}/apks"

if ! command -v aapt &> /dev/null; then
  # Try to find aapt in the Android SDK build-tools
  BUILD_TOOLS_DIR=${BUILD_TOOLS_DIR:-/home/unknown/Android/Sdk/build-tools/36.1.0}
  if [ -f "$BUILD_TOOLS_DIR/aapt" ]; then
    export PATH="$BUILD_TOOLS_DIR:$PATH"
  else
    echo "Error: aapt command not found. Please ensure it is in your PATH or set BUILD_TOOLS_DIR." >&2
    exit 1
  fi
fi

if [ ! -d "$APKS_DIR" ]; then
  echo "Error: Directory $APKS_DIR does not exist." >&2
  exit 1
fi

echo "Checking SDK versions for APKs in $APKS_DIR..."
echo "=================================================="
printf "%-50s | %-10s | %-10s\n" "APK Name" "Min SDK" "Target SDK"
echo "--------------------------------------------------|------------|------------"

find "$APKS_DIR" -maxdepth 1 -name "*.apk" -print0 | sort -z | while IFS= read -r -d '' apk_path; do
  apk_name=$(basename "$apk_path")
  
  # Use aapt to extract sdk versions
  badging_output=$(aapt dump badging "$apk_path" 2>/dev/null || true)
  
  if [ -z "$badging_output" ]; then
    printf "%-50s | %-10s | %-10s\n" "$apk_name" "ERROR" "ERROR"
    continue
  fi
  
  min_sdk=$(echo "$badging_output" | grep "sdkVersion:" | grep -E -o "[0-9]+" || echo "Unknown")
  target_sdk=$(echo "$badging_output" | grep "targetSdkVersion:" | grep -E -o "[0-9]+" || echo "Unknown")
  
  printf "%-50s | %-10s | %-10s\n" "$apk_name" "$min_sdk" "$target_sdk"
done

echo "=================================================="
echo "Check complete."
