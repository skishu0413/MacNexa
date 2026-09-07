#!/usr/bin/env bash
# Runs the full verification gate: core unit tests + app build.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Regenerating Xcode project"
xcodegen generate >/dev/null

echo "==> Core unit tests (swift test)"
( cd MacNexaCore && swift test )

echo "==> App build"
xcodebuild -project MacNexa.xcodeproj -scheme MacNexa \
  -destination 'platform=macOS' build | tail -1

echo "==> All checks passed"
