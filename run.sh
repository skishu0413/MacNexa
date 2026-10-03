#!/usr/bin/env bash
# ==============================================================================
# MacNexa - Universal One-Command Runner
# Compatible across ALL macOS versions:
# - macOS 12 (Monterey)
# - macOS 13 (Ventura)
# - macOS 14 (Sonoma)
# - macOS 15 (Sequoia)
# - macOS 16+ (Tahoe)
# Old-to-New, New-to-Old, Old-to-Old, New-to-New
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
log_ok()   { echo -e "${GREEN}==>${NC} $1"; }
log_warn() { echo -e "${YELLOW}WARNING:${NC} $1"; }
log_err()  { echo -e "${RED}ERROR:${NC} $1"; }

MODE="run"
USE_MOCK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only|-b)
      MODE="build"
      shift
      ;;
    --test|-t)
      MODE="test"
      shift
      ;;
    --mock|-m)
      USE_MOCK=1
      shift
      ;;
    --clean|-c)
      MODE="clean"
      shift
      ;;
    --logs|-l)
      MODE="logs"
      shift
      ;;
    --help|-h)
      echo "MacNexa - Universal Runner"
      echo "Usage: ./run.sh [options]"
      echo ""
      echo "Options:"
      echo "  (none)            Build, sign, and launch MacNexa"
      echo "  --build-only, -b  Compile and package app bundle without launching"
      echo "  --test, -t        Run native storage & security test suite"
      echo "  --mock, -m        Launch with simulated Bluetooth devices (testing mode)"
      echo "  --logs, -l        Stream live MacNexa console logs"
      echo "  --clean, -c       Clean build artifacts"
      echo "  --help, -h        Show this help"
      exit 0
      ;;
    *)
      log_warn "Unknown option: $1"
      shift
      ;;
  esac
done

if [[ "$MODE" == "logs" ]]; then
  log_info "Streaming live MacNexa logs (Ctrl+C to stop)..."
  exec log stream --predicate 'process == "MacNexa"' --style compact
fi

if [[ "$MODE" == "clean" ]]; then
  log_info "Cleaning build artifacts..."
  rm -rf build/MacNexa.app build/native_storage_tests
  log_ok "Clean complete. Run ./run.sh to build."
  exit 0
fi

if [[ "$MODE" == "test" ]]; then
  log_info "Compiling and running MacNexa native storage test suite..."
  mkdir -p build
  clang -fobjc-arc -O2 \
    -mmacosx-version-min=12.0 \
    -framework Foundation \
    -framework Security \
    MacNexa/Native/MNSecurity.m \
    Tests/NativeStorageTests.m \
    -o build/native_storage_tests
  ./build/native_storage_tests
  rm -f build/native_storage_tests
  log_ok "Native storage & security tests passed!"
  exit 0
fi

# ------------------------------------------------------------------------------
# 1. Universal Compiler Check
# ------------------------------------------------------------------------------
log_info "Verifying build environment for macOS universal compatibility..."

if ! command -v clang >/dev/null 2>&1; then
  log_err "Clang compiler not found. Please install Command Line Tools: xcode-select --install"
  exit 1
fi

SDK_PATH="$(xcrun --show-sdk-path 2>/dev/null || echo "")"
SDK_FLAG=""
if [[ -n "$SDK_PATH" && -d "$SDK_PATH" ]]; then
  SDK_FLAG="-isysroot $SDK_PATH"
fi

# ------------------------------------------------------------------------------
# 2. Build Universal App Bundle
# ------------------------------------------------------------------------------
log_info "Compiling MacNexa Universal Engine (macOS 12+ / 13 / 14 / 15 / 16+)..."

APP_DIR="$ROOT_DIR/build/MacNexa.app"
MACOS_DIR="$APP_DIR/Contents/MacOS"
RESOURCES_DIR="$APP_DIR/Contents/Resources"

mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

clang -fobjc-arc -O2 \
  $SDK_FLAG \
  -mmacosx-version-min=12.0 \
  -framework Cocoa \
  -framework IOBluetooth \
  -framework Security \
  -framework IOKit \
  MacNexa/Native/MNSecurity.m \
  MacNexa/Native/MNBluetoothManager.m \
  MacNexa/Native/MNNetwork.m \
  MacNexa/Native/MNMenuController.m \
  MacNexa/Native/main.m \
  -o "$MACOS_DIR/MacNexa"

# Write Info.plist
cat << 'EOF' > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>MacNexa</string>
    <key>CFBundleIdentifier</key>
    <string>com.macnexa.app</string>
    <key>CFBundleName</key>
    <string>MacNexa</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSBluetoothAlwaysUsageDescription</key>
    <string>MacNexa requires Bluetooth to connect and switch your Magic Keyboard and Trackpad.</string>
    <key>NSBluetoothPeripheralUsageDescription</key>
    <string>MacNexa requires Bluetooth to connect and switch your Magic Keyboard and Trackpad.</string>
    <key>NSLocalNetworkUsageDescription</key>
    <string>MacNexa requires local network access to communicate securely with your other Mac.</string>
    <key>NSBonjourServices</key>
    <array>
        <string>_macnexa._tcp</string>
    </array>
</dict>
</plist>
EOF

# ------------------------------------------------------------------------------
# 3. Ad-Hoc Code Sign with Entitlements
# ------------------------------------------------------------------------------
ENTITLEMENTS="$ROOT_DIR/MacNexa/Resources/MacNexa-Debug.entitlements"
if [[ ! -f "$ENTITLEMENTS" ]]; then
  log_err "Entitlements file not found: $ENTITLEMENTS"
  exit 1
fi

log_info "Signing MacNexa with Bluetooth & Local Network entitlements..."
if ! codesign --force --deep --sign - --entitlements "$ENTITLEMENTS" "$APP_DIR"; then
  log_err "Code signing failed for $APP_DIR"
  exit 1
fi

if [[ "$MODE" == "build" ]]; then
  log_ok "Build and signing complete: $APP_DIR"
  exit 0
fi

# ------------------------------------------------------------------------------
# 4. Launch Application
# ------------------------------------------------------------------------------
log_info "Terminating any previous MacNexa instance..."
killall MacNexa >/dev/null 2>&1 || true
sleep 0.5

if [[ $USE_MOCK -eq 1 ]]; then
  log_warn "Starting MacNexa with simulated Bluetooth devices (MOCK mode)..."
  MACNEXA_USE_MOCK_BLUETOOTH=1 open -n "$APP_DIR"
else
  log_info "Launching MacNexa..."
  open -n "$APP_DIR"
fi

echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  MacNexa is now running!${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "  Look for the ${BOLD}keyboard icon (⌨️) in your macOS menu bar${NC} (top right)."
echo ""
echo -e "  ${BOLD}Pairing your MacBook & Mac Mini:${NC}"
echo -e "    1. Run ${CYAN}./run.sh${NC} on both Macs (compatible with old & new macOS versions)."
echo -e "    2. Click the ${BOLD}keyboard icon (⌨️)${NC} in the menu bar -> ${BOLD}Pair New Mac${NC}."
echo -e "    3. Select your other Mac from the list."
echo -e "    4. Compare the 6-digit SAS security code on both screens and confirm."
echo -e "    5. Click ${BOLD}Switch${NC} to seamlessly hand off your Magic Keyboard & Trackpad!"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    Stop app:        ${CYAN}killall MacNexa${NC}"
echo -e "    Run with mocks:  ${CYAN}./run.sh --mock${NC}"
echo -e "    Stream logs:     ${CYAN}./run.sh --logs${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
