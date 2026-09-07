# MacNexa

Wireless handoff of an Apple Magic Keyboard and Magic Trackpad between multiple
Macs over the local network. Native macOS menu-bar app written in Swift.

See the full specification: `MacNexa — Architecture & Implementation Specification.md`.

## Project layout

```
MacNexaCore/     Swift Package: hardware-independent, unit-tested core
  Models/          Device, peer, and status value types
  Protocol/        Versioned network message envelope + payloads
  Security/        Curve25519 identity, HMAC signing, replay protection
  Switching/       Handoff state machine + retry policy
  Bluetooth/       Bluetooth abstraction + in-memory mock
  Support/         Typed errors, constants, clock abstraction

MacNexa/         Xcode app target: SwiftUI menu-bar UI + platform glue
  App/             Entry point, AppState, dependency container
  UI/              Menu-bar views
  Bluetooth/       IOBluetooth-backed manager
  Utilities/       OSLog loggers

.skills/           Developer working agreements and guardrails
Documentation/     Architecture, security, protocol, bluetooth, dev notes
```

## Requirements

- macOS 13 (Ventura) or later
- Xcode 15 or later (developed on Xcode 26)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) to generate the Xcode project
  (installable without Homebrew — see below)
- Apple Magic Keyboard and/or Magic Trackpad (only for real-hardware use;
  the app runs against an in-memory mock without them)

## Quick start (run it in 3 steps)

Run these from the repository root. Each command below has been verified on
macOS with Xcode 15+ and XcodeGen installed.

```bash
# 1. Generate the Xcode project from project.yml
xcodegen generate

# 2. Build the app (Debug configuration)
xcodebuild -project MacNexa.xcodeproj -scheme MacNexa \
  -destination 'platform=macOS' -configuration Debug build

# 3. Launch the built app
open "$(xcodebuild -project MacNexa.xcodeproj -scheme MacNexa \
  -configuration Debug -showBuildSettings 2>/dev/null \
  | awk '/ BUILT_PRODUCTS_DIR /{print $3}')/MacNexa.app"
```

After step 3, MacNexa launches as a **menu-bar app** — there is no window or
Dock icon. Look for the **keyboard icon in the macOS menu bar** (top-right of
the screen) and click it to open the panel.

To confirm it's running:

```bash
pgrep -l MacNexa
```

Prefer Xcode? After `xcodegen generate`, just open the project and press Run
(Cmd+R):

```bash
open MacNexa.xcodeproj
```

## Installation

MacNexa is currently distributed as source. Build it from a checkout:

```bash
# 1. Clone the repository
git clone https://github.com/skishu0413/MacNexa.git
cd MacNexa

# 2. Install the project generator (one time)
brew install xcodegen

# 3. Generate the Xcode project from project.yml
xcodegen generate

# 4a. Build the app from the command line...
xcodebuild -project MacNexa.xcodeproj -scheme MacNexa \
  -destination 'platform=macOS' build

# 4b. ...or open it in Xcode and press Run (Cmd+R)
open MacNexa.xcodeproj
```

The built `MacNexa.app` is placed under Xcode's DerivedData build products
directory. To install it for everyday use, copy it into `/Applications`:

```bash
APP=$(xcodebuild -project MacNexa.xcodeproj -scheme MacNexa \
  -showBuildSettings 2>/dev/null | awk '/ BUILT_PRODUCTS_DIR /{print $3}')
cp -R "$APP/MacNexa.app" /Applications/
```

> Note: The generated `MacNexa.xcodeproj` is not committed to source control.
> Always run `xcodegen generate` after cloning or after editing `project.yml`.

### Installing XcodeGen without Homebrew

On a managed or locked-down company Mac where Homebrew is not allowed, you can
still get XcodeGen with only the tools Xcode already provides. Use any one of
these approaches.

**Option A — Download the prebuilt binary (no admin, no build)**

XcodeGen ships a self-contained release binary. Download it, unzip it, and run
it in place — no installation required.

```bash
# Download and unzip the latest release (pin the version as needed)
curl -L -o xcodegen.zip \
  https://github.com/yonaskolb/XcodeGen/releases/download/2.46.0/xcodegen.zip
unzip xcodegen.zip

# Run it directly from the extracted bundle (keep bin/ next to share/)
./xcodegen/bin/xcodegen generate
```

To make it available as a plain `xcodegen` command without admin rights, install
it into a user-writable prefix and add that prefix's `bin` to your `PATH`:

```bash
# Installs to ~/.local/bin and ~/.local/share (no sudo needed)
PREFIX="$HOME/.local" ./xcodegen/install.sh
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc to make it permanent
xcodegen generate
```

**Option B — Build XcodeGen from source with Swift (no third-party tools)**

XcodeGen is a Swift package, so the Swift toolchain that comes with Xcode can
build it directly.

```bash
git clone https://github.com/yonaskolb/XcodeGen.git
cd XcodeGen
swift run xcodegen generate --spec /path/to/MacNexa/project.yml
# or build a release binary you can copy into ~/.local/bin:
#   swift build -c release
#   cp .build/release/xcodegen ~/.local/bin/
```

**Option C — Skip XcodeGen entirely**

If your policy forbids downloading and running unsigned binaries, generate the
`MacNexa.xcodeproj` once on an unrestricted machine and commit it to the
repository (remove the `MacNexa.xcodeproj/` line from `.gitignore`). Everyone
else can then open the committed project in Xcode without needing XcodeGen at
all. The tradeoff is that the checked-in project must be regenerated and
re-committed whenever `project.yml` changes.

## Usage

MacNexa runs as a **menu-bar app** — there is no Dock icon or main window.

1. **Launch** the app (from `/Applications`, Xcode, or the build output). A
   keyboard icon appears in the macOS menu bar.
2. **Open the panel** by clicking the menu-bar icon. You'll see:
   - **This Mac** — the name of the Mac you're on.
   - **Devices** — your Magic Keyboard / Magic Trackpad and their connection
     status (● Connected, ○ Disconnected, ◐ Connecting, ⚠ Error).
   - **Other Macs** — MacNexa peers discovered on the local network.
3. **Refresh** re-reads Bluetooth device state. **Quit** exits the app.
4. When a peer is **Available**, use its **Switch** button to hand the keyboard
   and trackpad over to that Mac. (Peer discovery, pairing, and the full
   handoff are being built out per the spec's phase order — see Status below.)

### Mock vs. real hardware

By default the app uses an **in-memory mock** Bluetooth manager, so it launches
and is fully demonstrable on any Mac — even without the peripherals. This is the
recommended mode for development and UI work.

To drive **real** Bluetooth hardware via IOBluetooth, set the environment flag:

```bash
# From the command line
MACNEXA_USE_IOBLUETOOTH=1 open -a MacNexa

# In Xcode: Product > Scheme > Edit Scheme… > Run > Arguments >
#   Environment Variables, set MACNEXA_USE_IOBLUETOOTH = 1
```

### Two-Mac setup (target workflow)

1. Install and launch MacNexa on **both** Macs (e.g. Mac mini and MacBook Pro).
2. Keep both Macs on the **same local network**.
3. Each Mac discovers the other under **Other Macs**; pair them once when
   prompted (explicit authorization is required the first time).
4. Click **Switch to <other Mac>** to move the keyboard and trackpad across.
   The reverse works identically from the other Mac.

MacNexa operates entirely over the local network. It does not require matching
Apple IDs, iCloud, Universal Control, USB connections, or any cloud service.

## Build & test

```bash
# Generate the Xcode project from project.yml
xcodegen generate

# Run the fast, hardware-independent unit suite
cd MacNexaCore && swift test

# Build the app
xcodebuild -project MacNexa.xcodeproj -scheme MacNexa -destination 'platform=macOS' build

# Or run the full verification gate (regenerate + core tests + app build)
./scripts/test.sh
```

## Status

Implemented and unit-tested (core) or built (app):

- **Models & protocol** — device/peer models, versioned message envelope, framing.
- **Security** — Curve25519 + HKDF, HMAC signing, replay protection, fail-closed
  command validation, trust store, rate limiting, pairing code + key exchange.
- **Persistence** — identity + trusted-peer storage (Keychain in the app,
  in-memory for tests).
- **Networking** — Bonjour discovery, listener, Network.framework transport,
  authenticated peer sessions.
- **Switching** — full `SwitchCoordinator` (one transaction at a time), state
  machine, retry, and `RecoveryManager` rollback.
- **App** — menu-bar UI, settings, pairing view, launch-at-login (SMAppService).

Remaining before a shippable v1.0: real-hardware validation of Magic device
handoff on two Macs (spec §49), and signing/notarization for distribution
(spec §44). The pairing handshake (MITM-resistant SAS) and live Bluetooth event
monitoring are now implemented.

## License

See `LICENSE`.
