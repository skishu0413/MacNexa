# Development

## Workflow
Follow `.skills/`:
- Review before implementing.
- Every feature ships with unit tests; build + tests green before moving on.
- Never push or open PRs without explicit approval.
- Commit only when asked; small, verified commits.

## Commands
```bash
xcodegen generate
cd MacNexaCore && swift test
xcodebuild -project MacNexa.xcodeproj -scheme MacNexa -destination 'platform=macOS' build
./scripts/test.sh
```

## Phase order (spec §53)
Bluetooth detect → disconnect → reconnect → two-device → Bonjour → protocol →
auth → remote release → switch coordinator → verification → rollback →
reliability → launch at login → signing/notarization → KVM.

Do not proceed past Bluetooth reconnect until it is proven reliable on the
actual Magic Keyboard and Magic Trackpad.
