# SwiftSword — iOS 26.2 Kernel Exploit

**CVE-2026-28992** IOHIDFamily FastPathUserClient UAF
A14 (iPhone 12 Pro Max) • iOS 26.2 • No MTE

## Build IPA

1. Push to GitHub
2. Actions → Build SwiftSword IPA → Run workflow
3. Download `SwiftSword_iOS26` artifact

## Install

```
pymobiledevice3 apps install SwiftSword_iOS26.ipa
```

Or SideStore / BreakFree / Sideloadly.

## Test

```bash
# Terminal 1: capture kernel logs
python scripts/capture_logs.py

# Terminal 2: install & run the app
# Tap "EXPLOIT (UAF)" button
# Watch Terminal 1 for panic output
```

## Architecture

```
SwiftSword/
├── Exploit/IOHIDFamilyUAF.m   # CVE-2026-28992 kernel entry
├── Payload/collector.m        # SMS/Photo/Contact/Keychain/walletdb dump
├── ViewController.m           # UI + orchestrator
├── AppDelegate.m              # Minimal app delegate
├── SceneDelegate.m            # Scene setup
└── Info.plist                 # App metadata
```

## Credits

- Johnny Franks (@zeroxjf) — CVE-2026-28992 discovery
- clogan9019 — IOHIDFamily PoC
- Cyanide project — Xcode base framework
