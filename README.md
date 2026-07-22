# SwiftSword — iOS 26.2 TRON Wallet Private Key Extraction

## Target

iPhone 12 Pro Max (A14) • iOS 26.2 • TokenPocket / imToken

A14 has no MTE → kernel UAF directly exploitable.

## Architecture

```
SwiftSword App (installed via Sideloadly)
│
├─ Step 1: Kernel Entry
│   IOHIDFamily FastPathUserClient UAF
│   CVE-2026-28992 • Zero Entitlements • Pre-A17 = Data Abort
│
├─ Step 2: Post-Exploitation
│   Kernel r/w → Root → Sandbox Escape → Keychain Access
│   PAC Bypass: CVE-2026-20700 (unpatched on 26.2)
│
├─ Step 3: Data Extraction
│   Keychain → KeyPal2 key → walletdb decrypt → TRON private key
│   Collector: SMS / Photos / Contacts / Keychain / TP walletdb
│
└─ Step 4: Exfiltration
    HTTPS POST to C2 server
```

## Dependencies (GitHub Repos)

| Repo | Usage | Status |
|------|-------|--------|
| [zeroxjf/cyanide](https://github.com/zeroxjf/cyanide) | Xcode project shell + kexploit framework | Build base |
| [clogan9019/IOHIDFamily-PoC-Research](https://github.com/clogan9019-dotcom/IOHIDFamily-PoC-Research) | CVE-2026-28992 kernel entry | Kernel exploit |
| [GenericCoding/pois0nSword](https://github.com/GenericCoding/pois0nSword) | PAC bypass (CVE-2026-20700) + atexit state mgmt | Post-exploitation |

## Project Structure

```
SwiftSword/
├── Exploit/
│   └── IOHIDFamilyUAF.m        # CVE-2026-28992: 15 conns, 8 threads, 200 rounds
├── Payload/
│   └── collector.m             # File dump + C2 upload (dead code until Step1 succeeds)
├── ViewController.m            # UI + 3-phase orchestrator
└── Info.plist                  # com.apple.health.sync
scripts/
├── capture_logs.py             # Live kernel panic log capture with auto-reconnect
└── check_device.py             # USB connection test
```

## Build & Install

1. Push to GitHub → Actions → Build → Download IPA
2. Sideloadly: drag IPA → sign with free Apple ID → install
3. Trust cert: Settings → General → VPN & Device Management

## Test

```bash
python scripts/capture_logs.py
# iPhone: open SwiftSword → tap EXPLOIT (UAF)
# Watch for [PANIC]/[IOHID]/[KERN] markers
```

## Status

| Phase | State |
|-------|-------|
| IPA Compilation | GitHub Actions configured |
| USB Connection | Troubleshooting data cable |
| Step 1: UAF Trigger | Ready for testing |
| Step 2: Kernel r/w | Pending Step 1 logs |
| Step 3: Key Extraction | Code written, dead until Step 2 |
