#!/usr/bin/env python3
"""iOS kernel panic log capturer — run BEFORE triggering exploit"""
import sys
from datetime import datetime
from pathlib import Path

def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else \
          Path(f"panic_log_{datetime.now():%Y%m%d_%H%M%S}.txt")

    print(f"[*] Output: {out}")
    print("[*] Connecting...")

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.syslog import SyslogService

    ld = create_using_usbmux()
    info = ld.all_values
    print(f"[+] {info.get('DeviceName','?')} iOS {info.get('ProductVersion','?')}")

    svc = SyslogService(lockdown=ld)
    keywords = ["panic","crash","fault","kernel","IOHID","UAF",
                "FastPath","copyEvent","close","MTE","FEEDFACE",
                "data abort","AppleJPEG","AppleKeyStore"]

    print("[*] Now trigger the exploit on your iPhone")
    print("="*60)

    n = 0
    with open(out, "w") as f:
        f.write(f"# Device: {info.get('DeviceName','?')}\n")
        f.write(f"# iOS: {info.get('ProductVersion','?')}\n")
        f.write(f"# Time: {datetime.now()}\n\n")
        for line in svc:
            s = str(line); f.write(s+"\n"); n += 1
            if any(k in s.lower() for k in keywords):
                print(f"[!!!] {s.strip()[:250]}")
            if n % 500 == 0: print(f"  ... {n} lines ...")
    print(f"\n[*] {n} lines saved to {out}")

if __name__ == "__main__":
    main()
