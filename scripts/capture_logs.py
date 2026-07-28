#!/usr/bin/env python3
"""iOS Kernel Panic Log Capture (async v2.18+)"""
import sys, time, asyncio
from datetime import datetime
from pathlib import Path

async def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(f"panic_log_{datetime.now():%Y%m%d_%H%M%S}.txt")
    print("=" * 60)
    print(f"  iOS Kernel Panic Log Capture")
    print(f"  Output: {out}")
    print("=" * 60)

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.syslog import SyslogService

    ld = await create_using_usbmux()
    info = ld.all_values
    print(f"[+] {info.get('DeviceName','?')} iOS {info.get('ProductVersion','?')} Model {info.get('ProductType','?')}")

    keywords = ["panic","crash","fault","kernel","IOHID","UAF",
                "FastPath","copyEvent","close","MTE","FEEDFACE",
                "data abort","DARWIN","xnu","debugger"]

    print("\n[*] iPhone: open UAFPoc → tap Trigger UAF")
    print("[*] Watching kernel logs...\n")

    n = 0
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# Device: {info.get('DeviceName','?')} iOS {info.get('ProductVersion','?')}\n")
        f.write(f"# Time: {datetime.now()}\n\n")

        svc = SyslogService(service_provider=ld)
        try:
            async for line in svc.watch():
                s = str(line); f.write(s + "\n"); n += 1
                for kw in keywords:
                    if kw.lower() in s.lower():
                        tag = "[PANIC]" if "panic" in s.lower() else "[KERN]" if "kernel" in s.lower() else "[*]"
                        print(f"{tag} {s.strip()[:250]}")
                        break
                if n % 500 == 0:
                    print(f"  ... {n} lines ...")
        except Exception as e:
            print(f"\n[*] Stream ended: {e}")

    print(f"\n[*] {n} lines → {out}")

if __name__ == "__main__":
    asyncio.run(main())
