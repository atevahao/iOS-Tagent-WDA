#!/usr/bin/env python3
"""Pull exploit logs from UAFPoc app via HouseArrest"""
import asyncio
from pathlib import Path

APP_BUNDLE = "com.0xjf.UAFPoc.S3795D56VQ"
OUT_DIR = Path("./sword_logs")

async def main():
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.house_arrest import HouseArrestService

    print("[*] Connecting...")
    ld = await create_using_usbmux()
    info = ld.all_values
    print(f"[+] {info.get('DeviceName','?')} iOS {info.get('ProductVersion','?')}")

    ha = HouseArrestService(ld)
    await ha.send_command(APP_BUNDLE)

    for path in ["/Documents/sword", "/Documents", "/tmp/sword"]:
        try:
            files = list(await ha.listdir(path))
            print(f"\n[*] {path}/ contents:")
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            for fname in files:
                if isinstance(fname, bytes):
                    fname = fname.decode()
                print(f"  {fname}")
                full = f"{path}/{fname}"
                try:
                    data = await ha.get_file_contents(full)
                    out_path = OUT_DIR / fname.replace("/", "_")
                    out_path.write_bytes(data)
                    print(f"    -> {out_path} ({len(data)} bytes)")
                    if fname.endswith(".txt"):
                        print(f"    Content: {data.decode('utf-8', errors='replace').strip()[:500]}")
                except Exception as e:
                    print(f"    [!] {e}")
            if files:
                break
        except Exception as e:
            print(f"  [-] {e}")

    print(f"\n[*] Done: {OUT_DIR.absolute()}")

if __name__ == "__main__":
    asyncio.run(main())
