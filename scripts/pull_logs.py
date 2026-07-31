#!/usr/bin/env python3
"""Pull all UAFPoc logs + crash logs from connected iPhone."""
import os
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.crash_reports import CrashReportsManager

BUNDLE_ID = "com.0xjf.UAFPoc.S3795D56VQ"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "sword_logs"))
os.makedirs(LOCAL_DIR, exist_ok=True)

print("Connecting...")
lockdown = create_using_usbmux()
info = lockdown.all_values
print(f"Device: {info.get('DeviceName','?')} | iOS {info.get('ProductVersion','?')}")

# === App Documents ===
print("\n=== App Documents ===")
ha = HouseArrestService(lockdown)
ha.send_command(BUNDLE_ID, cmd='VendContainer')

def pull_dir(rel_dir, local_subdir=None):
    """Recursively pull files from rel_dir, mirroring to local_subdir."""
    if local_subdir is None:
        local_subdir = rel_dir.replace("/", "_")
    local_dst = os.path.join(LOCAL_DIR, local_subdir) if local_subdir else LOCAL_DIR
    try:
        entries = ha.listdir(rel_dir)
    except Exception as e:
        print(f"  listdir({rel_dir}) error: {e}")
        return
    for fname in sorted(entries):
        src = f"{rel_dir}/{fname}"
        try:
            data = ha.get_file_contents(src)
        except Exception as e:
            if "not a file" not in str(e).lower():
                # Try as directory
                try:
                    pull_dir(src, os.path.join(local_subdir, fname) if local_subdir else fname)
                except:
                    pass
            continue
        dst = os.path.join(local_dst, fname) if local_subdir else os.path.join(LOCAL_DIR, fname)
        if local_subdir:
            os.makedirs(local_dst, exist_ok=True)
        with open(dst, 'wb') as f:
            f.write(data)
        show_path = f"{local_subdir}/{fname}" if local_subdir else fname
        print(f"  {show_path} ({len(data)}B)")
        # Show content for small text files
        if fname.startswith("diag") or fname.endswith(".log"):
            text = data.decode('utf-8', errors='replace')
            preview = text.strip()[:500]
            if len(text) > 500:
                preview += "\n  ...(truncated)"
            print(f"    -> {preview}")

pull_dir("Documents")

# === App tmp ===
print("\n=== App tmp ===")
try:
    for fname in sorted(ha.listdir("tmp")):
        src = f"tmp/{fname}"
        try:
            data = ha.get_file_contents(src)
            dst = os.path.join(LOCAL_DIR, fname)
            with open(dst, 'wb') as f:
                f.write(data)
            print(f"  {fname} ({len(data)}B)")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# === Crash Logs ===
print("\n=== Crash Logs ===")
try:
    cr = CrashReportsManager(lockdown)
    crash_files = sorted(cr.list(), reverse=True)
    pulled = 0
    for fname in crash_files:
        if "UAFPoc" in fname or (("panic" in fname.lower() or fname.startswith("panic")) and pulled < 3):
            dst = os.path.join(SCRIPT_DIR, fname)
            if not os.path.exists(dst):
                data = cr.get(fname)
                with open(dst, 'wb') as f:
                    f.write(data)
                print(f"  {fname} ({len(data)}B)")
                pulled += 1
            else:
                print(f"  (exists) {fname}")
except Exception as e:
    print(f"  Error: {e}")

print(f"\nDone. -> {LOCAL_DIR}")
