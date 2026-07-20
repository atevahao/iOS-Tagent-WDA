#!/usr/bin/env python3
"""
iOS Kernel Panic Log Capture
用法: python capture_logs.py [输出文件]
Windows + iPhone 12 Pro Max 专用

流程:
  1. USB连接iPhone → 启动监听
  2. iPhone上打开SwiftSword → 点EXPLOIT
  3. 设备kernel panic → 重启 → USB断开
  4. 脚本检测断开 → 自动等待重连 → 继续抓重启后的日志
"""

import sys
import time
from datetime import datetime
from pathlib import Path


def connect():
    """连接设备，返回 (lockdown, info_dict)"""
    from pymobiledevice3.lockdown import create_using_usbmux
    ld = create_using_usbmux()
    info = ld.all_values
    return ld, info


def wait_for_device(timeout=120):
    """等待设备重新连接（reboot后USB需要时间恢复）"""
    print("[*] Waiting for device to reconnect...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            from pymobiledevice3.usbmux import list_devices
            devs = list_devices()
            if devs:
                time.sleep(3)  # 等 lockdown 服务完全启动
                return True
        except Exception:
            pass
        time.sleep(2)
        print("  .", end="", flush=True)
    print("")
    return False


def stream_logs(ld, out_file, label):
    """持续读取 syslog 直到设备断开"""
    from pymobiledevice3.services.syslog import SyslogService

    svc = SyslogService(lockdown=ld)

    keywords = [
        "panic", "crash", "fault", "kernel", "IOHID", "UAF",
        "FastPath", "copyEvent", "close", "MTE", "FEEDFACE",
        "data abort", "AppleJPEG", "AppleKeyStore",
        "DARWIN", "xnu", "debugger", "Debugger",
    ]

    line_count = 0
    matched_count = 0

    with open(out_file, "a", encoding="utf-8") as f:
        f.write(f"\n# [{label}] Started at {datetime.now()}\n\n")

        try:
            for line in svc:
                s = str(line)
                f.write(s + "\n")
                line_count += 1

                s_lower = s.lower()
                for kw in keywords:
                    if kw.lower() in s_lower:
                        matched_count += 1
                        tag = "[PANIC]" if "panic" in s_lower else \
                              "[KERN]" if "kernel" in s_lower else \
                              "[IOHID]" if "iohid" in s_lower else \
                              "[FAULT]" if "fault" in s_lower else "[*]"
                        print(f"{tag} {s.strip()[:250]}")
                        f.flush()
                        break

                if line_count % 500 == 0:
                    print(f"     ... {line_count} lines, {matched_count} matched ...")
        except Exception as e:
            print(f"[*] Stream ended: {e}")
            print(f"[*] Session: {line_count} lines, {matched_count} matched")

    return line_count, matched_count


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else \
          Path(f"panic_log_{datetime.now():%Y%m%d_%H%M%S}.txt")

    print("=" * 60)
    print("  iOS Kernel Panic Log Capturer")
    print(f"  Output: {out}")
    print("=" * 60)

    # Round 1: Pre-panic
    print("\n[*] Connecting to device...")
    ld, info = connect()
    print(f"[+] {info.get('DeviceName', '?')}")
    print(f"[+] iOS {info.get('ProductVersion', '?')}")
    print(f"[+] Model {info.get('ProductType', '?')}")

    with open(out, "w") as f:
        f.write(f"# Device: {info.get('DeviceName', '?')}\n")
        f.write(f"# iOS:    {info.get('ProductVersion', '?')}\n")
        f.write(f"# Model:  {info.get('ProductType', '?')}\n")
        f.write(f"# UDID:   {info.get('UniqueDeviceID', '?')}\n")
        f.write(f"# Started {datetime.now()}\n")
        f.write("#" + "=" * 59 + "\n")

    print("\n[*] NOW: Open SwiftSword → tap EXPLOIT (UAF)")
    print("[*] Watching kernel logs...")
    print("=" * 60)

    total_lines, total_matched = stream_logs(ld, out, "PRE-PANIC")

    # Wait for device to come back after reboot
    if wait_for_device():
        print("\n[+] Device is back online — capturing post-reboot logs")
        try:
            ld2, info2 = connect()
            print(f"[+] {info2.get('DeviceName', '?')} iOS {info2.get('ProductVersion', '?')}")
            l, m = stream_logs(ld2, out, "POST-REBOOT")
            total_lines += l
            total_matched += m
        except Exception as e:
            print(f"[!] Post-reboot capture failed: {e}")

    print(f"\n{'=' * 60}")
    print(f"  Total: {total_lines} lines, {total_matched} matched")
    print(f"  Log saved to: {out.absolute()}")
    print(f"  Send this file for analysis")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
