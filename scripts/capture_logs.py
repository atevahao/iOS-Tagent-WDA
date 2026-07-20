#!/usr/bin/env python3
"""
iOS 内核日志实时捕获脚本
用法: python capture_logs.py [输出文件]
默认输出: panic_log_YYYYMMDD_HHMMSS.txt
"""

import sys
import os
from datetime import datetime
from pathlib import Path


def main():
    # 输出文件
    if len(sys.argv) > 1:
        out_path = Path(sys.argv[1])
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(f"panic_log_{ts}.txt")

    print(f"[*] 输出文件: {out_path.absolute()}")
    print("[*] 连接设备...")

    # 连接
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        ld = create_using_usbmux()
    except Exception as e:
        print(f"[!] 连接失败: {e}")
        print("[!] 请确认: USB已连接 + iPhone已解锁 + 已信任此电脑")
        sys.exit(1)

    info = ld.all_values
    print(f"[+] 设备: {info.get('DeviceName', '?')}")
    print(f"[+] iOS: {info.get('ProductVersion', '?')}")
    print(f"[+] 型号: {info.get('ProductType', '?')}")
    print(f"[+] UDID: {info.get('UniqueDeviceID', '?')}")

    # 启动 syslog 服务
    try:
        from pymobiledevice3.services.syslog import SyslogService
        svc = SyslogService(lockdown=ld)
    except Exception as e:
        print(f"[!] syslog 服务启动失败: {e}")
        sys.exit(1)

    print("[*] 正在监听内核日志... (Ctrl+C 停止)")
    print("[*] 现在在 iPhone 上: 打开 App → 点击 Panic → 打开相机")
    print("=" * 60)

    keywords = [
        "panic", "crash", "fault", "AppleJPEG", "kernel",
        "UAF", "exploit", "JpegRequest", "fullSpeed",
        "tag check", "FEEDFACE", "MTE", "IOSurface",
        "finish_io", "startDecoder", "terminate",
    ]

    line_count = 0
    matched_count = 0

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# iOS Kernel Log Capture\n")
            f.write(f"# Device: {info.get('DeviceName', '?')}\n")
            f.write(f"# iOS: {info.get('ProductVersion', '?')}\n")
            f.write(f"# Model: {info.get('ProductType', '?')}\n")
            f.write(f"# Started: {datetime.now().isoformat()}\n")
            f.write("#" + "=" * 59 + "\n\n")

            for line in svc:
                line_str = str(line)
                line_count += 1

                # 始终写入文件
                f.write(line_str + "\n")

                # 匹配关键词
                line_lower = line_str.lower()
                matched = False
                for kw in keywords:
                    if kw.lower() in line_lower:
                        matched = True
                        break

                if matched:
                    matched_count += 1
                    # 高亮输出到终端
                    if any(x in line_lower for x in ["panic", "crash", "fault", "feedface"]):
                        prefix = "[!!!]"
                    elif any(x in line_lower for x in ["applejpeg", "jpegrequest", "fullspeed"]):
                        prefix = "[JPEG]"
                    elif any(x in line_lower for x in ["kernel"]):
                        prefix = "[KERN]"
                    elif any(x in line_lower for x in ["exploit", "exploit"]):
                        prefix = "[EXP] "
                    else:
                        prefix = "[*]  "

                    print(f"{prefix} {line_str.strip()[:200]}")
                    f.flush()

                # 每 500 行输出进度
                if line_count % 500 == 0:
                    print(f"     ... {line_count} lines, {matched_count} matched ...")

                # 检测到 panic 后等待 5 秒再退出
                if "panic" in line_lower and "AppleJPEG" in line_str:
                    print("\n[!!!] 检测到 AppleJPEGDriver 内核 panic！")
                    print("[!!!] 等待 5 秒收集后续日志...")
                    import time
                    time.sleep(5)
                    break

    except KeyboardInterrupt:
        print(f"\n[*] 用户中断")
    except Exception as e:
        print(f"\n[!] 日志流中断: {e}")

    print(f"\n[*] 总计: {line_count} 行, 匹配: {matched_count} 行")
    print(f"[*] 日志已保存: {out_path.absolute()}")
    print(f"[*] 把此文件发送给我分析")


if __name__ == "__main__":
    main()
