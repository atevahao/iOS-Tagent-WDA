"""测试 iPhone USB 连接"""
import sys

print("[*] 检查 iPhone USB 连接...")

# 方法1: pymobiledevice3
try:
    from pymobiledevice3.lockdown import create_using_usbmux
    ld = create_using_usbmux()
    info = ld.all_values
    print(f"[+] pymobiledevice3 检测到设备:")
    print(f"    名称: {info.get('DeviceName', '?')}")
    print(f"    iOS:  {info.get('ProductVersion', '?')}")
    print(f"    型号: {info.get('ProductType', '?')}")
    print(f"    UDID: {info.get('UniqueDeviceID', '?')}")
    sys.exit(0)
except Exception as e:
    print(f"[-] pymobiledevice3: {e}")

# 方法2: Apple Mobile Device 服务
try:
    import subprocess
    r = subprocess.run(["sc", "query", "Apple Mobile Device Service"],
                       capture_output=True, text=True)
    if "RUNNING" in r.stdout:
        print("[+] Apple Mobile Device Service 正在运行")
    else:
        print("[-] Apple Mobile Device Service 未运行")
except Exception:
    print("[-] 无法检查服务状态")

# 方法3: usbmuxd
try:
    from pymobiledevice3.usbmux import list_devices
    devs = list_devices()
    if devs:
        print(f"[+] usbmux 检测到 {len(devs)} 个设备")
        for d in devs:
            print(f"    {d}")
    else:
        print("[-] usbmux 未检测到设备")
        print("[*] 请检查:")
        print("    1. USB 数据线连接")
        print("    2. iPhone 已解锁")
        print("    3. 点'信任此电脑'")
        print("    4. iTunes 桌面版已安装 (非 Microsoft Store 版)")
except Exception as e:
    print(f"[-] usbmux: {e}")

print("\n[*] Sideloadly 不识别设备时的排查:")
print("    1. 卸载 Microsoft Store 版 iTunes")
print("    2. 从 apple.com 下载 iTunes 桌面版重新安装")
print("    3. 重启电脑")
print("    4. 重新打开 Sideloadly")
