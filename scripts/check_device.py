"""测试 iPhone USB 连接 — 多路径检测"""
import sys, ctypes, os

print("[*] 检查 iPhone USB 连接...")
print()

# 1. Windows 设备管理器层面
print("[1] Windows USB 设备:")
try:
    import subprocess
    r = subprocess.run(["pnputil", "/enum-devices"],
                       capture_output=True, text=True, timeout=10)
    for line in r.stdout.split('\n'):
        if 'Apple' in line or 'iPhone' in line or 'apple' in line.lower():
            print(f"    {line.strip()}")
except Exception as e:
    print(f"    [-]: {e}")

# 2. Apple Mobile Device 服务
print()
print("[2] Apple 服务状态:")
try:
    r = subprocess.run(["sc", "query", "Apple Mobile Device Service"],
                       capture_output=True, text=True, timeout=5)
    for line in r.stdout.split('\n'):
        if 'STATE' in line or 'RUNNING' in line or 'STOPPED' in line:
            print(f"    {line.strip()}")
except:
    pass

# 3. MobileDevice.dll 是否存在
print()
print("[3] MobileDevice.dll:")
for path in [
    r"C:\Program Files\Common Files\Apple\Mobile Device Support\MobileDevice.dll",
    r"C:\Program Files (x86)\Common Files\Apple\Mobile Device Support\MobileDevice.dll",
]:
    if os.path.exists(path):
        print(f"    [+] {path} ({os.path.getsize(path):,} bytes)")
        # 尝试加载
        try:
            dll = ctypes.CDLL(path)
            print(f"        DLL 加载成功")
        except Exception as e:
            print(f"        DLL 加载失败: {e}")
    else:
        print(f"    [-] {path} (不存在)")

# 4. iTunes 能否检测
print()
print("[4] iTunes 检测:")
print("    手动检查: 打开 iTunes → 看左上角有没有 iPhone 图标")

# 5. pymobiledevice3
print()
print("[5] pymobiledevice3:")
try:
    from pymobiledevice3.lockdown import create_using_usbmux
    ld = create_using_usbmux()
    info = ld.all_values
    print(f"    [+] 设备: {info.get('DeviceName','?')}")
    print(f"    [+] iOS:  {info.get('ProductVersion','?')}")
    print(f"    [+] 型号: {info.get('ProductType','?')}")
    print(f"    [+] UDID: {info.get('UniqueDeviceID','?')}")
    sys.exit(0)
except Exception as e:
    err = str(e)
    if not err or len(err) < 3:
        err = f"{type(e).__name__}"
    print(f"    [-] {err[:200]}")

# 6. 尝试 usbmux 直连
print()
print("[6] usbmux 直连:")
try:
    from pymobiledevice3.usbmux import list_devices
    devs = list_devices()
    if devs:
        print(f"    [+] {len(devs)} 个设备: {devs}")
    else:
        print("    [-] 未检测到")
        print("    常见原因:")
        print("    1. iTunes 未运行 → 先打开 iTunes")
        print("    2. Apple Mobile Device Service 未启动")
        print("    3. 线只充电不传数据 → 换原装线")
except Exception as e:
    print(f"    [-] {e}")

# 7. 网络备选方案
print()
print("[7] 备选方案:")
print("    爱思助手 (i4.cn) → 自带驱动，不依赖 iTunes usbmux")
print("    下载 → 安装 → 插 iPhone → 自动装驱动 → 识别")
print("    然后用它的 IPA 签名工具安装")
