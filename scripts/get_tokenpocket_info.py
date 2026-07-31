"""Get TokenPocket container info from connected iPhone using pymobiledevice3"""
import sys
sys.path.insert(0, r"D:\PythonProject\.venv\Lib\site-packages")

from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux

def main():
    devices = list_devices()
    if not devices:
        print("[-] No iOS device connected")
        return

    device = devices[0]
    print(f"[+] Device: {device.serial}")

    lockdown = create_using_usbmux(serial=device.serial)
    print(f"[+] Connected: {lockdown.all_values.get('DeviceName', 'unknown')}")

    # Get installation_proxy service
    print("[*] Starting installation_proxy service...")
    service = lockdown.start_lockdown_service("com.apple.mobile.installation_proxy")
    print(f"[+] Service connected")

    # Use the lower-level plist protocol
    # installation_proxy uses XML plists over the lockdown service

    # Browse: list all installed apps
    import plistlib
    browse_cmd = {
        "Command": "Browse",
        "ClientOptions": {
            "ApplicationType": "User",
            "ReturnAttributes": [
                "CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName",
                "CFBundleVersion", "CFBundleShortVersionString",
                "Container", "Path", "ApplicationType"
            ]
        }
    }
    print("[*] Sending Browse command...")
    service.send_plist(browse_cmd)

    tp_info = None
    bundle_id = "com.global.wallet.ios"
    all_apps = []

    while True:
        try:
            resp = service.recv_plist()
            status = resp.get("Status", "")
            if status == "Complete":
                print(f"[*] Browse complete: {resp}")
                break
            # Each app entry
            for entry in resp.get("CurrentList", []):
                bid = entry.get("CFBundleIdentifier", "")
                name = entry.get("CFBundleDisplayName", entry.get("CFBundleName", "?"))
                all_apps.append(bid)
                if bid == bundle_id:
                    tp_info = entry
                # Also check for wallet/token related
                if any(kw in bid.lower() or kw in name.lower()
                       for kw in ["tokenpocket", "global.wallet", "tron"]):
                    print(f"\n[!!!] FOUND: {bid} - {name}")
                    print(f"  {entry}")
        except Exception as e:
            print(f"Error parsing response: {e}")
            import traceback
            traceback.print_exc()
            break

    if tp_info:
        print(f"\n=== TokenPocket Found! ===")
        for k, v in sorted(tp_info.items()):
            print(f"  {k}: {v}")
        container = tp_info.get("Container", "N/A")
        print(f"\n  Container path: {container}")
        if container and container != "N/A":
            uuid = container.rstrip("/").split("/")[-1]
            print(f"  Data UUID: {uuid}")
            with open("scripts/tokenpocket_uuid.txt", "w") as f:
                f.write(f"bundle_id={bundle_id}\ncontainer={container}\nuuid={uuid}\n")
            print("  [+] Saved to scripts/tokenpocket_uuid.txt")
    else:
        print(f"\n[-] TokenPocket ({bundle_id}) not found")
        print(f"[*] Total apps found: {len(all_apps)}")
        print("[*] All bundle IDs:")
        for bid in all_apps:
            marker = " <---" if "wallet" in bid.lower() or "token" in bid.lower() else ""
            print(f"  {bid}{marker}")

if __name__ == "__main__":
    main()
