#!/usr/bin/env python3
"""Download iOS IPSW and extract kernelcache for a given device/build."""
import urllib.request
import json
import os
import sys
import argparse

def get_ipsw_url(device, build):
    """Get the IPSW download URL for a device+build from ipsw.me API."""
    url = f"https://api.ipsw.me/v4/device/{device}?type=ipsw"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    data = json.loads(urllib.request.urlopen(req).read())
    for fw in data["firmwares"]:
        if fw["buildid"] == build:
            return fw["url"], fw["version"], fw["filesize"] / (1024**3)
    return None, None, None

def download(url, dest, chunk_size=8 * 1024 * 1024):
    """Download a file with progress reporting."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    resp = urllib.request.urlopen(req)
    total = int(resp.headers.get("Content-Length", 0))
    downloaded = 0
    with open(dest, "wb") as f:
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded / total * 100
                mb = downloaded / (1024 * 1024)
                total_mb = total / (1024 * 1024)
                print(f"\r  {mb:.0f}/{total_mb:.0f} MB ({pct:.0f}%)", end="", flush=True)
    print()

def main():
    parser = argparse.ArgumentParser(description="Download iOS IPSW")
    parser.add_argument("--device", default="iPhone14,5", help="Device identifier (default: iPhone14,5 = iPhone 13)")
    parser.add_argument("--build", default="23C55", help="Build ID (default: 23C55 = iOS 26.2)")
    parser.add_argument("--output", default=None, help="Output directory (default: current dir)")
    args = parser.parse_args()

    out_dir = args.output or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== iOS IPSW Downloader ===")
    print(f"Device: {args.device}")
    print(f"Build:  {args.build}")

    url, version, size_gb = get_ipsw_url(args.device, args.build)
    if not url:
        print(f"ERROR: No IPSW found for {args.device} build {args.build}")
        sys.exit(1)

    fname = os.path.basename(url)
    dest = os.path.join(out_dir, fname)

    print(f"Version: {version}")
    print(f"Size:    {size_gb:.1f} GB")
    print(f"URL:     {url}")
    print(f"File:    {dest}")

    if os.path.exists(dest):
        remote_size = None
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
            remote_size = int(urllib.request.urlopen(req).headers.get("Content-Length", 0))
        except:
            pass
        local_size = os.path.getsize(dest)
        if remote_size and local_size == remote_size:
            print(f"Already downloaded ({local_size / (1024**3):.1f} GB). Skipping.")
            return dest
        else:
            print(f"Partial download ({local_size / (1024**3):.1f} GB). Re-downloading...")

    print("Downloading...")
    download(url, dest)
    print(f"Done: {dest}")
    return dest

if __name__ == "__main__":
    main()
