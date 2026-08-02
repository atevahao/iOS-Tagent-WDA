#!/usr/bin/env python3
"""Download iOS IPSW or just the kernelcache file from within it."""
import urllib.request
import json
import os
import sys
import struct
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

def http_get(url, range_header=None):
    """Make an HTTP GET request, optionally with Range header."""
    headers = {"User-Agent": "Mozilla/5.0"}
    if range_header:
        headers["Range"] = range_header
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req)

def download_kernelcache(url, out_dir):
    """Download just the kernelcache file from inside the IPSW zip (~30MB).

    The IPSW is a ZIP file. We download the central directory from the end,
    find the kernelcache entry, then download just that file via Range request.
    """
    # Get file size
    resp = http_get(url, range_header="bytes=0-0")
    ipsw_size = int(resp.headers["Content-Range"].split("/")[1])
    print(f"IPSW total size: {ipsw_size / (1024**3):.1f} GB")

    # Download last 128KB to get EOCD + central directory
    eocd_download = 131072
    download_size = min(eocd_download, ipsw_size)
    print(f"Fetching ZIP directory (last {download_size/1024:.0f} KB)...")

    resp = http_get(url, range_header=f"bytes={ipsw_size - download_size}-{ipsw_size - 1}")
    tail = resp.read()

    # Find EOCD signature PK\x05\x06
    eocd_off = None
    for i in range(len(tail) - 22, -1, -1):
        if tail[i:i+4] == b'PK\x05\x06':
            eocd_off = i
            break
    if eocd_off is None:
        print("ERROR: Cannot find ZIP EOCD")
        sys.exit(1)

    tail_start = ipsw_size - download_size

    eocd = tail[eocd_off:]
    cd_size = struct.unpack("<I", eocd[12:16])[0]
    cd_offset = struct.unpack("<I", eocd[16:20])[0]

    # Check for ZIP64 (IPSW > 4GB)
    is_zip64 = (cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF)

    if is_zip64:
        print("ZIP64 detected (IPSW > 4GB)")
        # ZIP64 EOCD Locator is 20 bytes before standard EOCD
        locator = tail[eocd_off - 20:eocd_off]
        if locator[:4] == b'PK\x06\x07':
            zip64_eocd_off = struct.unpack("<Q", locator[8:16])[0]
            print(f"ZIP64 EOCD at offset {zip64_eocd_off}")

            # ZIP64 EOCD: 4B sig + 8B size + 2B version + 2B min_version + 4B disk + 4B disk_count
            # + 8B total_entries + 8B total_entries + 8B cd_size + 8B cd_offset
            # = 56 bytes minimum
            if zip64_eocd_off >= tail_start:
                off = zip64_eocd_off - tail_start
                zip64_eocd = tail[off:]
            else:
                zip64_size = 56 + 1024  # generous
                resp = http_get(url,
                    range_header=f"bytes={zip64_eocd_off}-{zip64_eocd_off + zip64_size}")
                zip64_eocd = resp.read()

            if zip64_eocd[:4] == b'PK\x06\x06':
                cd_size = struct.unpack("<Q", zip64_eocd[40:48])[0]
                cd_offset = struct.unpack("<Q", zip64_eocd[48:56])[0]
                print(f"ZIP64 central directory: offset={cd_offset} size={cd_size}")
            else:
                print(f"ERROR: ZIP64 EOCD signature not found at {zip64_eocd_off}")
                sys.exit(1)
        else:
            print("ERROR: ZIP64 locator not found")
            sys.exit(1)

    print(f"Central directory: offset={cd_offset} size={cd_size}")

    # Download central directory if not fully in tail
    if cd_offset < tail_start:
        # Need to download more
        need = cd_offset + cd_size
        resp = http_get(url, range_header=f"bytes={cd_offset}-{need - 1}")
        cd_data = resp.read()
    else:
        off = cd_offset - tail_start
        cd_data = tail[off:off + cd_size]

    print(f"Parsing {len(cd_data)} bytes of file listings...")

    # Parse central directory
    def parse_zip64_extra(extra_data, comp_is_64, uncomp_is_64, off_is_64):
        """Extract ZIP64 8-byte values from the extra field."""
        result = {}
        p = 0
        while p < len(extra_data) - 4:
            tag = struct.unpack("<H", extra_data[p:p+2])[0]
            size = struct.unpack("<H", extra_data[p+2:p+4])[0]
            if tag == 0x0001:
                data = extra_data[p+4:p+4+size]
                dp = 0
                if uncomp_is_64 and dp + 8 <= len(data):
                    result["uncomp_size"] = struct.unpack("<Q", data[dp:dp+8])[0]
                    dp += 8
                if comp_is_64 and dp + 8 <= len(data):
                    result["comp_size"] = struct.unpack("<Q", data[dp:dp+8])[0]
                    dp += 8
                if off_is_64 and dp + 8 <= len(data):
                    result["local_off"] = struct.unpack("<Q", data[dp:dp+8])[0]
                    dp += 8
                break
            p += 4 + size
        return result

    best_kc = None
    pos = 0
    while pos < len(cd_data) - 46:
        if cd_data[pos:pos+4] == b'PK\x01\x02':
            comp_size = struct.unpack("<I", cd_data[pos+20:pos+24])[0]
            uncomp_size = struct.unpack("<I", cd_data[pos+24:pos+28])[0]
            name_len = struct.unpack("<H", cd_data[pos+28:pos+30])[0]
            extra_len = struct.unpack("<H", cd_data[pos+30:pos+32])[0]
            comment_len = struct.unpack("<H", cd_data[pos+32:pos+34])[0]
            local_off = struct.unpack("<I", cd_data[pos+42:pos+46])[0]
            name = cd_data[pos+46:pos+46+name_len].decode('utf-8', errors='replace')

            # ZIP64: resolve 64-bit values from extra field when 32-bit overflowed
            comp_is_64 = (comp_size == 0xFFFFFFFF)
            uncomp_is_64 = (uncomp_size == 0xFFFFFFFF)
            off_is_64 = (local_off == 0xFFFFFFFF)
            if comp_is_64 or off_is_64:
                extra_start = pos + 46 + name_len
                extra_data = cd_data[extra_start:extra_start + extra_len]
                zip64 = parse_zip64_extra(extra_data, comp_is_64, uncomp_is_64, off_is_64)
                if "comp_size" in zip64:
                    comp_size = zip64["comp_size"]
                if "local_off" in zip64:
                    local_off = zip64["local_off"]

            if 'kernelcache' in name.lower():
                print(f"  Found: {name} ({comp_size/1024/1024:.1f} MB)")
                # Prefer the release variant (not development/kernel)
                is_dev = 'development' in name.lower() or name.endswith('.kernel')
                if best_kc is None or (not is_dev):
                    best_kc = {
                        "name": name,
                        "comp_size": comp_size,
                        "local_off": local_off,
                    }
                    if not is_dev:
                        break  # found the right one
            pos += 46 + name_len + extra_len + comment_len
        else:
            pos += 1

    if not best_kc:
        print("ERROR: No kernelcache found in IPSW")
        sys.exit(1)

    print(f"Downloading: {best_kc['name']}")
    print(f"Compressed size: {best_kc['comp_size']/1024/1024:.1f} MB")

    # Download local header + compressed data
    # Local file header is 30 bytes + name_len + extra_len,
    # but we don't know extra_len until we read it.
    # Download a safe margin first, then read more if needed
    header_guess = 30 + len(best_kc["name"]) + 512
    start = best_kc["local_off"]
    first_chunk_size = min(header_guess + best_kc["comp_size"],
                           ipsw_size - start)

    resp = http_get(url, range_header=f"bytes={start}-{start + first_chunk_size - 1}")
    raw = resp.read()

    # Parse local file header
    name_len = struct.unpack("<H", raw[26:28])[0]
    extra_len = struct.unpack("<H", raw[28:30])[0]
    data_start = 30 + name_len + extra_len
    data = raw[data_start:]

    # If we didn't get enough, download the rest
    if len(data) < best_kc["comp_size"]:
        remaining = best_kc["comp_size"] - len(data)
        rest_start = start + len(raw)
        print(f"  Fetching remaining {remaining/1024:.0f} KB...")
        resp = http_get(url, range_header=f"bytes={rest_start}-{rest_start + remaining - 1}")
        data = data + resp.read()

    kc_name = f"kernelcache.{best_kc['name'].rsplit('.', 1)[-1] if '.' in best_kc['name'] else 'release'}"
    kc_path = os.path.join(out_dir, kc_name)
    with open(kc_path, "wb") as f:
        f.write(data[:best_kc["comp_size"]])

    print(f"Saved: {kc_path} ({len(data[:best_kc['comp_size']])/1024/1024:.1f} MB)")
    return kc_path

def download_full(url, dest):
    """Download a full file with progress reporting."""
    chunk_size = 8 * 1024 * 1024
    resp = http_get(url)
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
                print(f"\r  {downloaded/(1024**2):.0f}/{total/(1024**2):.0f} MB ({pct:.0f}%)",
                      end="", flush=True)
    print()

def main():
    parser = argparse.ArgumentParser(description="Download iOS IPSW or kernelcache")
    parser.add_argument("--device", default="iPhone14,5",
                        help="Device identifier (default: iPhone14,5 = iPhone 13)")
    parser.add_argument("--build", default="23C55",
                        help="Build ID (default: 23C55 = iOS 26.2)")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: current dir)")
    parser.add_argument("--kernelcache-only", action="store_true",
                        help="Download only kernelcache (~30MB) instead of full IPSW (~9GB)")
    args = parser.parse_args()

    out_dir = args.output or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)

    print(f"Device: {args.device}  |  Build: {args.build}")

    url, version, size_gb = get_ipsw_url(args.device, args.build)
    if not url:
        print(f"ERROR: No IPSW found for {args.device} build {args.build}")
        sys.exit(1)

    print(f"Version: {version}  |  IPSW size: {size_gb:.1f} GB")
    print(f"URL: {url}")

    if args.kernelcache_only:
        print("\n--- Kernelcache-only mode (~30 MB) ---")
        download_kernelcache(url, out_dir)
    else:
        fname = os.path.basename(url)
        dest = os.path.join(out_dir, fname)
        print(f"File: {dest}")
        if os.path.exists(dest):
            try:
                resp = http_get(url, range_header="bytes=0-0")
                remote_size = int(resp.headers["Content-Range"].split("/")[1])
                if os.path.getsize(dest) == remote_size:
                    print(f"Already downloaded ({remote_size/(1024**3):.1f} GB).")
                    return dest
            except:
                pass
        print("Downloading full IPSW...")
        download_full(url, dest)
        print(f"Done: {dest}")
        return dest

if __name__ == "__main__":
    main()
