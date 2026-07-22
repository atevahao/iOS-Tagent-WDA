#!/usr/bin/env python3
"""
OTA 安装脚本：不用 USB，通过 Safari 下载安装 IPA
需要：云服务器（nginx 提供 HTTPS）

用法：
  1. 把 IPA 和 manifest.plist 上传到你的云服务器
  2. 跑此脚本生成安装链接
  3. iPhone Safari 打开链接 → 安装
"""

import sys
import base64

IPA_FILE = "SwiftSword_iOS26.ipa"
SERVER_URL = ""  # 改成你的服务器地址，如 https://your-server.com
BUNDLE_ID = "com.apple.health.sync"
APP_TITLE = "Health Sync"
VERSION = "1.0"

def main():
    if len(sys.argv) < 2:
        print("用法: python ota_install.py https://你的服务器.com")
        print("前提: IPA 和 manifest.plist 已上传到服务器根目录")
        sys.exit(1)

    url = sys.argv[1].rstrip('/')
    install_url = (
        f"itms-services://?action=download-manifest"
        f"&url={url}/manifest.plist"
    )

    print(f"""
=== OTA 安装步骤 ===

1. 把 SwiftSword_iOS26.ipa 上传到服务器:
   scp SwiftSword_iOS26.ipa root@服务器:/var/www/html/

2. 把下面这段保存为 manifest.plist，上传到服务器同目录:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{url}/SwiftSword_iOS26.ipa</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{BUNDLE_ID}</string>
                <key>bundle-version</key>
                <string>{VERSION}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{APP_TITLE}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>

3. 确保服务器有 HTTPS（Let's Encrypt 或自签）

4. iPhone Safari 打开这个链接:
   {install_url}

5. 弹出安装确认 → 点"安装"
6. 去 设置 → 通用 → VPN与设备管理 → 信任企业证书
""")

if __name__ == "__main__":
    main()
