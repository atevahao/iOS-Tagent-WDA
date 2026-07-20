# iOS 26.2 Kernel Exploit — iPhone 12 Pro Max (A14)

基于 CVE-2026-20687 AppleJPEGDriver UAF + pois0nSword 后利用框架

## 编译 IPA (自动)

1. 把这个仓库推到 GitHub
2. Actions → Build iOS 26.2 Exploit IPA → Run workflow
3. 下载 artifact `exploit_A14_iOS26`

## 安装到 iPhone

```bash
# Windows 上 (需要 pymobiledevice3)
pymobiledevice3 apps install exploit_A14_iOS26.ipa

# 或 SideStore / BreakFree
```

## 运行

1. 打开 App → 点 Panic 按钮
2. 打开相机 App 触发内核 UAF

## 实时调试

```bash
# 终端抓内核日志
python test_device.py
```

## 依赖

| 项目 | 作用 |
|------|------|
| [zeroxjf/CVE-2026-20687](https://github.com/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF) | Xcode 项目框架 + IOKit 利用 |
| [GenericCoding/pois0nSword](https://github.com/GenericCoding/pois0nSword) | PAC 绕过 + 后利用 |

## 状态

- [ ] 第1步: UAF → PC 控制
- [ ] 第2步: PC → 内核 r/w
- [ ] 第3步: r/w → 提权
- [ ] 第4步: Keychain dump
- [ ] 第5步: TRON 私钥
