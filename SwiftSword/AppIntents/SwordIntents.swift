import Foundation

@objc public class SwordAppIntentBridge: NSObject {

    @objc public func enumerateDirectory(_ dirPath: String) -> String {
        let fm = FileManager.default
        let base = "../../../../../../../../../../../../../"
        let fullPath = (base + dirPath as NSString).expandingTildeInPath

        var result = "[Swift Bridge]\n"
        result += "target: \(fullPath)\n"

        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: fullPath, isDirectory: &isDir)
        result += "exists: \(exists), isDir: \(isDir.boolValue)\n"

        if exists && isDir.boolValue {
            if let contents = try? fm.contentsOfDirectory(atPath: fullPath) {
                result += "Foundation contentsOfDir: \(contents.count) entries\n"
                for entry in contents.prefix(200) {
                    result += "  \(entry)\n"
                }
            } else {
                result += "Foundation contentsOfDir: FAILED\n"
            }
        } else if exists {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: fullPath)) {
                result += "file size: \(data.count) bytes\n"
                let hex = data.prefix(64).map { String(format: "%02x", $0) }.joined(separator: " ")
                result += "hex (first 64): \(hex)\n"
                if data.count >= 16 && data.prefix(16) == Data("SQLite format 3".utf8) {
                    result += "type: SQLite3\n"
                }
            }
        } else {
            result += "NOT FOUND\n"
        }
        return result
    }

    @objc public func probePath(_ relPath: String) -> String {
        let base = "../../../../../../../../../../../../../"
        let fullPath = (base + relPath as NSString).expandingTildeInPath
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: fullPath, isDirectory: &isDir)
        if exists {
            let attrs = try? fm.attributesOfItem(atPath: fullPath)
            let sz = attrs?[.size] as? UInt64 ?? 0
            return "[+] \(relPath) (\(sz) bytes)\(isDir.boolValue ? " [DIR]" : "")"
        }
        return "[-] \(relPath)"
    }
}
