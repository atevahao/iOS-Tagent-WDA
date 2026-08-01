/*
 * rie_child.c — minimal suspended-target helper for iOS Rie reslide probe.
 *
 * Spawned by ViewController.m with POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE.
 * The kernel finishes exec (vm_map_exec -> vm_shared_region_enter binds a fresh, EMPTY
 * reslide region), then leaves the task SUSPENDED — BEFORE dyld runs. main() never executes.
 *
 * The host hijacks the suspended main thread, sets PC = child_probe (this image's signed
 * __TEXT), and resumes. child_probe() runs PRE-DYLD, so it MUST use ONLY raw svc syscalls
 * (no libc, no GOT, no lazy binding).
 *
 * child_probe() calls shared_region_check_np (#294) and exits:
 *   exit 12 (ENOMEM) -> region BOUND-but-EMPTY => viable #536 FIRST-MAPPER  [WANT]
 *   exit  0          -> region already populated
 *   exit 22 (EINVAL) -> no region bound at all
 *
 * child_trigger() is the real exploit payload (syscall 536) — for future use.
 *
 * arm64 (non-e) so the host's thread_set_state needs no PAC handling.
 * Signed with get-task-allow so same-uid host can task_for_pid() it.
 */
#include <unistd.h>
#include <stdint.h>

/* runs pre-dyld: raw syscalls only, never returns.
 * Called with no arguments (host hijacks main thread and sets PC here). */
__attribute__((noinline, used, visibility("default")))
void child_probe(void)
{
    unsigned long long scratch = 0;
    long carry = 0, rc = 0;

    /* syscall 294 = shared_region_check_np(&scratch) */
    {
        register long x16 asm("x16") = 294;
        register long x0  asm("x0")  = (long)&scratch;
        asm volatile(
            "svc #0x80\n\t"
            "cset %1, cs\n\t"
            : "+r"(x0), "=r"(carry)
            : "r"(x16)
            : "cc", "memory");
        rc = x0;
    }

    long code = carry ? (rc & 0xff) : 0;   /* errno on error, else 0 */

    /* syscall 1 = exit(code) */
    {
        register long x16 asm("x16") = 1;
        register long x0  asm("x0")  = code;
        asm volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "cc", "memory");
    }
    __builtin_unreachable();
}

/*
 * child_trigger(cfg) — real exploit payload (syscall 536 + fault sweep).
 * Stub for future use; the host passes x0 = address of injected sr_cfg struct.
 */
__attribute__((noinline, used, visibility("default")))
void child_trigger(unsigned long cfgp)
{
    (void)cfgp;
    /* Future: open cache fds, call syscall 536, check_np nest, fault-sweep.
     * For now: exit(0x53) = 'S' for "stub" to distinguish from child_probe. */
    register long x16 asm("x16") = 1;
    register long x0  asm("x0")  = 0x53;
    asm volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "cc", "memory");
    __builtin_unreachable();
}

/* never runs (hijacked before dyld); present for valid dynamic exe structure */
int main(void)
{
    for (;;) {
        /* nothing — unreachable */
    }
    return 0;
}
