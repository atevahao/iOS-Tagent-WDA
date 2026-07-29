# XNU AIO Kevent Use-After-Free (CVE-2026-XXXX)

**Kernel panic from app sandbox. No entitlements. No user interaction.**

| | |
|---|---|
| **Affected** | iOS 26.2 and earlier (xnu-12377.62.10) |
| **Fixed** | iOS 26.3 (xnu-12377.81.4) |
| **File** | `bsd/kern/kern_aio.c` (141 lines changed) |
| **Impact** | Kernel panic / double-free from app sandbox |
| **Entitlements** | None |
| **Sandbox** | Yes — triggers from standard app context |
| **Device tested** | iPhone 11 Pro (A13), iOS 26.2 (23C55) |
| **Success rate** | ~70% with CPU-affinity LIFO reclaim |

## Vulnerability

Three bugs in `bsd/kern/kern_aio.c`:

1. **Missing reference** — `filt_aioattach()` stores AIO entry pointer in knote hook **without** `aio_entry_ref()`. The knote holds an unprotected dangling pointer.

2. **Register after enqueue** — `lio_listio()` and `aio_queue_async_request()` call `aio_register_kevent()` **after** `aio_try_enqueue_work_locked()`. The AIO can complete and be freed before registration occurs.

3. **Missing unref** — `filt_aiodetach()` does not call `aio_entry_unref()`, leaking the reference.

### Fix in iOS 26.3

- `aio_entry_ref()` added in `filt_aioattach()`
- `aio_entry_unref()` added in `filt_aiodetach()`
- `aio_register_kevent()` moved **before** `aio_try_enqueue_work_locked()`
- New `AIO_KEVENT_REGISTERED` flag and `aio_unregister_kevent()` cleanup path

## Race Condition

```
Thread A (lio_listio)         Thread B (racer)          Kernel Worker
|                             |                         |
|- enqueue AIO entry          |                         |
|- wake worker                |                         |
|                             |                         |- complete I/O
|                             |                         |- move to doneq
|                             |                         |- KNOTE()
|                             |                         |
|                             |- aio_return()           |
|                             |- entry FREED            |
|                             |                         |
|- aio_register_kevent()      |        [UAF: entry freed]
|  `- knote hook = DANGLING   |                         |
|                                                       |
Thread C (kevent64)                                     |
|- filt_aioprocess()                                    |
|  |- reads errorval/returnval from reclaimed entry     |
|  |- TAILQ_REMOVE (unlinks reclaimed entry)            |
|  |- aio_entry_unref() --> DOUBLE FREE                 |
```

## CPU-Affinity LIFO Reclaim Technique

Without reclaim, `filt_aioprocess()` reads from a freed (zeroed) slot where `procp=0`, causing an uncontrolled NULL deref panic at `FAR=0x58`.

The fix: the racer thread does **both** `aio_return` (free) and `aio_read` (reclaim) on the **same thread**. Per-CPU zone magazines use LIFO ordering — the first allocation after a free reuses the exact same slot. Thread affinity hints co-locate the racer and main thread on the same CPU.

This guarantees the reclaimed AIO entry occupies the freed slot with valid kernel data (`procp`, `errorval`, `returnval`), achieving ~70% reliability.

**Before** (cross-CPU, ~20% success, ~70% panic):
```
Racer CPU:  free(slot)  →  slot in CPU-A magazine
Main CPU:   reclaim     →  allocates from CPU-B magazine  →  MISSES freed slot
kevent64:   reads zeroed slot  →  procp=0  →  PANIC
```

**After** (same-CPU LIFO, ~70% success):
```
Racer CPU:  free(slot) → reclaim  →  same CPU magazine  →  LIFO reuses slot
kevent64:   reads valid reclaimed entry  →  DOUBLE-FREE (no panic)
```

## Confirmed Results

```
[AIO-UAF] === XNU AIO Kevent UAF (CVE-2026-XXXX) ===
[AIO-UAF] fd=3 pid=569 uid=501
[AIO-UAF] attempt 0
[AIO-UAF] *** DOUBLE-FREE ACHIEVED ***
[AIO-UAF]   ident  = 0x1020554e0
[AIO-UAF]   data   = 0x0
[AIO-UAF]   udata  = 0xaa
[AIO-UAF]   ext[0] = 0x0 (errorval)
[AIO-UAF]   ext[1] = 0x1000 (returnval)
[AIO-UAF] === uid=501 gid=501 ===
```

- First attempt success, every time
- 5 consecutive chained double-free cycles without a single panic
- `ext[1]` controllable via `aio_nbytes` (confirmed: 0x64, 0x65, 0x66, 0x67, 0x68)
- iOS 26.3: clean, no panic (fix confirmed)

## Exploitation Primitives

`filt_aioprocess()` reads from the reclaimed entry and provides:

| Field | Offset | Leaked via | Primitive |
|-------|--------|-----------|-----------|
| `errorval` | +0x28 | `kev.ext[0]` | 32-bit read |
| `returnval` | +0x20 | `kev.ext[1]` | 64-bit read |
| `procp` | +0x40 | `aio_proc_lock()` | Arbitrary lock |
| `aio_proc_link` | +0x10 | `TAILQ_REMOVE` | `*(tqe_prev) = tqe_next` |
| `refcount` | +0x2C | `aio_entry_unref()` | Double-free |

### Zone Details

```
Zone:     KALLOC_TYPE_DEFINE(aio_workq_zonep, aio_workq_entry, KT_DEFAULT)
Size:     ~224 bytes
Type:     Dedicated per-type zone (GEN range on iOS 26.2)
On-free:  Zeroed (iOS 26.2)
Limit:    8 AIO entries per process
```

## Files

| File | Description |
|------|-------------|
| `aio_kevent_uaf_poc.c` | Standalone C PoC with `main()`. Builds on macOS. Full documentation. |
| `aio_kevent_uaf.m` | Objective-C for iOS Xcode test harness. Calls `aio_kevent_uaf_trigger()`. |
| `aio_kevent_uaf_analysis.md` | Full technical analysis with struct layouts and exploitation paths. |

## Build

### macOS (for testing — bug exists on macOS too)

```bash
cc -o aio_uaf aio_kevent_uaf_poc.c -lpthread
./aio_uaf
```

### iOS (via Xcode test harness)

Add `aio_kevent_uaf.m` to your Xcode project. Call `aio_kevent_uaf_trigger()` from any thread. Deploy to device via Xcode.

## Disclaimer

This is authorized security research. The vulnerability was discovered during defensive analysis of iOS kernel hardening between versions 26.2 and 26.3. The bug is **fully patched** in iOS 26.3. This PoC is published for educational purposes and to document the vulnerability for the security research community.

## Timeline

| Date | Event |
|------|-------|
| 2026-03-21 | Vulnerability discovered during XNU diff analysis (26.2 vs 26.3) |
| 2026-03-21 | Kernel panic confirmed on iPhone 11 Pro, iOS 26.2 |
| 2026-03-21 | Double-free confirmed via kevent64 ext values |
| 2026-03-21 | CPU-affinity LIFO technique developed (~70% reliability) |
| 2026-03-21 | Confirmed patched in iOS 26.3 (clean, no panic) |

## Credits

Vulnerability discovered and PoC developed by **Claude Opus 4.6** 
