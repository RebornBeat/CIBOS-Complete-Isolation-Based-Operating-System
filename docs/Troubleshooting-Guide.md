# TROUBLESHOOTING GUIDE

**CIBIOS/CIBOS/HIP — Troubleshooting**
**Version:** 1.0.0
**Audience:** Administrators and developers diagnosing issues

---

## Overview

```
TROUBLESHOOTING PHILOSOPHY IN CIBOS:

  Traditional OS issues that DON'T EXIST in CIBOS:
  ✗ Deadlocks from lock ordering   (no locks)
  ✗ Priority inversion             (weighted entropy, not priority queues)
  ✗ Race conditions in kernel data (single ownership everywhere)
  ✗ Memory corruption from sharing (isolated address spaces)

  Issues that DO EXIST in CIBOS:
  ✓ Boot failures (signature mismatch, hardware not detected)
  ✓ Containers never executing (all stalled, no Ready Pool entries)
  ✓ Channel stalls (buffer full, nobody consuming)
  ✓ Memory exhaustion (container over its limit)
  ✓ Application errors (bugs in your code)
```

---

## Chapter 1: Boot Issues

### Issue: Boot Fails Immediately After CIBIOS Starts

**Symptom:** Screen shows CIBIOS messages then halts with an error before kernel loads.

**Diagnostic:**

```
[CIBIOS] Hardware initialization...
[CIBIOS] ERROR: [error message here]
```

**Common causes and resolutions:**

```
ERROR: "Signature verification failed"
─────────────────────────────────────
Cause:   CIBOS kernel binary does not match CIBIOS-expected signature.
         This is CIBIOS's self-enforcing profile pairing check.

Check 1: Did you build CIBIOS and CIBOS together?
         They must be built as a pair (same `make` invocation).
         Mixing CIBIOS from one build with CIBOS from another = failure.

Check 2: Profile mismatch?
         CIBIOS Standard pairs with: Maximum Isolation, Balanced, Performance.
         CIBIOS Lightweight pairs with: Performance (reduced), Compute.
         CIBIOS Standard + CIBOS Compute = BOOT FAILURE (by design).
         Rebuild with correct profile: make profile=compute
                                        (builds CIBIOS Lightweight + CIBOS Compute)

Resolution: Rebuild both CIBIOS and CIBOS together:
         make clean && make profile=<your-profile>

────────────────────────────────────────────────────────
ERROR: "Hardware not supported"
─────────────────────────────────────────────────────────
Cause:   Required hardware feature not present.

Check 1: Are you on a supported architecture?
         x86-64, ARM64, or RISC-V64 required.
         32-bit x86 is NOT supported.

Check 2: SMT configuration?
         Maximum Isolation and Balanced require SMT disabled in BIOS.
         Performance and Compute work with or without SMT.
         Enable/disable SMT in BIOS/UEFI settings.

Check 3: Minimum RAM?
         System requires at least 1 GB RAM for CIBIOS/CIBOS.
         If RAM is below minimum, boot fails.

────────────────────────────────────────────────────────
ERROR: "Memory isolation boundary establishment failed"
─────────────────────────────────────────────────────────
Cause:   CIBIOS could not establish required memory regions.
         Usually indicates BIOS memory map issue.

Resolution: Check BIOS for memory remapping settings.
            Try disabling memory hole remapping.
            Check for bad RAM (run memtest86 first).
```

### Issue: CIBIOS Boots But Kernel Handoff Fails

**Symptom:** CIBIOS completes, then kernel fails to start.

```
[CIBIOS] Signature verification: PASS
[CIBIOS] ──► Transferring control to CIBOS
[CIBOS]  ERROR: Kernel handoff verification failed
```

**Cause:** Kernel received corrupt or wrong CIBIOS hardware config record.

**Resolution:**

```bash
# Verify the build image integrity
make verify-image build/cibios-cibos.img

# If verification fails:
make clean && make profile=<your-profile>

# Write fresh image to boot media
sudo dd if=build/cibios-cibos.img of=/dev/sdb bs=4M
sudo sync
```

### Issue: System Boots But Immediately Hangs

**Symptom:** CIBOS reports "System ready" but the system is unresponsive.

**Cause:** Usually the first container failed to launch or immediately stalled.

**Diagnostic:**

```bash
# If you have serial console:
# Check serial output for error messages after "System ready"

# Boot with verbose mode
make profile=balanced BOOT_ARGS="verbose=3"
# Additional diagnostic output will appear on serial/screen
```

---

## Chapter 2: Scheduling Issues

### Issue: System Appears Unresponsive

**Symptom:** System is running but nothing appears to be executing.

**Diagnostic:**

```bash
cibos-ctl status
# If this command responds: kernel is running, issue is with containers

# Check Ready Pool
cibos-ctl metrics --metric ready_pool_depth
# If 0: no containers in Ready Pool → all containers stalled

# Check why containers are stalled
cibos-ctl containers list --status stalled
# Shows which containers are stalled and why:
# Container        Stalled On       Duration
# ────────────     ────────────     ────────
# ui-app           channel-receive  4.2s     ← waiting for input
# background-sync  timer            0.8s     ← sleeping, normal
# my-app           channel-receive  47.2s    ← UNUSUAL: stalled very long
```

**Stalled on `channel-receive` for long duration:**

```
Cause: Container is waiting for a message that never comes.
       Either:
       a) Sender container exited or crashed
       b) Sender is stalled on something else (its channel is full)
       c) Application logic error — sender never sends

Check:
  cibos-ctl containers list  # Is sender container still running?
  cibos-ctl channels --container sender-app  # Is sender's channel full?
```

**Ready Pool depth is 0 but containers are stalled on timer:**

```
This is NORMAL. Containers sleeping = system is idle = Ready Pool = 0.
This is correct behavior. Not a problem.
```

### Issue: One Container Never Executes

**Symptom:** A specific container was launched but never runs.

**Diagnostic:**

```bash
# Check if container exists
cibos-ctl containers list
# If not in list: container failed to launch

# Check container status
cibos-ctl containers status my-app

# If status is "stalled":
cibos-ctl containers stall-reason my-app
# Output: "Stalled waiting for: channel-receive (channel-id: 0x4f2)"

# If status is "ready":
# Container IS in Ready Pool — but maybe there are many more containers
# Check total Ready Pool depth
cibos-ctl metrics --metric ready_pool_depth
# If very high: your container is waiting its turn (correct behavior)
# If equal to 1: only your container is ready — should execute soon
```

**Container never reaches Ready Pool:**

```bash
# Check if container was launched with correct image
cibos-ctl log --container my-app --level error

# Check for launch errors
cibos-ctl audit --event container_launch --container my-app
```

### Issue: UI Is Lagging

**Symptom:** User interface feels sluggish or unresponsive.

**Diagnostic:**

```bash
# Check UI container lane utilization
cibos-ctl lanes --container ui-app --utilization

# If ui-lane utilization is low but stall rate is low:
# UI lane is not getting dispatch time — likely weight issue on Compute profile

# Check weights (Compute profile only)
cibos-ctl lanes --container ui-app --weights

# If UI and background lanes have equal weight on Compute:
# Solution: raise UI lane weight
cibos-ctl config lanes --container ui-app --lane ui-lane --weight 5
cibos-ctl config lanes --container ui-app --lane background --weight 1
```

**On Maximum Isolation/Balanced/Performance:**

```
UI lag on these profiles is NOT a weight issue (weights are fixed or equal).
Likely causes:
  1. UI lane is doing too much work per dispatch
     → Break large computations into smaller chunks
     → Use Timer::sleep(0) to yield to other lanes

  2. Input channel is full (UI events being dropped or delayed)
     → Increase input channel buffer size
     → Check if event producer is sending too fast

  3. Render function is too slow
     → Profile render code
     → Reduce render complexity or render less frequently
```

### Issue: Background Tasks Are Stalling

**Symptom:** Background sync or processing is falling behind.

**Diagnostic:**

```bash
# Check background lane stall time
cibos-ctl lanes --container my-app --lane background-lane --detail

# Output:
# Lane: background-lane
# Weight: 1
# Utilization: 12% (VERY LOW)
# Stall time: 88%
# Stall breakdown:
#   channel-receive: 61%    ← waiting for data
#   channel-send:    27%    ← output buffer full
#   timer:           0%

# channel-send 27% stalled → output channel is full
# Resolution: Consumer of output channel is too slow
```

**Resolution for output channel full:**

```
Options:
  1. Increase output channel buffer: more buffering before stalling
  2. Speed up the consumer: profile and optimize consumer
  3. Add more consumer lanes: parallelize consumption
  4. Reduce producer rate: add back-pressure intentionally
```

---

## Chapter 3: Memory Issues

### Issue: Allocation Stalls

**Symptom:** Container operations suddenly slow down. Metrics show "allocation-stall" events.

**Diagnostic:**

```bash
# Check current memory usage
cibos-ctl containers memory --container my-app

# Output:
# Container: my-app
# Allocated: 498.2 MB
# Limit:     512.0 MB   ← approaching limit
# Peak:      501.4 MB
# Status:    WARNING: 97% of limit used
```

**Resolution:**

```bash
# Option 1: Increase container memory limit (if hardware allows)
cibos-ctl containers limit --container my-app --memory 1GB

# Option 2: Investigate allocation in application
# Enable allocation tracking (Balanced/Performance profiles only)
cibos-ctl debug allocation-track --container my-app --enable

# Then check what's allocating:
cibos-ctl debug allocation-report --container my-app
```

**Common causes:**

```
1. Growing Vec without bound
   Fix: Use bounded collections, process and drain

2. Channel buffers holding large messages
   Fix: Process messages faster or reduce buffer capacity

3. Cloning large data structures per-lane
   Fix: Use Arc for shared immutable data (reference-counted, not locked)
   Note: Arc is safe in CIBOS — immutable data doesn't need isolation

4. String formatting in hot path
   Fix: Pre-allocate format buffers
```

### Issue: Memory Limits Exceeded

**Symptom:** Container crashes with `ContainerError::MemoryLimitExceeded`.

```
[cibos] Container my-app terminated: MemoryLimitExceeded (allocated: 512 MB, limit: 512 MB)
```

**Resolution:**

```bash
# Check memory growth trend before the crash
cibos-ctl log --container my-app --level warn --last 100
# Look for memory warning messages before the crash

# Increase limit if crash is legitimate (correct behavior, needs more RAM)
cibos-ctl containers limit --container my-app --memory 2GB

# If limit increase is not desired, application must manage memory better
# Enable allocation tracking and find the growth source
```

---

## Chapter 4: Channel Issues

### Issue: Channel Creation Rejected

**Symptom:** `Channel::request()` returns error immediately.

**Common errors:**

```
Err(ChannelError::TargetNotFound)
─────────────────────────────────
Cause: Target container ID does not exist.
Check: Is the target container running?
       cibos-ctl containers list
       Is the ContainerId correct? IDs are assigned at launch — may change.

Err(ChannelError::Unauthorized)
─────────────────────────────────
Cause: Container policy prevents this channel.
       On Maximum Isolation profile, inter-container channels require
       explicit authorization in container manifest.
Check: cibos-ctl policy --container my-app --check channel-to target-app
       Add authorization: cibos-ctl policy --add-channel my-app target-app

Err(ChannelError::TermsViolation)
──────────────────────────────────
Cause: Requested terms exceed system policy.
       max_message_bytes may exceed system maximum.
       buffer_capacity may exceed system maximum.
Check: cibos-ctl config get channel-limits
```

### Issue: Send Stalls (Back-Pressure)

**Symptom:** `channel.send().await` does not return for a long time.

**This is correct behavior** when the channel buffer is full. It means the consumer is slow.

**Diagnostic:**

```bash
# Check if consumer is running and consuming
cibos-ctl channels --id <channel-id> --stats

# Output:
# Channel: <channel-id>
# Direction: my-app → consumer-app
# Buffer: 16/16 FULL  ← buffer completely full
# Messages sent:    1,247,832
# Messages received: 1,183,294   ← consumer is behind by 64,538
# Consumer state: stalled (other-resource)  ← consumer is blocked on something else
```

**Resolution:**

```
Option 1: Consumer is blocked on something else
  → Fix the blocking issue in consumer
  → Check consumer's stall reason

Option 2: Consumer is simply slower than producer
  → Increase channel buffer (more buffering before back-pressure)
  → Add more consumer lanes (parallelism)
  → Reduce producer rate (sleep between sends)

Option 3: Intentional — back-pressure is correct design
  → No action needed. Back-pressure is the mechanism working as designed.
```

### Issue: Receive Stalls (No Messages)

**Symptom:** `channel.receive().await` does not return for a long time.

**This is usually correct behavior** — waiting for messages.

**Diagnostic:**

```bash
# Is the sender still running?
cibos-ctl containers list | grep sender-app

# Is sender actually sending?
cibos-ctl channels --id <channel-id> --stats
# If messages-sent is not increasing: sender has stopped sending

# Check sender state
cibos-ctl containers status sender-app
# If "stalled on channel-send": sender's output is full — consume its output
# If "stalled on channel-receive": sender is waiting for its own input
# If "exited": sender has exited — receiver will eventually get None
```

### Issue: Channel Closed Unexpectedly

**Symptom:** `channel.receive()` returns `None` when you didn't expect it.

**Cause:** The sender closed its end of the channel.

**Diagnostic:**

```bash
# Check if sender exited
cibos-ctl containers list
# If sender-app is not in list: it exited (closing all its channels)

# Check container exit reason
cibos-ctl audit --event container_exit --container sender-app
# Output: exited cleanly / crashed with error / killed by OOM / etc.
```

**Application fix:**

```rust
// Always handle None from receive():
loop {
    match channel.receive().await {
        Some(msg) => process(msg),
        None => {
            log::info!("Channel closed — sender is done");
            break; // Exit gracefully
        }
    }
}
```

---

## Chapter 5: Application Issues

### Issue: Application Panics

**Symptom:** Container exits with "panicked" message.

```
[cibos] Container my-app terminated: Panic("index out of bounds: the len is 5 but index is 7")
```

**Resolution:**

```bash
# Get full panic information including backtrace
cibos-ctl log --container my-app --level error --last 50

# Enable panic details for development
# In application:
# [profile.dev]
# panic = "unwind"   # More information, larger binary

# For production: panic = "abort" (faster, smaller)
# But log the panic reason via cibos panic hook:
```

```rust
// Register a panic handler to log before aborting
cibos::set_panic_hook(|info| {
    log::error!("PANIC: {}", info);
    // Panic hook is called before container terminates
});
```

### Issue: Incorrect Results

**Symptom:** Application computes wrong answers. Results vary between runs.

**First check: Is non-determinism expected?**

```
CIBOS is non-deterministic by default (HIP property N).
If your result depends on the ORDER lanes complete, you will get
different results on different runs. This is CORRECT.

Non-determinism is NOT a bug in CIBOS — it's the default state.
If your computation requires deterministic output, you must
design for it explicitly.
```

**Designing for deterministic output:**

```rust
// NON-DETERMINISTIC (result depends on which lane finishes first):
let (sender, receiver) = Channel::new_local(8)?;

for i in 0..4 {
    let s = sender.clone();
    lane.submit(async move {
        let result = compute(i);
        s.send(result).await.unwrap();
    })?;
}

// WRONG: takes results in random order
let mut results = Vec::new();
for _ in 0..4 {
    results.push(receiver.receive().await.unwrap());
}
// results[0] might be from lane 3, results[1] from lane 1, etc.

// CORRECT: index-tagged results, assemble in order
let mut results = [0u64; 4];
for _ in 0..4 {
    let (i, value) = receiver.receive().await.unwrap();
    results[i] = value; // Store by index — order-independent
}
// results[0] is always from lane 0, etc.
```

### Issue: Race Conditions

**Symptom:** Intermittent incorrect behavior that is hard to reproduce.

**In CIBOS, true race conditions (from shared mutable state) should be impossible** — isolation boundaries prevent shared mutable state by design.

**If you are seeing behavior that resembles a race condition:**

1. **Are you using `unsafe`?** Unsafe code can bypass isolation. Audit all `unsafe` blocks.

2. **Are you using `static mut`?** Global mutable state in `no_std` Rust can create races. Replace with lane-local state.

3. **Are you using external FFI?** FFI code is not verified by CIBOS isolation. Treat FFI as potentially unsafe.

4. **Is the "race" actually non-determinism?** See the section above. Non-deterministic ordering is expected.

```bash
# Check for unsafe code in your application
cargo audit --container my-app --unsafe-check

# Check for shared global state
cargo audit --container my-app --global-state-check
```

---

## Chapter 6: Error Message Reference

### CIBIOS Error Messages

| Error | Cause | Resolution |
|-------|-------|------------|
| `CIBIOS_SIGNATURE_VERIFY_FAIL` | Kernel signature doesn't match | Rebuild CIBIOS+CIBOS together |
| `CIBIOS_HW_UNSUPPORTED` | CPU/RAM below minimum | Upgrade hardware or use different profile |
| `CIBIOS_SMT_CONFLICT` | SMT state conflicts with profile | Change BIOS SMT setting |
| `CIBIOS_MEMORY_MAP_FAIL` | Cannot establish memory regions | Check BIOS memory settings |
| `CIBIOS_RNG_UNAVAILABLE` | No hardware RNG | System will use software fallback (logged as warning) |
| `CIBIOS_HANDOFF_FAIL` | Kernel handoff verification failed | Rebuild fresh image |

### CIBOS Kernel Error Messages

| Error | Cause | Resolution |
|-------|-------|------------|
| `CIBOS_LANE_CAPACITY` | Lane limit reached | Increase limit or reduce lane usage |
| `CIBOS_CONTAINER_OOM` | Container out of memory | Increase memory limit or fix memory leak |
| `CIBOS_CHANNEL_CLOSED` | Channel was closed by other end | Handle `None` from `receive()` |
| `CIBOS_CHANNEL_TERMS_VIOLATED` | Message too large or buffer too large | Reduce message/buffer size |
| `CIBOS_UNAUTHORIZED` | Policy violation | Add authorization in container manifest |
| `CIBOS_DISPATCH_TIMEOUT` | Container in Ready Pool but not dispatched | System overloaded, reduce container count |

### Application Error Messages

| Error | Cause | Resolution |
|-------|-------|------------|
| `LaneError::AlreadyOccupied` | submit() called on lane with running future | Call join() first |
| `LaneError::WeightOutOfRange` | Weight outside 1..=100 | Use weight in valid range |
| `ChannelError::TargetNotFound` | Target container doesn't exist | Verify container is running |
| `SensorError::NotAvailable` | Sensor not on hardware | Check hardware, use feature detection |
| `SensorError::Timeout` | Sensor held by another container | Increase timeout or release from other container |
