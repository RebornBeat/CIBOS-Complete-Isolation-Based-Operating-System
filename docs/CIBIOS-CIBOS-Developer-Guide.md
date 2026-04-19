# CIBIOS/CIBOS Developer Guide
**Implementation Reference for Kernel and Firmware Developers**

## Introduction

This guide provides complete implementation details for developers working on CIBIOS firmware and the CIBOS kernel. It covers mechanisms, algorithms, data structures, and interaction patterns that implement HIP at the system level.

---

## Chapter 1: Repository Architecture

### Directory Structure

```
repository-root/
├── Cargo.toml              (workspace root, shared feature flags)
├── firmware/               (CIBIOS)
│   ├── Cargo.toml
│   ├── .cargo/config.toml  (target triples, linker scripts)
│   ├── linker-x86_64.ld
│   ├── linker-aarch64.ld
│   ├── linker-riscv64.ld
│   ├── linker-x86.ld
│   ├── build.rs            (assembly compilation via cc crate)
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       ├── allocator.rs    (bump allocator — never frees)
│       ├── serial.rs       (debug output without OS)
│       ├── entropy.rs      (hardware RNG without OS)
│       ├── arch/
│       │   ├── x86_64/     (boot.s, memory.s, transfer.s, smt.s)
│       │   ├── aarch64/
│       │   ├── x86/
│       │   └── riscv64/
│       ├── core/
│       │   ├── boot.rs
│       │   ├── hardware.rs
│       │   ├── memory.rs
│       │   ├── isolation.rs
│       │   ├── smt.rs
│       │   ├── verification.rs
│       │   └── handoff.rs
│       └── security/
├── kernel/                 (CIBOS)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       ├── scheduler/
│       │   ├── mod.rs
│       │   ├── ready_pool.rs
│       │   ├── stalled_list.rs
│       │   ├── selector.rs
│       │   ├── anti_starvation.rs
│       │   ├── full_fairness.rs
│       │   └── timing.rs       (shared timing infrastructure)
│       ├── core/
│       │   ├── memory.rs
│       │   ├── ipc.rs
│       │   ├── isolation.rs
│       │   └── syscall.rs
│       └── security/
├── async-runtime/          (CIBOS async runtime — no global locks)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── executor.rs     (LaneExecutor, CibosWaker)
│       ├── timer.rs        (kernel-managed timer futures)
│       ├── channel.rs      (HIP-native channel futures)
│       ├── resource.rs     (generic resource waiting)
│       └── macros.rs       (#[cibos::main])
├── shared/
├── platforms/
├── tools/
└── profiles/
```

### The No-Global-Locks Principle: Implementation

The architecture's hard constraint is single ownership of all mutable state:

- **Selector owns exclusively:** Ready Pool, Stalled List, resource registry, core state tracking, class pool metadata (when compiled), core affinity mapping (when compiled), ALL weight data including per-lane weights and any dynamic weight updates
- **Each execution context owns:** Its own execution state during execution
- **Each lane owns:** Its internal event queue
- **All inter-thread communication:** Lock-free SPSC message queues (one sender, one receiver — no locks needed by design)

This means no Mutex, no RwLock, no spin locks anywhere. Code review should grep for these and find nothing.

---

## Chapter 2: CIBIOS Firmware Implementation

### no_std Requirements

CIBIOS is bare-metal firmware. Required crate-level attributes:

```rust
#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
```

CIBIOS provides a bump allocator (never frees; ~2MB heap — all memory reclaimed at CIBOS handoff). CIBIOS provides its own panic handler (writes to serial, halts). Hardware RNG accessed directly:
- x86_64: RDRAND instruction (check CPUID leaf 1, ECX bit 30)
- ARM64: RNDR system register (check ID_AA64ISAR0_EL1 RNDR field)
- RISC-V: SEED CSR from Zkr extension

No async/await in CIBIOS. All functions synchronous. All errors returned as `Result<T, FirmwareError>`. `anyhow` requires `std` and is not used.

### Handoff Data Structure

```rust
#[repr(C)]
pub struct HandoffData {
    pub version: u32,
    pub hardware_config: HardwareConfig,
    pub memory_layout: MemoryLayout,
    pub isolation_boundaries: IsolationBoundaries,
    pub smt_enabled: bool,
    pub logical_core_count: u32,
    pub physical_core_count: u32,
    /// Standard profile: populated with verification chain
    /// Lightweight profile: empty
    pub verification_chain: VerificationChain,
}
```

### SMT Configuration

```rust
pub fn configure_smt(profile: CibiosProfile) {
    match profile {
        CibiosProfile::Standard => {
            // Disable SMT for adversarial profiles
            // x86_64: Write to IA32_MISC_ENABLE MSR
            // ARM64: Write to MPIDR_EL1 cluster threading control
            // RISC-V: Platform-specific hart management
            disable_smt_hardware();
        }
        CibiosProfile::Lightweight => {
            // Enable SMT for compute profiles
            enable_smt_hardware();
        }
    }
    // Record in handoff data for CIBOS to read
}
```

### CIBIOS Initialization Sequence

1. CPU state initialization (assembly)
2. BSS zeroing
3. Serial port initialization (debug output from here)
4. Hardware RNG availability check
5. Hardware detection (CPU, memory, storage, display)
6. Memory isolation boundary configuration (before any code uses memory)
7. Lane memory region reservation (regions CIBOS will use)
8. SMT configuration per profile
9. Cryptographic engine initialization (Standard profile only)
10. Boot configuration loading, first-boot detection
11. CIBOS image loading from storage
12. CIBOS image verification: Standard = Ed25519 signature check; Lightweight = none
13. CIBOS entry point parsing from ELF header
14. Isolation boundary finalization
15. Handoff data structure preparation (memory layout, isolation state, SMT status, core counts)
16. Control transfer to CIBOS — NEVER RETURNS

### build.rs: Assembling Boot Code

```rust
fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let asm_dir = match target_arch.as_str() {
        "x86_64"  => "src/arch/x86_64/asm",
        "aarch64" => "src/arch/aarch64/asm",
        "riscv64" => "src/arch/riscv64/asm",
        "x86"     => "src/arch/x86/asm",
        _ => panic!("Unsupported architecture"),
    };
    cc::Build::new()
        .flag("-x").flag("assembler-with-cpp")
        .files(/* all .s files in asm_dir */)
        .compile("cibios_asm");
}
```

---

## Chapter 3: The Two-Layer Execution Model Implementation

### Layer 1: Catch and Release Data Structures

```rust
pub struct ReadyPool {
    events: Vec<ReadyEvent>,
    total_weight: u64,
}

pub struct ReadyEvent {
    lane_id: Uuid,
    container_id: Uuid,
    weight: u32,              // From container class or per-lane (if compiled)
    entry_time: Instant,      // When entered current visit to Ready Pool
    accumulated_ready_time: Duration, // Total Ready Pool time across all visits
    event_payload: ExecutionEvent,

    // Feature-specific fields:
    #[cfg(feature = "deadline-scheduling")]
    deadline: Option<Instant>,

    #[cfg(feature = "weight-aging")]
    age: u32,
}

pub struct StalledList {
    entries: Vec<StalledEntry>,
    // Indexed by resource type for efficient lookup
    memory_waiters: HashMap<ContainerId, ResourceRequirements>,
    io_waiters: HashMap<ContainerId, ResourceRequirements>,
    channel_waiters: HashMap<ChannelId, Vec<ContainerId>>,
}

pub struct StalledEntry {
    container_id: Uuid,
    lane_id: Uuid,
    resource_requirements: ResourceRequirements, // ALL required resources
    stall_time: Instant,
    pending_event: ExecutionEvent,
    accumulated_ready_time: Duration, // Preserved from Ready Pool
}

pub struct ResourceRequirements {
    memory_bytes: Option<u64>,
    channel_reads: Vec<ChannelId>,
    channel_writes: Vec<ChannelId>,
    io_operations: Vec<IoOperationId>,
}
```

### Resource Signal Processing: The Qualification Check

When a resource signal arrives, the kernel checks ALL resources for each waiting container:

```
signal: ResourceAvailable { resource_type }

1. Find all containers waiting for resource_type

2. FOR EACH container:
   qualified = true

   for req in requirements.memory_bytes:
     if memory_available < req: qualified = false; break
   for ch in requirements.channel_reads:
     if !channel_has_data(ch): qualified = false; break
   for ch in requirements.channel_writes:
     if !channel_has_space(ch): qualified = false; break
   for io in requirements.io_operations:
     if !io_complete(io): qualified = false; break

   IF qualified:
     stalled_list.remove(container)
     ready_pool.add(ReadyEvent {
       accumulated_ready_time: container.accumulated_ready_time,
       entry_time: now(),
       ...
     })
   ELSE:
     container stays in Stalled List — waiting for remaining resources
```

**Critical:** Only containers with ALL required resources become qualified. A container waiting for memory AND channel data stays stalled if only memory becomes available.

### Layer 2: Dispatch Logic

```
TRIGGER: Core completion, resource availability, new work created

1. available = count_available_execution_contexts()
2. ready_count = ready_pool.size()
3. IF ready_count == 0: return

4. IF ready_count <= available:
   // NO COMPETITION — dispatch ALL simultaneously, zero selection overhead
   FOR each event IN ready_pool.drain_all():
     context = select_context_affinity(event)
     dispatch_to(event, context)
   return

5. // COMPETITION EXISTS — weighted entropy selection

   // Check anti-starvation first (if compiled)
   #[cfg(feature = "anti-starvation")]
   {
     starving = events where total_ready_wait > threshold
     if !starving.is_empty():
       priority_count = min(starving.len(), available)
       priority_selected = entropy_select(starving, priority_count)
       remaining = available - priority_count
       others = weighted_entropy_select(non_starving, remaining)
       dispatch_all(priority_selected + others)
       return
   }

   selected = weighted_entropy_select(ready_pool, available)
   FOR each event IN selected:
     ready_pool.remove(event.lane_id)
     context = select_context_affinity(event)
     dispatch_to(event, context)
```

---

## Chapter 4: Weighted Entropy Algorithm

```
WEIGHTED ENTROPY SELECTION:

Input: ReadyPool with N events, select K events (K < N)
Output: K selected events

1. IF pool empty OR K == 0: return []
2. total_weight = Σ event.weight for all events
3. IF total_weight == 0: return first K events

4. selected = []
   pool_copy = copy_of_pool

   FOR i = 0 to K-1:
     R = cryptographic_random_u64() % current_total_weight
     accumulated = 0
     FOR each event in pool_copy:
       accumulated += event.weight
       IF R < accumulated:
         selected.append(event)
         pool_copy.remove(event)
         current_total_weight -= event.weight
         BREAK inner loop

5. return selected

COMPLEXITY: O(K × N) — fast for typical values
OPTIMIZATION: Prefix-sum tree for O(log N) when N is large
```

```
WEIGHTED ENTROPY — VISUAL:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  SELECT 2 FROM 5 EVENTS:                                                    │
│                                                                             │
│  Ready Pool:                                                                │
│  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐                    │
│  │   A   │  │   B   │  │   C   │  │   D   │  │   E   │                    │
│  │ w = 3 │  │ w = 1 │  │ w = 1 │  │ w = 1 │  │ w = 1 │                    │
│  └───────┘  └───────┘  └───────┘  └───────┘  └───────┘                    │
│                                                                             │
│  Total weight: 7                                                             │
│                                                                             │
│  Selection 1: R = random(0,7) = 4                                           │
│    Walk: A accumulates to 3, 4>3 continue                                   │
│          B accumulates to 4, 4≤4 → SELECT B                                 │
│                                                                             │
│  Remaining: A(3), C(1), D(1), E(1) — total weight 6                        │
│  Selection 2: R = random(0,6) = 2                                           │
│    Walk: A accumulates to 3, 2<3 → SELECT A                                 │
│                                                                             │
│  Result: A and B selected. C, D, E stay in Ready Pool (not stalled).        │
│                                                                             │
│  Higher weight = more tickets = higher probability (not certainty)          │
│  Selection is entropy-based — unpredictable but correct                     │
│  No locks: selector owns pool exclusively                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Weight Modifications (Feature-Dependent)

**weight-aging (Compute profile):**
```rust
fn effective_weight(event: &ReadyEvent) -> u32 {
    event.base_weight + (event.age * AGE_FACTOR)
}
// Age incremented by selector each dispatch cycle
// Provides gradual priority increase — progress guarantee without strict deadline
```

**dynamic-weights (Compute profile, requires per-lane-weights):**
Dynamic weights are processed as messages by the selector. No locks:

```rust
// Application sends (no waiting for reply):
SelectorMessage::UpdateWeight { lane_id, new_weight }

// Selector receives in main loop (exclusive ownership):
fn process_weight_update(&mut self, lane_id: Uuid, new_weight: u32) {
    // Update in Ready Pool if present
    if let Some(event) = self.ready_pool.find_by_lane(lane_id) {
        self.ready_pool.total_weight -= event.weight as u64;
        event.weight = new_weight;
        self.ready_pool.total_weight += new_weight as u64;
    }
    // Update in Stalled List if present (for when it becomes eligible)
    if let Some(entry) = self.stalled_list.find_by_lane(lane_id) {
        entry.pending_event.weight = new_weight;
    }
}
```

Container does not wait for acknowledgment. This is triggering, not coordination. Overhead: ~45-110 cycles per message, zero per dispatch.

---

## Chapter 5: Anti-Starvation Timer Semantics

```
ANTI-STARVATION TIMER BEHAVIOR:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  WHAT IS TRACKED:                                                           │
│  accumulated_ready_time: Total time spent in Ready Pool across ALL visits   │
│  entry_time: When event entered current visit to Ready Pool                 │
│                                                                             │
│  WHAT IS NOT TRACKED:                                                       │
│  Time in Stalled List, time executing, time inactive — NONE of these count  │
│                                                                             │
│  STATE TRANSITIONS:                                                         │
│                                                                             │
│  Event enters Ready Pool (new event):                                       │
│    accumulated_ready_time = 0                                               │
│    entry_time = now()                                                       │
│                                                                             │
│  Event enters Ready Pool (from Stalled List):                               │
│    accumulated_ready_time = carried from StalledEntry (preserved)           │
│    entry_time = now()  ← new visit begins                                  │
│                                                                             │
│  Event dispatched (exits Ready Pool):                                       │
│    accumulated_ready_time NOT updated (preserved for potential stall)        │
│                                                                             │
│  Event stalls during execution:                                             │
│    accumulated_ready_time += (now() - entry_time)  ← add current visit     │
│    Value stored in StalledEntry                                             │
│                                                                             │
│  Event completes; new head event forms:                                     │
│    New event: accumulated_ready_time = 0  ← RESET (this is a NEW event)    │
│    entry_time = now()                                                       │
│                                                                             │
│  CURRENT WAIT CALCULATION:                                                  │
│  if is_in_ready_pool:                                                       │
│    total = accumulated_ready_time + (now() - entry_time)                   │
│  else:                                                                      │
│    total = accumulated_ready_time                                           │
│                                                                             │
│  ONLY Ready Pool time counts. Stalled time does NOT count.                  │
│  Anti-starvation is SELECTION FAIRNESS — not resource availability.         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Chapter 6: CIBOS Async Runtime Implementation

### Why a Custom Async Runtime is Required

Standard async runtimes (Tokio, async-std) use global task queues with locks — incompatible with HIP. Rust's `Future` trait is executor-agnostic; the `.await` syntax describes dependencies, not coordination. CIBOS implements its own async runtime that delegates waiting to the kernel's Catch and Release.

```
STANDARD RUNTIME vs CIBOS RUNTIME:

TOKIO (INCOMPATIBLE):
┌─────────────────────────────────────────────────────────────────────────────┐
│  Global Task Queue (LOCKED)                                                 │
│  ┌──────────────────────────────────────────────┐                           │
│  │ Task 1, Task 2, Task 3, ... Task N           │ ← LOCK HERE               │
│  └──────────────────────────────────────────────┘                           │
│  Multiple threads steal tasks (COORDINATION REQUIRED)                       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                                     │
│  │Thread 1 │◄─│Thread 2 │◄─│Thread 3 │  ← MORE LOCKS                       │
│  └─────────┘  └─────────┘  └─────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘

CIBOS ASYNC RUNTIME (COMPATIBLE):
┌─────────────────────────────────────────────────────────────────────────────┐
│  Per-Lane Task Queues (NO LOCKS — each lane owns its queue)                 │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐                               │
│  │ Lane 1 Q  │  │ Lane 2 Q  │  │ Lane N Q  │                               │
│  │ HEAD only │  │ HEAD only │  │ HEAD only │                               │
│  │ visible   │  │ visible   │  │ visible   │                               │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘                               │
│        └──────────────┼──────────────┘                                      │
│                        │                                                    │
│                        ▼                                                    │
│              ┌─────────────────┐                                            │
│              │    SELECTOR     │ (single owner — no locks)                  │
│              │ Ready Pool      │                                            │
│              │ Stalled List    │                                            │
│              └────────┬────────┘                                            │
│                        │                                                    │
│           ┌────────────┼────────────┐                                       │
│           ▼            ▼            ▼                                       │
│      ┌─────────┐  ┌─────────┐  ┌─────────┐                                 │
│      │Context 1│  │Context 2│  │Context 3│                                 │
│      │Executes │  │Executes │  │Executes │                                 │
│      │one event│  │one event│  │one event│                                 │
│      └─────────┘  └─────────┘  └─────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How .await Maps to Catch and Release

```rust
// What you write:
let data = channel.receive().await?;

// What happens internally:
//
// Future::poll() called:
//   - channel has data? → Poll::Ready(data) → execution continues
//   - channel empty?    → register dependency with kernel
//                         Poll::Pending returned
//                         execution suspends at this point
//
// Kernel side:
//   - Event moves to Stalled List
//   - Resource: ChannelData(channel_id)
//   - NO polling, NO retry
//
// When data arrives on channel:
//   - ResourceAvailable signal emitted
//   - Kernel qualifies ALL resources for this event
//   - If ALL available: event moves to Ready Pool
//   - Event dispatched → Waker::wake() called
//   - Future::poll() called again
//   - channel.try_receive() returns Some(data)
//   - Poll::Ready(data) returned
//   - Execution resumes after .await
```

### The CibosWaker

```rust
struct CibosWakerData {
    lane_id: Uuid,
    container_id: Uuid,
    kernel: Arc<dyn KernelInterface>,
}

// When Waker::wake() is called (when resource becomes available):
unsafe fn cibos_waker_wake(data: *const ()) {
    let arc = Arc::from_raw(data as *const CibosWakerData);
    // Signal to kernel that this lane should be scheduled
    // Kernel decides WHEN to poll (based on Catch and Release)
    arc.kernel.signal_ready(arc.lane_id);
    // Arc is dropped here
}
// CRITICAL: wake() does NOT poll directly
// It signals the kernel; kernel manages scheduling via Catch and Release
// No locks anywhere in this path
```

### The LaneExecutor

```rust
pub struct LaneExecutor {
    lane_id: Uuid,
    container_id: Uuid,
    // Lane-local task queue — NO locks, single owner
    tasks: VecDeque<LaneTask>,
    kernel: Arc<dyn KernelInterface>,
}

impl LaneExecutor {
    // Called by Lane::submit()
    pub fn submit<F: Future<Output = ()> + Send + 'static>(&mut self, future: F) {
        let was_empty = self.tasks.is_empty();
        self.tasks.push_back(LaneTask { future: Box::pin(future) });
        // If now has work, signal kernel
        if was_empty {
            self.kernel.signal_ready(self.lane_id);
        }
    }

    // Called by kernel when this lane is dispatched
    pub fn poll_head(&mut self) -> Poll<()> {
        let task = match self.tasks.front_mut() {
            Some(t) => t,
            None => return Poll::Ready(()),
        };
        let waker = self.create_waker();
        let mut cx = Context::from_waker(&waker);

        match task.future.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {
                self.tasks.pop_front();
                // If more tasks, signal kernel
                if !self.tasks.is_empty() {
                    self.kernel.signal_ready(self.lane_id);
                }
                Poll::Ready(())
            }
            Poll::Pending => {
                // Waker was registered with kernel inside poll()
                // Kernel handles the waiting via Catch and Release
                Poll::Pending
            }
        }
    }
}
```

### HIP-Native Async Primitives

```rust
// Channel receive future
impl<T> Future for Receive<'_, T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Try to receive (non-blocking)
        if let Some(value) = self.channel.try_receive() {
            return Poll::Ready(Some(value));
        }
        // Register with kernel — NOT with a runtime queue
        if !self.registered {
            self.channel.kernel.register_wait(
                self.channel.lane_id,
                Resource::ChannelData(self.channel.inner.id()),
            );
            self.registered = true;
        }
        Poll::Pending
        // Kernel will call wake() when data arrives
    }
}

// Timer future
impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let now = Instant::now();
        if now >= self.deadline {
            return Poll::Ready(());
        }
        if !self.registered {
            // Register timer event with kernel — no thread sleeping
            self.kernel.register_wait(
                self.lane_id,
                Resource::Timer(self.deadline),
            );
            self.registered = true;
        }
        Poll::Pending
        // Kernel will call wake() when timer fires
    }
}
```

### What Applications Can and Cannot Use

```
STANDARD RUNTIME COMPONENTS — CANNOT USE:

❌ tokio::spawn() / async_std::task::spawn()
   → Adds to GLOBAL task queue with LOCKS

❌ tokio::sync::Mutex / RwLock
   → These are locks! HIP prohibits locks.

❌ tokio::runtime::Runtime
   → The entire runtime assumes shared task queue

❌ Thread pools (work stealing requires coordination)

CIBOS EQUIVALENTS — USE THESE:

✓ Lane::submit(async { ... })
  → Adds to LANE-LOCAL queue (no global state)

✓ cibos::Channel
  → HIP-native channels, no locks

✓ Timer::sleep(duration)
  → Kernel-managed timer events, no sleeping thread

✓ WaitFor(resource)
  → Kernel tracks dependency, no polling
```

---

## Chapter 7: Signal Coalescence Implementation

When `signal-coalescence` is compiled in:

```rust
#[cfg(feature = "signal-coalescence")]
struct SignalBuffer {
    pending: VecDeque<ResourceSignal>,

    #[cfg(feature = "signal-coalescence-threshold")]
    oldest_signal_time: Option<Instant>,
}

#[cfg(feature = "signal-coalescence")]
impl SignalBuffer {
    fn add(&mut self, signal: ResourceSignal) {
        self.pending.push_back(signal);
        #[cfg(feature = "signal-coalescence-threshold")]
        if self.oldest_signal_time.is_none() {
            self.oldest_signal_time = Some(Instant::now());
        }
    }

    fn should_process(&self) -> bool {
        if self.pending.is_empty() { return false; }
        // Check backstop threshold
        #[cfg(feature = "signal-coalescence-threshold")]
        if let Some(time) = self.oldest_signal_time {
            if time.elapsed() > SIGNAL_BACKSTOP_THRESHOLD {
                return true; // Process even if few signals accumulated
            }
        }
        !self.pending.is_empty() // Opportunistic: process when available
    }

    fn drain(&mut self) -> Vec<ResourceSignal> {
        #[cfg(feature = "signal-coalescence-threshold")]
        { self.oldest_signal_time = None; }
        self.pending.drain(..).collect()
    }
}
```

### Shared Timing Infrastructure

When `anti-starvation` + `signal-coalescence-threshold` are both compiled:

```rust
#[cfg(all(feature = "anti-starvation", feature = "signal-coalescence-threshold"))]
mod shared_timing {
    // Single timing source shared by both features
    pub fn get_current_time() -> Instant { Instant::now() }
    pub fn threshold_exceeded(start: Instant, threshold: Duration) -> bool {
        get_current_time().duration_since(start) > threshold
    }
}
// Anti-starvation uses this for Ready Pool wait time
// Signal threshold uses this for signal buffer wait time
// Same code, different purposes, zero additional overhead
```

When `anti-starvation` + `full-fairness` are both compiled: they share execution time tracking. When all three are compiled: unified timing subsystem serves all three.

---

## Chapter 8: Multi-Core Single-Pool Routing

### Selector Main Loop

```rust
async fn selector_main_loop(mut state: SelectorState) {
    loop {
        // Step 1: Process core completion messages
        while let Ok(msg) = state.from_cores.try_recv() {
            match msg {
                CoreMessage::ExecutionComplete { context_id, lane_id, .. } => {
                    state.core_state[context_id].available = true;
                    if let Some(next) = get_next_lane_event(lane_id) {
                        if all_resources_available(&next) {
                            state.ready_pool.add(next);
                        } else {
                            state.stalled_list.add(next);
                        }
                    }
                }
                CoreMessage::ExecutionStalled { context_id, lane_id, resources, accumulated } => {
                    state.core_state[context_id].available = true;
                    state.stalled_list.add(StalledEntry {
                        accumulated_ready_time: accumulated,
                        ..create_entry(lane_id, resources)
                    });
                }
            }
        }

        // Step 2: Process resource signals
        #[cfg(feature = "signal-coalescence")]
        {
            while let Ok(signal) = state.resource_signals.try_recv() {
                state.signal_buffer.add(signal);
            }
            if state.signal_buffer.should_process() {
                for signal in state.signal_buffer.drain() {
                    process_resource_signal(&mut state, signal);
                }
            }
        }
        #[cfg(not(feature = "signal-coalescence"))]
        while let Ok(signal) = state.resource_signals.try_recv() {
            process_resource_signal(&mut state, signal);
        }

        // Step 3: Process async runtime waker signals
        while let Ok(wake) = state.waker_signals.try_recv() {
            // Lane's async future has signaled it should be re-polled
            state.async_runtime.schedule_poll(wake.lane_id);
        }

        // Step 4: Process dynamic weight updates (Compute profile)
        #[cfg(feature = "dynamic-weights")]
        while let Ok(msg) = state.weight_updates.try_recv() {
            state.process_weight_update(msg.lane_id, msg.new_weight);
        }

        // Step 5: Check anti-starvation (if compiled)
        #[cfg(feature = "anti-starvation")]
        state.check_and_mark_starving();

        // Step 6: Assess and dispatch
        let available = state.available_execution_contexts();
        let ready_count = state.ready_pool.size();

        if available > 0 && ready_count > 0 {
            if ready_count <= available {
                // NO COMPETITION: dispatch all simultaneously — zero selection overhead
                for event in state.ready_pool.drain_all() {
                    let ctx = state.select_context(&event);
                    dispatch_event(event, ctx, &mut state);
                }
            } else {
                // COMPETITION: weighted entropy selection
                let selected = state.weighted_entropy_select(available);
                for event in selected {
                    state.ready_pool.remove(event.lane_id);
                    let ctx = state.select_context(&event);
                    dispatch_event(event, ctx, &mut state);
                }
            }
        }

        if state.ready_pool.is_empty() && state.stalled_list.is_empty() {
            thread::yield_now();
        }
    }
}
```

### Core Affinity Routing (When Compiled)

```rust
fn select_context(state: &SelectorState, event: &ReadyEvent) -> usize {
    #[cfg(feature = "class-core-affinity")]
    {
        // Route to correct class pool first
        let class_pool = state.affinity_config.contexts_for_class(event.weight_class);
        // Then apply cache affinity within class pool
        if let Some(preferred) = state.cache_affinity.preferred_context(event.container_id) {
            if class_pool.contains(&preferred) && state.core_state[preferred].available {
                return preferred;
            }
        }
        // First available in class pool
        class_pool.iter()
            .find(|&&ctx| state.core_state[ctx].available)
            .copied()
            .unwrap_or_else(|| find_any_available(state))
    }

    #[cfg(not(feature = "class-core-affinity"))]
    {
        // Cache affinity routing only
        if let Some(preferred) = state.cache_affinity.preferred_context(event.container_id) {
            if state.core_state[preferred].available {
                return preferred;
            }
        }
        find_any_available(state)
    }
}
// No locks anywhere: selector owns all state exclusively
```

---

## Chapter 9: Configuration System

### Loading Configuration

```
load_config(path, pubkey) → Result<Config, Error>:

1. Read config file
2. Read signature file
3. Verify Ed25519 signature with embedded public key
   - Invalid/missing: use compiled defaults, warn
4. Parse TOML configuration
5. Validate values (weights > 0, thresholds ≥ 0, limits reasonable)
6. Return validated config
```

Invalid or missing configuration is NOT a fatal error. System always remains operational with compiled defaults.

---

## Chapter 10: Feature Flag Interaction Implementation

### Compile-Time Feature Verification

```rust
// In build.rs or validation module
fn validate_features() {
    let rtro = cfg!(feature = "rtro");
    let lightweight = cfg!(feature = "lightweight-handshake");
    if rtro && lightweight {
        panic!("Feature conflict: rtro requires handoff-cryptographic; lightweight prohibits it");
    }

    let full_fairness = cfg!(feature = "full-fairness");
    let per_lane = cfg!(feature = "per-lane-weights");
    if full_fairness && per_lane {
        panic!("Feature conflict: full-fairness and per-lane-weights are incompatible");
    }

    let dynamic = cfg!(feature = "dynamic-weights");
    if dynamic && !per_lane {
        panic!("Feature dependency: dynamic-weights requires per-lane-weights");
    }

    let multi_user = cfg!(feature = "multi-user-isolation");
    if multi_user && !cfg!(feature = "cryptographic-ipc") {
        panic!("Feature dependency: multi-user-isolation requires cryptographic-ipc");
    }
}
```

### Feature Combination Notes

**anti-starvation + signal-coalescence-threshold:** Shared timing source automatically. Single `Instant::now()` call serves both. No additional overhead for second feature.

**anti-starvation + full-fairness:** Shared execution time tracking. `record_execution_time()` called once; updates both features' data structures.

**class-resource-pools + class-core-affinity:** Independent features. Can combine freely. Each partitions a different resource type (memory vs execution contexts). Both owned by selector, no coordination.

**per-lane-weights + dynamic-weights:** Dynamic weights requires per-lane-weights as foundation. When both compiled: selector maintains per-lane weight data updateable at runtime via messages. No locks — selector owns all weight data exclusively.

---

## Chapter 11: Assembly Integration Reference

### Naming Convention

Pattern: `{arch}_{subsystem}_{operation}`

Examples: `x86_64_boot_initialize_hardware`, `aarch64_memory_setup_isolation`, `x86_64_boot_configure_smt`, `x86_64_transfer_control_to_os`

### Rust FFI Declaration Pattern

```rust
mod asm {
    use shared::protocols::handoff::HandoffData;

    extern "C" {
        /// Initialize CPU hardware state at boot.
        /// Safety: Called once during firmware initialization.
        /// Returns: 0 on success, non-zero on error
        pub fn x86_64_boot_initialize_hardware() -> i32;

        /// Configure SMT state.
        /// enable: 0 = disable, 1 = enable
        /// Safety: Must be called before any core starts execution.
        pub fn x86_64_boot_configure_smt(enable: u32) -> i32;

        /// Transfer control to CIBOS. Never returns.
        pub fn x86_64_transfer_control_to_os(
            entry_point: u64,
            handoff_data: *const HandoffData,
        ) -> !;
    }
}
```

---

## Chapter 12: No-Global-Locks Verification

### Code Review Checklist

```
□ No Mutex<T> in any kernel or firmware module
□ No RwLock<T> in any kernel or firmware module
□ No spin locks in any module
□ No atomic operations used for locking
□ Ready Pool: single owner (selector) verified
□ Stalled List: single owner (selector) verified
□ All weight data: single owner (selector) verified
□ Class pool metadata: single owner (selector) verified (when compiled)
□ Core affinity mapping: single owner (selector) verified (when compiled)
□ Dynamic weight updates: message passing verified (when compiled)
□ All inter-thread communication via SPSC message queues
□ No busy-wait loops anywhere
□ No polling loops anywhere
□ No retry loops anywhere — all waits are event-driven
□ Selector → Core: SPSC message queue (no locks by design)
□ Core → Selector: SPSC message queue (no locks by design)
□ Async waker: signal via message (no locks)
□ No shared memory between execution contexts
□ Lane executor: lane-local queue, single owner (no locks)
□ Async CibosWaker: signals kernel via message (no locks)
```

### Testing Methodology

**Thread sanitizer:** `RUSTFLAGS="-Z sanitizer=thread" cargo build` then run under high load. Any data race = FAILURE.

**Contention test:** 1000+ containers with 10+ lanes each. Linear latency growth = PASS. Super-linear = FAILURE.

**Dispatch model verification:**
```bash
cibos-test --verify-dispatch-model
# When N ≤ C: ALL N events must dispatch simultaneously — ANY violation = CRITICAL FAILURE
# When N > C: EXACTLY C events must dispatch
```

**Async runtime verification:**
```bash
cibos-test --verify-async-runtime
# Verify .await points correctly stall/resume via kernel
# Verify no Tokio dependency anywhere
# Verify no global task queue
```

**Dynamic weight verification (Compute profile):**
```bash
cibos-test --verify-dynamic-weights
# Verify weight changes propagate correctly via messages
# Verify zero impact on dispatch throughput
# Verify no locks introduced
```

---

## Appendix: Error Types

### FirmwareError (CIBIOS)

```rust
pub enum FirmwareError {
    HardwareInitFailed,
    MemoryInitFailed,
    SMTConfigFailed,
    CryptoInitFailed,
    IsolationSetupFailed,
    ConfigLoadFailed,
    VerificationFailed,
    SignatureInvalid,
    StorageReadFailed,
    HandoffPreparationFailed,
    OSEntryPointInvalid,
    UnsupportedArchitecture,
    InsufficientMemory,
}
```

### KernelError (CIBOS)

```rust
pub enum KernelError {
    SchedulerError(SchedulerError),
    MemoryError(MemoryError),
    IpcError(IpcError),
    IsolationError(IsolationError),
    ConfigError(ConfigError),
    AsyncRuntimeError(AsyncRuntimeError),
    WeightUpdateError(WeightUpdateError),  // when dynamic-weights compiled
}
```

---

*For deployment guidance, see the Administrator Guide. For application programming, see the Application Developer Guide. For the async runtime specifically, see the CIBOS Async Runtime Guide.*
