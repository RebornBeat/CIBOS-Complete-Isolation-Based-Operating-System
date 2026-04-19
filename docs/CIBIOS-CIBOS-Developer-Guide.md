# CIBIOS/CIBOS Developer Guide
**Implementation Reference for Kernel and Firmware Developers**

## Introduction

This guide provides complete implementation details for developers working on the CIBIOS firmware and CIBOS kernel. It covers the exact mechanisms, algorithms, data structures, and interaction patterns that implement the Hybrid Isolation Paradigm at the system level.

This guide assumes familiarity with the HIP README, CIBIOS README, and CIBOS README. It provides the implementation-level detail that README documents appropriately omit.

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
│   ├── build.rs            (assembly compilation)
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       ├── allocator.rs    (bump allocator for firmware heap)
│       ├── serial.rs       (debug output, no OS required)
│       ├── entropy.rs      (hardware RNG without OS)
│       ├── arch/
│       │   ├── x86_64/     (boot.s, memory.s, transfer.s)
│       │   ├── aarch64/
│       │   ├── x86/
│       │   └── riscv64/
│       ├── core/
│       │   ├── boot.rs
│       │   ├── hardware.rs
│       │   ├── memory.rs
│       │   ├── isolation.rs
│       │   ├── smt.rs      (SMT configuration at boot)
│       │   ├── verification.rs
│       │   └── handoff.rs
│       └── security/
├── kernel/                 (CIBOS)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       ├── scheduler/
│       │   ├── mod.rs      (dispatch logic: catch-release + entropy)
│       │   ├── ready_pool.rs
│       │   ├── stalled_list.rs
│       │   ├── selector.rs
│       │   └── anti_starvation.rs
│       ├── core/
│       │   ├── memory.rs
│       │   ├── ipc.rs
│       │   ├── isolation.rs
│       │   └── syscall.rs
│       └── security/
├── shared/                 (common types used by both)
├── platforms/              (architecture-specific code)
├── tools/                  (build and signing tools)
└── profiles/               (profile feature flag presets)
```

### System Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CIBIOS FIRMWARE                                │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │   Boot      │  │  Isolation  │  │ Handoff     │  │ Hardware    │       │
│  │ Sequence    │  │ Boundary    │  │ Protocol    │  │ Abstraction │       │
│  │ Controller  │  │ Manager     │  │ Handler     │  │ Layer       │       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
│                                                                             │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
                                │ Handoff (Cryptographic or Lightweight)
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CIBOS KERNEL                                   │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Scheduler     │  │  Memory Manager │  │    IPC Engine   │            │
│  │  (Weighted      │  │  (Isolated      │  │  (Channels)     │            │
│  │   Entropy)      │  │   Regions)      │  │                 │            │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘            │
│           │                    │                    │                      │
│           └────────────────────┼────────────────────┘                      │
│                                │                                           │
│                    ┌───────────▼───────────┐                               │
│                    │   Ready Pool Manager  │                               │
│                    │   Stalled List Mgr    │                               │
│                    └───────────────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                 │
                                 │ Event Routing
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION CORES                                   │
│                                                                             │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│  │ Core 0  │    │ Core 1  │    │ Core 2  │    │ Core N  │                  │
│  │         │    │         │    │         │    │         │                  │
│  │ Execute │    │ Execute │    │ Execute │    │ Execute │                  │
│  │ Event   │    │ Event   │    │ Event   │    │ Event   │                  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow: Event Selection and Execution

```
┌──────────────────────────────────────────────────────────────────┐
│                     EVENT LIFECYCLE                              │
│                                                                  │
│  1. EVENT CREATED                                                │
│     └─► Container creates work item                              │
│         └─► Check resource availability                          │
│             ├─► Available ──► Enter READY POOL                   │
│             └─► Unavailable ──► Enter STALLED LIST               │
│                                                                  │
│  2. IN READY POOL                                                │
│     └─► Event has weight assigned                                │
│         └─► Competing for dispatch opportunity                   │
│             └─► Dispatch assessment                               │
│                 ├─► No competition ──► DISPATCH ALL              │
│                 └─► Competition ──► Weighted entropy selection   │
│                                                                  │
│  3. EXECUTING                                                     │
│     └─► Event runs on core                                        │
│         ├─► Completes successfully ──► DONE                       │
│         └─► Resource unavailable ──► Enter STALLED LIST          │
│                                                                  │
│  4. IN STALLED LIST                                               │
│     └─► Waiting for resource                                      │
│         └─► Resource becomes available                            │
│             └─► Kernel verifies ALL requirements                  │
│                 └─► Qualified ──► Move to READY POOL             │
│                 └─► Not qualified ──► Stay in STALLED LIST       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Event State Machine

```
                    ┌─────────────────────┐
                    │      CREATED        │
                    │                     │
                    │ New work item       │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
            Resources OK          Resources N/A
                    │                     │
                    ▼                     ▼
           ┌─────────────┐        ┌─────────────┐
           │    READY    │        │   STALLED   │
           │             │        │             │
           │ In Pool     │        │ Wait List   │
           │ Weight: W   │        │ Waiting for │
           │ Timer: T    │        │ Resource R  │
           └──────┬──────┘        └──────┬──────┘
                  │                      │
          Dispatched│                     │All Resources
                    │                     │Available
                  ▼                      │
           ┌─────────────┐               │
           │  EXECUTING  │◄──────────────┘
           │             │
           │ On Core C   │
           └──────┬──────┘
                  │
           ┌──────┴──────┐
           │             │
       Complete    Resource N/A
           │             │
           ▼             ▼
     ┌──────────┐  ┌─────────────┐
     │  DONE    │  │   STALLED   │
     │          │  │             │
     │ Finished │  │ Wait for R  │
     └──────────┘  └─────────────┘
```

---

## Chapter 2: CIBIOS Firmware Implementation

### no_std Requirements

CIBIOS is a bare-metal firmware binary. It has no operating system beneath it.

**Required crate-level attributes in lib.rs:**
```rust
#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
```

**The allocator problem:** `no_std` provides no allocator by default. CIBIOS provides a bump allocator. This allocator never frees memory — firmware operation is short and all memory is reclaimed at CIBOS handoff.

**The panic problem:** CIBIOS provides its own panic handler that writes to serial and halts.

**The RNG problem:** Standard `rand` crate requires OS. CIBIOS uses hardware RNG directly:
- **x86_64:** RDRAND instruction (check CPUID leaf 1, ECX bit 30)
- **ARM64:** RNDR system register (check ID_AA64ISAR0_EL1 RNDR field)
- **RISC-V:** SEED CSR from Zkr extension

**No async/await anywhere in CIBIOS.** Every function is synchronous. Every call returns `Result<T, FirmwareError>`. The `anyhow` crate requires `std` and is not used.

### CIBIOS Bump Allocator

Static memory region in `.bss` section. Atomic cursor for thread-safety within firmware. Never frees. Heap size: 2MB default, sufficient for all firmware operations.

### Debug Output: Serial Without OS

- **x86_64:** COM1 at I/O port 0x3F8, 115200 baud 8N1
- **ARM64:** PL011 UART at platform-specific address
- **RISC-V:** SiFive UART at platform-specific address

Output is write-only, polling-based. No interrupts. No DMA. No OS.

### Linker Scripts

- **x86_64:** Load at 0x100000 (1MB)
- **ARM64:** Load at 0x40080000
- **RISC-V:** Load at 0x80000000

The linker script places `_start` first in `.text` to ensure it is at the entry point address.

### build.rs: Assembling Boot Code

```rust
fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let asm_dir = match target_arch.as_str() {
        "x86_64" => "src/arch/x86_64/asm",
        "aarch64" => "src/arch/aarch64/asm",
        "riscv64" => "src/arch/riscv64/asm",
        "x86" => "src/arch/x86/asm",
        _ => panic!("Unsupported architecture"),
    };
    cc::Build::new()
        .flag("-x").flag("assembler-with-cpp")
        .files(/* all .s files in asm_dir */)
        .compile("cibios_asm");
}
```

### SMT Configuration

CIBIOS configures SMT at boot before handoff:

```rust
pub fn configure_smt(profile: Profile) {
    match profile {
        Profile::Standard => {
            // Disable SMT for Maximum Isolation and Balanced profiles
            disable_smt_hardware();
        }
        Profile::Lightweight => {
            // Enable SMT for Performance and Compute profiles
            enable_smt_hardware();
        }
    }
}

fn disable_smt_hardware() {
    // x86_64: Write to IA32_MISC_ENABLE MSR or use CPUID leaf 0x1F
    // ARM64: Write to MPIDR_EL1 cluster threading control
    // RISC-V: Platform-specific hart management
    architecture_specific_smt_disable();
}
```

### CIBIOS Initialization Sequence

1. CPU state initialization (assembly)
2. BSS zeroing
3. Serial port initialization for debug output
4. Hardware RNG availability check
5. Hardware detection (CPU, memory, storage, display)
6. Memory isolation boundary configuration
7. Lane memory region reservation
8. SMT configuration per profile
9. Cryptographic engine initialization (Standard profile only)
10. Boot configuration loading
11. First boot detection and setup UI (if applicable)
12. CIBOS image loading from storage
13. CIBOS image verification (Standard profile only)
14. CIBOS entry point parsing from ELF header
15. Isolation boundary finalization
16. Handoff data structure preparation (including SMT status)
17. Control transfer to CIBOS

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
    pub verification_chain: VerificationChain, // Standard only
}
```

The structure is defined in the `shared` crate with `#[repr(C)]` for binary compatibility.

### Handoff Protocol

**Cryptographic Handoff (Standard Profile):**

```
┌─────────────────────────────────────────────────────────────┐
│               CRYPTOGRAPHIC HANDOFF                          │
│                                                             │
│  1. CIBIOS loads CIBOS kernel image                         │
│  2. CIBIOS computes SHA-256 hash of image                   │
│  3. CIBIOS verifies Ed25519 signature                       │
│  4. If verification fails: halt with error                  │
│  5. CIBIOS prepares HandoffData structure                   │
│  6. CIBIOS writes HandoffData to known address              │
│  7. CIBIOS transfers control to CIBOS entry point           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Lightweight Handoff (Lightweight Profile):**

```
┌─────────────────────────────────────────────────────────────┐
│               LIGHTWEIGHT HANDOFF                            │
│                                                             │
│  1. CIBIOS loads CIBOS kernel image                         │
│  2. CIBIOS prepares HandoffData structure                   │
│  3. CIBIOS writes HandoffData to known address              │
│  4. CIBIOS transfers control to CIBOS entry point           │
│     (No signature verification)                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 3: The Two-Layer Execution Model Implementation

### Layer 1: Catch and Release Data Structures

**Ready Pool:**
```
ReadyPool {
    events: Vec<ReadyEvent>,
    total_weight: u64,
}

ReadyEvent {
    lane_id: Uuid,
    container_id: Uuid,
    weight: u32,
    entry_time: Instant,
    accumulated_ready_time: Duration,
    event_payload: ExecutionEvent,
}
```

**Ready Pool Operations:**

```
OPERATIONS:

Add Event:
  1. Create ReadyEvent with current timestamp
  2. Add to events list
  3. Add weight to total_weight

Remove Event (by Lane ID):
  1. Find event by lane_id
  2. Subtract weight from total_weight
  3. Remove from events list
  4. Return event

Select Event (Weighted Entropy - only when competition exists):
  1. Generate random R in [0, total_weight)
  2. Walk events, accumulating weights
  3. Return event where accumulated > R
```

**Stalled List:**
```
StalledList {
    entries: Vec<StalledEntry>,
    // Indexed by resource type for efficient lookup
    memory_waiters: HashMap<ContainerId, ResourceRequirements>,
    io_waiters: HashMap<ContainerId, ResourceRequirements>,
    channel_waiters: HashMap<ChannelId, Vec<ContainerId>>,
}

StalledEntry {
    container_id: Uuid,
    lane_id: Uuid,
    resource_requirements: ResourceRequirements, // ALL resources needed
    stall_time: Instant,
    pending_event: ExecutionEvent,
    accumulated_ready_time: Duration, // preserved from Ready Pool
}

ResourceRequirements {
    memory_bytes: Option<u64>,
    channel_reads: Vec<ChannelId>,
    channel_writes: Vec<ChannelId>,
    io_operations: Vec<IoOperationId>,
}
```

**Stalled List Operations:**

```
OPERATIONS:

Stall Container:
  1. Create StalledEntry with preserved accumulated time
  2. Add to entries list
  3. Add to resource-type index

Release for Resource:
  1. Lookup entries waiting for resource
  2. For each: verify ALL required resources available
  3. Remove qualified entries from entries list
  4. Remove from resource-type index
  5. Return qualified entries for Ready Pool

Find Waiting:
  1. Lookup by resource type
  2. Return matching entries
```

### Resource Types

```
RESOURCE TYPES:

┌─────────────────────────────────────────────────────────────┐
│                     RESOURCE TYPES                           │
│                                                             │
│  Memory:                                                    │
│  - GlobalMemory: System-wide memory pool                    │
│  - ContainerMemory(ContainerID): Per-container limit        │
│                                                             │
│  I/O:                                                       │
│  - DiskIO(ContainerID): Disk operations                     │
│  - NetworkIO(ContainerID): Network operations               │
│                                                             │
│  Channels:                                                  │
│  - ChannelBuffer(ChannelID, Direction): Buffer space        │
│  - ChannelData(ChannelID, Direction): Data availability     │
│                                                             │
│  Custom:                                                    │
│  - Custom(ResourceID): Application-defined resources        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Event State Manager

```
EVENT STATE MANAGER:

┌─────────────────────────────────────────────────────────────┐
│                  EVENT STATE MANAGER                         │
│                                                             │
│  Ready Pool: ReadyPool                                      │
│  Stalled List: StalledList                                  │
│  Resource Registry: ResourceRegistry                        │
│                                                             │
│  METHODS:                                                   │
│                                                             │
│  event_created(event, resources_available):                 │
│    if resources_available:                                  │
│      ready_pool.add(event)                                  │
│    else:                                                    │
│      stalled_list.stall(event)                              │
│                                                             │
│  event_selected(lane_id):                                   │
│    event = ready_pool.remove(lane_id)                       │
│    return event                                             │
│                                                             │
│  execution_stalled(event, resource):                        │
│    // Preserve accumulated ready time                        │
│    entry = StalledEntry {                                   │
│      accumulated = event.accumulated_ready_time,            │
│      ...                                                    │
│    }                                                        │
│    stalled_list.stall(entry)                                │
│                                                             │
│  resource_available(resource):                              │
│    entries = stalled_list.release_for_resource(resource)    │
│    for entry in entries:                                    │
│      ready_pool.add(ReadyEvent {                            │
│        accumulated = entry.accumulated,                     │
│        entry_time = now(),                                  │
│        ...                                                  │
│      })                                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Resource Signal Processing: The Qualification Check

When a resource signal arrives, the processing is NOT "move all waiters." It is "move qualified waiters — those for whom ALL requirements are now satisfied."

```
RESOURCE SIGNAL PROCESSING:

signal: ResourceAvailable { resource_type }

1. Find all containers waiting for resource_type

2. FOR EACH container:
   requirements = container.resource_requirements

   qualified = true

   for each req in requirements.memory_bytes:
     if memory_registry.available(container) < req:
       qualified = false; break

   for each channel in requirements.channel_reads:
     if channel_registry.data_available(channel) == false:
       qualified = false; break

   for each channel in requirements.channel_writes:
     if channel_registry.buffer_space(channel) == false:
       qualified = false; break

   for each io_op in requirements.io_operations:
     if io_registry.complete(io_op) == false:
       qualified = false; break

   IF qualified:
     stalled_list.remove(container)
     ready_pool.add(ReadyEvent {
       lane_id: container.lane_id,
       container_id: container.container_id,
       weight: container.weight,
       entry_time: now(),
       accumulated_ready_time: container.accumulated_ready_time,
       event_payload: container.pending_event,
     })
   ELSE:
     // Container stays in Stalled List
     // Update what it's primarily waiting for (optional optimization)
```

**Integration with State Manager:**

```
signal_processor_loop():
  while running:
    for signal in pending_signals():
      match signal:
        MemoryFreed(cid, _):
          state_manager.resource_available(Memory(cid))
        IOComplete(cid, _):
          state_manager.resource_available(DiskIO(cid))
        BufferAvailable(chid):
          state_manager.resource_available(ChannelBuffer(chid))
        DataAvailable(chid):
          state_manager.resource_available(ChannelData(chid))
```

### Layer 2: Dispatch Logic

```
DISPATCH LOGIC:

TRIGGER: Core completion signal, resource availability, new work created

1. available_contexts = count_available_execution_contexts()
   // Includes all logical cores that are free (physical × SMT)

2. ready_count = ready_pool.size()

3. IF ready_count == 0: return  // Nothing to dispatch

4. IF ready_count <= available_contexts:
   // NO COMPETITION — dispatch all
   FOR each event IN ready_pool.all():
     context = select_context(event)  // Cache affinity
     dispatch_to(event, context)
   // All events dispatched, ready pool now empty
   return

5. // COMPETITION EXISTS — need selection
   dispatch_count = available_contexts
   selected = weighted_entropy_select(ready_pool, dispatch_count)
   FOR each event IN selected:
     context = select_context(event)
     dispatch_to(event, context)
   // Remaining events stay in ready pool (not stalled)
```

---

## Chapter 4: Weighted Entropy Algorithm

### Selection Algorithm (Called Only When Competition Exists)

```
WEIGHTED ENTROPY SELECTION:

Input: ReadyPool with N events, need to select K events (K < N)
Output: K selected events

Algorithm (select K from N):

1. IF pool is empty OR K == 0: return []

2. total_weight = Σ weightᵢ for all events in pool

3. IF total_weight == 0: return first K events

4. selected = []
   pool_copy = copy_of_pool

   FOR i = 0 to K-1:
     // Generate random value in [0, current_total_weight)
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

COMPLEXITY: O(K × N) where N = events in pool, K = events to select
For typical K = available_contexts and moderate N, this is fast.

OPTIMIZATION: For systems with many events, use prefix-sum tree
for O(log N) selection.
```

### With Anti-Starvation Priority

```
SELECTION WITH ANTI-STARVATION:

1. Compute current total wait for each event in Ready Pool:
   total_wait = event.accumulated_ready_time
                + (now() - event.entry_time)

2. Identify events exceeding threshold:
   starving = events WHERE total_wait > threshold

3. IF starving is not empty:
   // Select from starving events first (with entropy among them)
   priority_count = min(len(starving), available_contexts)
   priority_selected = entropy_select(starving, priority_count)

   // Fill remaining slots from non-starving events
   remaining_slots = available_contexts - priority_count
   IF remaining_slots > 0:
     non_starving = ready_pool.all() - priority_selected
     other_selected = weighted_entropy_select(non_starving, remaining_slots)

   return priority_selected + other_selected

4. ELSE: normal weighted entropy selection
```

### Entropy Source

```
ENTROPY SOURCE:

┌─────────────────────────────────────────────────────────────┐
│                    ENTROPY SOURCE                            │
│                                                             │
│  IMPLEMENTATION: ChaCha20 CSPRNG                            │
│                                                             │
│  SEEDING:                                                   │
│  - Initial seed from hardware RNG                           │
│  - Periodic reseed from hardware entropy                    │
│                                                             │
│  INTERFACE:                                                 │
│  - gen_range(min, max) → u64                                │
│  - gen_bytes(len) → [u8]                                    │
│  - reseed(seed) → void                                      │
│                                                             │
│  HARDWARE RNG SOURCES:                                      │
│  - x86_64: RDRAND instruction                               │
│  - ARM64: RNDR system register                              │
│  - RISC-V: SEED CSR (Zkr extension)                         │
│                                                             │
│  FALLBACK:                                                  │
│  - If hardware RNG unavailable:                             │
│    - Entropy from timing variations                         │
│    - Entropy from interrupt timing                          │
│    - Entropy from storage access timing                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 5: Anti-Starvation Timer Semantics

### Timer Fields Per Event

```
ANTI-STARVATION TIMER FIELDS:

┌─────────────────────────────────────────────────────────────┐
│                 TIMER FIELDS PER EVENT                       │
│                                                             │
│  accumulated_ready_time: Duration                           │
│    - Total time spent in Ready Pool across all stints       │
│    - Zero for newly created events                          │
│    - Preserved when stalled                                 │
│    - Reset when new event becomes head                      │
│                                                             │
│  entry_time: Instant                                        │
│    - Timestamp when event entered Ready Pool (current stint)│
│    - Updated each time event enters Ready Pool              │
│    - Used to calculate current stint duration               │
│                                                             │
│  is_in_ready_pool: bool                                     │
│    - True if event is currently in Ready Pool               │
│    - False if executing, stalled, or inactive               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Timer Behavior Through All Transitions

**Event enters Ready Pool (any source — new work or from Stalled List):**
```
// From INACTIVE (new event)
accumulated_ready_time = 0
entry_time = now()
is_in_ready_pool = true

// From STALLED (resource available)
// accumulated_ready_time preserved from stall
entry_time = now()
is_in_ready_pool = true
```

**Event dispatched from Ready Pool:**
```
// accumulated_ready_time NOT updated at this point
// It is preserved for potential future stall
// If the event completes and a NEW head event forms,
// the NEW event starts with accumulated_ready_time = 0
is_in_ready_pool = false
```

**Event execution stalls (exits Ready Pool → Stalled List):**
```
// Add current stint to accumulated
accumulated_ready_time += (now() - entry_time)
is_in_ready_pool = false
// Value preserved in StalledEntry
```

**Event returns from Stalled List to Ready Pool:**
```
// accumulated_ready_time carried forward from StalledEntry
entry_time = now()       // new stint begins
is_in_ready_pool = true
```

**Event completes and new head event forms:**
```
// New event becomes head
accumulated_ready_time = 0  // RESET for new event
entry_time = now()
is_in_ready_pool = true
```

### Current Wait Calculation

```
CALCULATING CURRENT TOTAL WAIT:

get_total_ready_wait(event, now):
  if event.is_in_ready_pool:
    current_stint = now - event.entry_time
    return event.accumulated_ready_time + current_stint
  else:
    return event.accumulated_ready_time

// This correctly returns:
// - Only Ready Pool time
// - Does NOT include time spent stalled
// - Accumulates across multiple Ready Pool visits
```

### Key Semantic Rules

```
SEMANTIC RULES:

┌─────────────────────────────────────────────────────────────┐
│                  KEY SEMANTIC RULES                          │
│                                                             │
│  1. READY TIME ONLY:                                        │
│     Anti-starvation measures ONLY time in Ready Pool.       │
│     Time spent stalled does NOT count.                      │
│                                                             │
│  2. ACCUMULATION ACROSS STINTS:                             │
│     If an event stalls and returns to Ready Pool,           │
│     the accumulated time is preserved.                      │
│                                                             │
│  3. RESET ON NEW HEAD:                                      │
│     When a lane's head event completes and the next         │
│     event becomes head, the timer resets to zero.           │
│     This is a NEW event, not a continuation.                │
│                                                             │
│  4. STALL PAUSES TIMER:                                     │
│     When an event stalls, timer stops accumulating.         │
│     The accumulated value is preserved.                     │
│                                                             │
│  5. ANTI-STARVATION IS SELECTION FAIRNESS:                  │
│     Anti-starvation ensures selection fairness.             │
│     It does NOT address resource availability.              │
│     A container waiting for unavailable resource            │
│     is NOT being starved—it cannot execute anyway.         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 6: Multi-Core Single-Pool Routing

### Selector Thread Implementation

```
SELECTOR THREAD STATE:

ready_pool: ReadyPool          // Owned exclusively by selector
stalled_list: StalledList      // Owned exclusively by selector
core_state: Vec<CoreState>     // Availability and last container
from_cores: Receiver<CoreMessage>
to_cores: Vec<Sender<SelectorMessage>>
resource_signals: Receiver<ResourceSignal>
entropy: KernelEntropy

SELECTOR MAIN LOOP:

while running {
    // Step 1: Process core messages (non-blocking drain)
    while let Ok(msg) = from_cores.try_recv() {
        match msg {
            ExecutionComplete { context_id, lane_id, container_id } => {
                core_state[context_id].available = true;
                core_state[context_id].last_container = container_id;
                // Check if this lane has more work
                if let Some(next) = get_next_lane_event(lane_id) {
                    if all_resources_available(next) {
                        ready_pool.add(next);
                    } else {
                        stalled_list.add(next);
                    }
                }
            }
            ExecutionStalled { context_id, lane_id, resources, event } => {
                core_state[context_id].available = true;
                // Move to stalled list with preserved accumulated time
                stalled_list.add(StalledEntry {
                    accumulated_ready_time: event.accumulated_ready_time,
                    ...
                });
            }
        }
    }

    // Step 2: Process resource signals (non-blocking drain)
    while let Ok(signal) = resource_signals.try_recv() {
        process_resource_signal(signal); // Moves qualified to Ready Pool
    }

    // Step 3: Process timer events (application-level timers)
    for fired_timer in collect_fired_timers() {
        ready_pool.add(timer_event(fired_timer));
    }

    // Step 4: Check anti-starvation (if compiled in)
    #[cfg(feature = "anti-starvation")]
    mark_starving_events_for_priority();

    // Step 5: Assess and dispatch
    let available_count = core_state.iter().filter(|c| c.available).count();
    let ready_count = ready_pool.size();

    if available_count > 0 && ready_count > 0 {
        if ready_count <= available_count {
            // No competition: dispatch all
            for event in ready_pool.drain_all() {
                let ctx = select_context_affinity(
                    &event, &core_state
                );
                dispatch_event(event, ctx);
                core_state[ctx].available = false;
            }
        } else {
            // Competition: weighted entropy selection
            let selected = weighted_entropy_select(
                &ready_pool,
                available_count,
                &mut entropy,
            );
            for event in selected {
                ready_pool.remove(event.lane_id);
                let ctx = select_context_affinity(
                    &event, &core_state
                );
                dispatch_event(event, ctx);
                core_state[ctx].available = false;
            }
        }
    }

    // Step 6: Yield if nothing to do
    if ready_pool.is_empty() && stalled_list.is_empty() {
        thread::yield_now();
    }
}
```

### Core Routing Logic

```
CORE ROUTING:

┌─────────────────────────────────────────────────────────────┐
│                    EVENT ROUTING                             │
│                                                             │
│  find_available_core(): Option<usize>                       │
│    for i in 0..NUM_CORES:                                   │
│      if core_available[i]:                                  │
│        return Some(i)                                       │
│    return None                                              │
│                                                             │
│  find_best_core(event): usize                               │
│    // Optional cache affinity optimization                  │
│    preferred = get_affinity_core(event.container_id)        │
│    if preferred.is_some() && core_available[preferred]:     │
│      return preferred                                       │
│    return find_available_core()                             │
│                                                             │
│  route_event(event, core_id):                               │
│    core_executing[core_id] = event.container_id             │
│    to_cores[core_id].send(Execute(event))                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Cache Affinity Tracking

```
CACHE AFFINITY (OPTIONAL OPTIMIZATION):

┌─────────────────────────────────────────────────────────────┐
│                 CACHE AFFINITY TRACKER                       │
│                                                             │
│  last_core: HashMap<ContainerId, CoreId>                    │
│                                                             │
│  record_execution(container_id, core_id):                  │
│    last_core[container_id] = core_id                        │
│                                                             │
│  get_affinity_core(container_id): Option<CoreId>            │
│    return last_core.get(container_id)                       │
│                                                             │
│  WHY THIS HELPS:                                            │
│  - If core recently executed same container,                │
│    cache likely has relevant data                           │
│  - Reduces cache cold-start overhead                        │
│  - No shared state—selector maintains the map               │
│  - No coordination between cores                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Message Types

```
MESSAGE TYPES:

┌─────────────────────────────────────────────────────────────┐
│                    MESSAGE TYPES                             │
│                                                             │
│  CoreMessage (Core → Selector):                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ExecutionComplete {                                  │   │
│  │   core_id: usize,                                   │   │
│  │   lane_id: Uuid,                                    │   │
│  │ }                                                   │   │
│  │                                                     │   │
│  │ ExecutionStalled {                                  │   │
│  │   core_id: usize,                                   │   │
│  │   lane_id: Uuid,                                    │   │
│  │   resource: ResourceType,                           │   │
│  │   preserved_time: Duration,                         │   │
│  │ }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  SelectorMessage (Selector → Core):                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Execute {                                            │   │
│  │   event: ExecutionEvent,                            │   │
│  │ }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ResourceSignal (Resource Manager → Selector):              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ MemoryAvailable { container_id: Option<Uuid> }       │   │
│  │ IOComplete { container_id: Uuid }                    │   │
│  │ ChannelBufferAvailable { channel_id: Uuid }          │   │
│  │ ChannelDataAvailable { channel_id: Uuid }            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why Single Selector

A single selector is not a bottleneck. Per-dispatch work is bounded:
- Signal processing: O(signals received)
- Resource check: O(stalled containers for this resource)
- Entropy selection: O(K × N) where K = cores, N = ready events
- Dispatch: O(K)

For typical deployments (4-128 cores, hundreds to thousands of containers), this work completes in microseconds. The selector can handle hundreds of thousands of dispatch decisions per second — orders of magnitude more than typical workloads generate.

Multiple selectors would require:
- Partitioning the container set (arbitrary, creates load imbalance)
- Coordinating between selectors (lock-like behavior)
- Complexity without throughput improvement

---

## Chapter 7: Execution Capacity: SMT Implementation

### SMT Detection and Configuration

```rust
pub struct ExecutionCapacity {
    pub physical_cores: u32,
    pub smt_factor: u32,
    pub logical_cores: u32,
}

impl ExecutionCapacity {
    pub fn from_handoff(handoff: &HandoffData) -> Self {
        ExecutionCapacity {
            physical_cores: handoff.physical_core_count,
            smt_factor: if handoff.smt_enabled {
                handoff.logical_core_count / handoff.physical_core_count
            } else {
                1
            },
            logical_cores: handoff.logical_core_count,
        }
    }

    pub fn total_execution_contexts(&self) -> u32 {
        self.logical_cores
    }
}
```

### Context Availability Tracking

The selector maintains one entry per logical core. Each entry tracks:
- `available: bool` — is this context free?
- `last_container: Option<ContainerId>` — for cache affinity

---

## Chapter 8: Configuration System

### Configuration File Format

```toml
# /boot/cibos.conf

[scheduling]
# Weight values (positive integers)
system_weight = 3
user_weight = 1
background_weight = 1

# Anti-starvation threshold (milliseconds)
# Set to 0 to disable
anti_starvation_threshold_ms = 100

[resources]
# Per-container limits
memory_limit_mb = 512
io_bandwidth_mbps = 100

[channels]
max_channels_per_container = 16
message_queue_size = 256

[signature]
algorithm = "ed25519"
signature = "<base64-encoded-signature>"
```

### Configuration Loading

```
CONFIGURATION LOADING:

load_config(path, pubkey): Result<Config, Error>

1. Read config file
2. Read signature file
3. Verify signature with embedded public key
   - If invalid: return Error, use compiled defaults
   - If missing: use compiled defaults
4. Parse configuration
5. Validate values:
   - weights > 0
   - threshold >= 0
   - limits reasonable
6. Return validated config

COMPILED DEFAULTS:
┌─────────────────────────────────────────────────────┐
│ Defaults by Profile:                                 │
│                                                     │
│ Maximum Isolation:                                  │
│   system_weight = 1                                 │
│   user_weight = 1                                   │
│   background_weight = 1                             │
│   anti_starvation = disabled (not compiled)         │
│                                                     │
│ Balanced:                                            │
│   system_weight = 3                                 │
│   user_weight = 1                                   │
│   background_weight = 1                             │
│   anti_starvation = 100ms                           │
│                                                     │
│ Performance:                                         │
│   system_weight = 5                                 │
│   user_weight = 2                                   │
│   background_weight = 1                             │
│   anti_starvation = 50ms                            │
│                                                     │
│ Compute:                                             │
│   system_weight = 1                                 │
│   user_weight = 1                                   │
│   background_weight = 1                             │
│   anti_starvation = optional                        │
└─────────────────────────────────────────────────────┘
```

### Signature Verification

```
SIGNATURE VERIFICATION:

verify_config(data, signature, pubkey): Result<(), Error>

1. Parse signature as Ed25519 Signature
2. Verify data with pubkey
3. Return Ok if valid, Error if invalid

KEY MANAGEMENT:
- Public key embedded in CIBIOS at build time
- Private key managed externally
- Sign config with: cibos-sign --key priv.pem config
- Verify with: cibos-verify --key pub.pem config sig
```

---

## Chapter 9: Resource Signals

### Memory Signal Handling

```
MEMORY SIGNALS:

┌─────────────────────────────────────────────────────────────┐
│                   MEMORY MANAGER                             │
│                                                             │
│  SIGNALS EMITTED:                                           │
│  - MemoryFreed { container_id, amount }                     │
│  - MemoryLimitExceeded { container_id }                     │
│  - GlobalMemoryAvailable { amount }                         │
│                                                             │
│  PROCESSING:                                                │
│  MemoryFreed { container_id, ... }:                         │
│    1. Find entries waiting for Memory(container_id)         │
│    2. Move to Ready Pool                                    │
│    3. Update container memory tracking                      │
│                                                             │
│  GlobalMemoryAvailable { ... }:                             │
│    1. Find entries waiting for GlobalMemory                 │
│    2. Move to Ready Pool                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### I/O Signal Handling

```
I/O SIGNALS:

┌─────────────────────────────────────────────────────────────┐
│                     I/O MANAGER                              │
│                                                             │
│  SIGNALS EMITTED:                                           │
│  - DiskIOComplete { container_id, operation_id }            │
│  - NetworkIOComplete { container_id, operation_id }         │
│                                                             │
│  PROCESSING:                                                │
│  IOComplete { container_id, ... }:                          │
│    1. Find entries waiting for IO(container_id)             │
│    2. Move to Ready Pool                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Channel Signal Handling

```
CHANNEL SIGNALS:

┌─────────────────────────────────────────────────────────────┐
│                    CHANNEL MANAGER                           │
│                                                             │
│  SIGNALS EMITTED:                                           │
│  - BufferSpaceAvailable { channel_id }                      │
│  - DataAvailable { channel_id }                             │
│                                                             │
│  PROCESSING:                                                │
│  BufferSpaceAvailable { channel_id }:                       │
│    1. Find senders waiting for this channel                │
│    2. Move to Ready Pool                                    │
│                                                             │
│  DataAvailable { channel_id }:                              │
│    1. Find receivers waiting for this channel              │
│    2. Move to Ready Pool                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 10: Channel Implementation

### Channel Data Structure

```
Channel {
    id: ChannelId,
    source_container: ContainerId,
    destination_container: ContainerId,
    mode: ChannelMode,
    message_buffer: CircularBuffer,
    rate_limiter: RateLimiter,
    lifetime: ChannelLifetime,
}

ChannelMode {
    Cryptographic { session_key: [u8; 32] }  // AES-256
    LightweightHandshake
}
```

### Channel Buffer and Catch and Release

When a sender attempts to send and the buffer is full:
1. Container encounters full buffer during execution
2. Container signals `ExecutionStalled { resources: [ChannelBuffer(id)] }`
3. Selector moves container to Stalled List
4. When receiver reads, freeing buffer space: `ChannelBufferAvailable` signal emitted
5. Selector processes signal, verifies ALL requirements, moves container to Ready Pool if qualified

When a receiver attempts to receive from an empty buffer:
1. Container encounters empty buffer during execution
2. Container signals `ExecutionStalled { resources: [ChannelData(id)] }`
3. Selector moves container to Stalled List
4. When sender writes to buffer: `ChannelDataAvailable` signal emitted
5. Selector processes, qualifies, moves to Ready Pool

---

## Chapter 11: RTRO Implementation

### What RTRO Intercepts

RTRO is compiled into the kernel boundary layer between kernel-internal state and all observable outputs. Observable outputs include system call responses, event log entries, scheduler state queries, and performance counter access.

### RTRO Mechanism

For each observable output:
1. Kernel computes the actual value
2. RTRO applies a randomized transformation to the reported value
3. Transformed value is returned to the observer

The transformation is consistent within a context window (a single process's view in a single invocation) but inconsistent across context windows. RTRO does not modify internal state used for dispatch or resource management.

---

## Chapter 12: No-Global-Locks Verification

### Verification Principles

```
NO-GLOBAL-LOCKS VERIFICATION:

┌─────────────────────────────────────────────────────────────┐
│              VERIFICATION PRINCIPLES                         │
│                                                             │
│  PRINCIPLE 1: SINGLE OWNERSHIP                              │
│  Every mutable data structure has exactly one owner.        │
│  No concurrent access to mutable state.                     │
│  No locks needed because no sharing.                        │
│                                                             │
│  PRINCIPLE 2: MESSAGE PASSING                               │
│  Communication through messages, not shared memory.         │
│  Sender owns message until sent.                            │
│  Receiver owns message after received.                      │
│  No shared ownership.                                       │
│                                                             │
│  PRINCIPLE 3: EVENT-DRIVEN                                  │
│  No polling.                                                │
│  No spinning.                                               │
│  Wait for events, proceed when events arrive.               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Ownership Rules

**Selector owns:** Ready Pool, Stalled List, Core state tracking, Resource registry.
**Execution contexts own:** Their execution state during execution.
**Containers own:** Their internal event queues.
**Communication:** Through lock-free message queues (SPSC — one selector writes, one core reads).

### Code Review Checklist

```
CODE REVIEW CHECKLIST:

┌─────────────────────────────────────────────────────────────┐
│                   CODE REVIEW                                │
│                                                             │
│  □ No Mutex<T> in any module                                │
│  □ No RwLock<T> in any module                               │
│  □ No spin::Mutex in any module                             │
│  □ No parking_lot::Mutex in any module                      │
│  □ No AtomicPtr with mutation                               │
│  □ No Arc<Mutex<T>> patterns                                │
│  □ All mutable state has single owner                       │
│  □ Inter-thread communication via channels only             │
│  □ No busy-wait loops                                       │
│  □ No polling loops                                         │
│  □ All waits are event-driven                               │
│  □ Selector owns Ready Pool exclusively                     │
│  □ Selector owns Stalled List exclusively                   │
│  □ Cores never touch Ready Pool                             │
│  □ Cores never touch Stalled List                           │
│  □ Resource signals are messages, not shared state          │
│  □ No shared memory between cores                           │
│  □ No shared counters between cores                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Testing Methodology

```
TESTING METHODOLOGY:

┌─────────────────────────────────────────────────────────────┐
│                    TESTING                                   │
│                                                             │
│  1. THREAD SANITIZER:                                       │
│     Build with thread sanitizer enabled                     │
│     Run under high load                                     │
│     Any data race detected = FAILURE                        │
│                                                             │
│  2. CONTENTION TESTING:                                     │
│     Create many containers                                  │
│     All competing for execution                             │
│     Measure throughput                                      │
│     Linear scaling = PASS                                   │
│     Super-linear degradation = FAILURE                      │
│                                                             │
│  3. ISOLATION TESTING:                                      │
│     Container A tries to access Container B memory         │
│     Any success = FAILURE                                   │
│                                                             │
│  4. TIMING ANALYSIS:                                        │
│     Measure selection latency distribution                  │
│     Check for periodic spikes                               │
│     No periodic patterns = PASS                             │
│                                                             │
│  5. DEADLOCK DETECTION:                                     │
│     Run extended duration test                              │
│     No stalls that never resolve                            │
│     All stalls eventually release = PASS                    │
│                                                             │
│  6. DISPATCH MODEL VERIFICATION:                            │
│     All ready events dispatch when no competition           │
│     Exactly N events dispatch when competition (N = cores)  │
│     Weighted entropy used only when competition exists      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 13: Profile Build Configuration

### Feature Flag Organization

```
FEATURE FLAGS:

┌─────────────────────────────────────────────────────────────┐
│                  FEATURE FLAGS                               │
│                                                             │
│  CORE (Always compiled):                                    │
│  - weighted-entropy (architectural)                         │
│  - catch-and-release (architectural)                        │
│  - channels (architectural)                                 │
│  - isolation-boundaries (architectural)                     │
│                                                             │
│  SCHEDULING:                                                │
│  - anti-starvation                                          │
│  - full-fairness                                            │
│  - per-lane-weights                                         │
│                                                             │
│  SECURITY:                                                  │
│  - rtro                                                     │
│  - cryptographic-ipc                                        │
│  - lightweight-handshake                                    │
│  - user-authentication                                      │
│  - multi-user-isolation                                     │
│  - audit-logging                                            │
│  - cryptographic-entropy                                    │
│  - hardware-rng                                             │
│                                                             │
│  CAPABILITIES:                                              │
│  - network-stack                                            │
│  - usb-stack                                                │
│  - gui-subsystem                                            │
│  - cli-interface                                            │
│  - audio-subsystem                                          │
│  - dynamic-lanes                                            │
│                                                             │
│  HANDOFF (Shared with CIBIOS):                              │
│  - handoff-cryptographic                                    │
│  - handoff-lightweight                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Profile Definitions

```
PROFILE DEFINITIONS:

┌─────────────────────────────────────────────────────────────┐
│                 PROFILE DEFINITIONS                          │
│                                                             │
│  MAXIMUM ISOLATION:                                         │
│  features = [                                               │
│    "rtro",                                                  │
│    "cryptographic-ipc",                                     │
│    "user-authentication",                                   │
│    "multi-user-isolation",                                  │
│    "audit-logging",                                         │
│    "cryptographic-entropy",                                 │
│    "hardware-rng",                                          │
│    "network-stack",                                         │
│    "gui-subsystem",                                         │
│    "cli-interface",                                         │
│    "handoff-cryptographic",                                 │
│  ]                                                          │
│  smt = "disabled"                                           │
│                                                             │
│  BALANCED:                                                  │
│  features = [                                               │
│    "anti-starvation",                                       │
│    "cryptographic-ipc",                                     │
│    "user-authentication",                                   │
│    "cryptographic-entropy",                                 │
│    "hardware-rng",                                          │
│    "network-stack",                                         │
│    "gui-subsystem",                                         │
│    "cli-interface",                                         │
│    "handoff-cryptographic",                                 │
│    # rtro = optional                                        │
│  ]                                                          │
│  smt = "disabled" (default, user may enable)                │
│                                                             │
│  PERFORMANCE:                                               │
│  features = [                                               │
│    "anti-starvation",                                       │
│    "full-fairness",                                         │
│    "cryptographic-entropy",                                 │
│    "cli-interface",                                         │
│    "handoff-cryptographic",                                 │
│  ]                                                          │
│  smt = "enabled"                                            │
│                                                             │
│  COMPUTE:                                                   │
│  features = [                                               │
│    "per-lane-weights",                                      │
│    "lightweight-handshake",                                 │
│    "cli-interface",                                         │
│    "handoff-lightweight",                                   │
│    "cryptographic-entropy",                                 │
│    # anti-starvation = optional                             │
│  ]                                                          │
│  smt = "enabled"                                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Feature Flag Files

```toml
# profiles/maximum-isolation.toml
[features]
compile_in = [
    "rtro",
    "cryptographic-ipc",
    "user-authentication",
    "multi-user-isolation",
    "audit-logging",
    "cryptographic-entropy",
    "hardware-rng",
    "network-stack",
    "gui-subsystem",
    "cli-interface",
]
handoff = "handoff-cryptographic"
smt = "disabled"

[defaults]
system_weight = 1
user_weight = 1
background_weight = 1
```

```toml
# profiles/compute.toml
[features]
compile_in = [
    "per-lane-weights",
    "lightweight-handshake",
    "cli-interface",
    "cryptographic-entropy",
]
handoff = "handoff-lightweight"
smt = "enabled"

[defaults]
system_weight = 1
user_weight = 1
background_weight = 1
```

---

## Chapter 14: Assembly Integration Reference

### Assembly Function Naming Convention

Pattern: `{arch}_{subsystem}_{operation}`

Examples:
- `x86_64_boot_initialize_hardware`
- `aarch64_memory_setup_isolation`
- `x86_64_boot_configure_smt`
- `x86_64_transfer_control_to_os`

### Rust FFI Declaration Pattern

```rust
mod asm {
    extern "C" {
        /// Initialize CPU hardware state at boot.
        /// Safety: Called once during firmware initialization.
        pub fn x86_64_boot_initialize_hardware() -> i32;

        /// Configure SMT state.
        /// enable: 0 = disable, 1 = enable
        /// Safety: Must be called before any core starts execution.
        pub fn x86_64_boot_configure_smt(enable: u32) -> i32;

        /// Transfer control to CIBOS. Never returns.
        pub fn x86_64_transfer_control_to_os(
            entry_point: u64,
            handoff_data: *const crate::HandoffData,
        ) -> !;
    }
}
```

---

## Appendix: Error Types

### FirmwareError (CIBIOS)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug)]
pub enum KernelError {
    SchedulerError(SchedulerError),
    MemoryError(MemoryError),
    IpcError(IpcError),
    IsolationError(IsolationError),
    ConfigError(ConfigError),
}
```

---

*This Developer Guide covers implementation details for CIBIOS firmware and CIBOS kernel. For deployment guidance, see the Administrator Guide. For application programming, see the Application Developer Guide.*
