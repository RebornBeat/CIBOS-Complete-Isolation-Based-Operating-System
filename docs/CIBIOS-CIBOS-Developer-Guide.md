# CIBIOS/CIBOS Developer Guide
**Implementation Reference for Kernel and Firmware Developers**

## Introduction

This guide provides complete implementation details for developers working on the CIBIOS firmware and CIBOS kernel. It covers the exact mechanisms, algorithms, data structures, and interaction patterns that implement the Hybrid Isolation Paradigm at the system level.

This guide assumes familiarity with the HIP README, CIBIOS README, and CIBOS README. It provides the implementation-level detail that README documents appropriately omit.

---

## Chapter 1: Architecture Overview

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
│         └─► Competing for selection                               │
│             └─► Weighted entropy selection                        │
│                 ├─► Selected ──► EXECUTE                         │
│                 └─► Not selected ──► Stay in READY POOL          │
│                                                                  │
│  3. EXECUTING                                                     │
│     └─► Event runs on core                                        │
│         ├─► Completes successfully ──► DONE                       │
│         └─► Resource unavailable ──► Enter STALLED LIST          │
│                                                                  │
│  4. IN STALLED LIST                                               │
│     └─► Waiting for resource                                      │
│         └─► Resource becomes available                            │
│             └─► Kernel emits signal                               │
│                 └─► Move to READY POOL                            │
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
          Selected│                      │Resource Available
                  │                      │
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

## Chapter 2: Catch and Release Implementation

### Ready Pool Data Structure

```
READY POOL STRUCTURE:

┌─────────────────────────────────────────────────────────────┐
│                      READY POOL                             │
│                                                             │
│  Events: [Event₁, Event₂, Event₃, ..., Eventₙ]            │
│                                                             │
│  Each Event:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Lane ID: UUID                                       │   │
│  │ Container ID: UUID                                  │   │
│  │ Weight: u32                                         │   │
│  │ Entry Time: Instant                                 │   │
│  │ Accumulated Ready Time: Duration                    │   │
│  │ Event Payload: ExecutionEvent                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Total Weight: Σ(weightᵢ)                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

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

Select Event (Weighted Entropy):
  1. Generate random R in [0, total_weight)
  2. Walk events, accumulating weights
  3. Return event where accumulated > R
```

### Stalled List Data Structure

```
STALLED LIST STRUCTURE:

┌─────────────────────────────────────────────────────────────┐
│                      STALLED LIST                           │
│                                                             │
│  Entries: [Entry₁, Entry₂, Entry₃, ..., Entryₙ]            │
│                                                             │
│  Each Entry:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Container ID: UUID                                  │   │
│  │ Lane ID: UUID                                       │   │
│  │ Resource Needed: ResourceType                       │   │
│  │ Stall Time: Instant                                 │   │
│  │ Pending Event: ExecutionEvent                       │   │
│  │ Accumulated Ready Time: Duration (preserved)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Index by Resource Type (for efficient lookup):            │
│  Memory Waiters: [Container IDs]                            │
│  IO Waiters: [Container IDs]                                │
│  Channel Waiters: {Channel ID → [Container IDs]}            │
│                                                             │
└─────────────────────────────────────────────────────────────┘

OPERATIONS:

Stall Container:
  1. Create StalledEntry with preserved accumulated time
  2. Add to entries list
  3. Add to resource-type index

Release for Resource:
  1. Lookup entries waiting for resource
  2. Remove from entries list
  3. Remove from resource-type index
  4. Return entries for Ready Pool

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

### Resource Signal Processing

```
RESOURCE SIGNAL PROCESSING:

┌─────────────────────────────────────────────────────────────┐
│                   SIGNAL HANDLER                             │
│                                                             │
│  Memory Signal:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ MemoryFreed { container_id, amount }                │   │
│  │                                                     │   │
│  │ Process:                                            │   │
│  │ 1. If container_id: release ContainerMemory         │   │
│  │ 2. Else: release GlobalMemory                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  I/O Signal:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ IOComplete { container_id, operation_id }           │   │
│  │                                                     │   │
│  │ Process:                                            │   │
│  │ 1. Release DiskIO or NetworkIO                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Channel Signal:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ BufferAvailable { channel_id }                      │   │
│  │ DataAvailable { channel_id }                        │   │
│  │                                                     │   │
│  │ Process:                                            │   │
│  │ 1. Lookup waiters for this channel                  │   │
│  │ 2. Release to Ready Pool                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘

INTEGRATION WITH STATE MANAGER:

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

---

## Chapter 3: Weighted Entropy Algorithm

### Selection Algorithm

```
WEIGHTED ENTROPY SELECTION:

┌─────────────────────────────────────────────────────────────┐
│                   SELECTION ALGORITHM                        │
│                                                             │
│  INPUT: ReadyPool with N events                             │
│  OUTPUT: Selected event                                     │
│                                                             │
│  ALGORITHM:                                                 │
│                                                             │
│  1. if pool is empty: return None                          │
│                                                             │
│  2. total_weight = Σ weightᵢ for all events                │
│                                                             │
│  3. if total_weight == 0: return first event               │
│                                                             │
│  4. R = random_in_range(0, total_weight)                   │
│     // Cryptographic entropy source                         │
│                                                             │
│  5. accumulated = 0                                         │
│                                                             │
│  6. for each event in pool:                                │
│       accumulated += event.weight                           │
│       if R < accumulated:                                   │
│         return event                                        │
│                                                             │
│  7. return last event (fallback)                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘

COMPLEXITY: O(N) where N = number of ready events

OPTIMIZATION: For systems with many events, use prefix-sum tree
for O(log N) selection.
```

### With Anti-Starvation Priority

```
SELECTION WITH ANTI-STARVATION:

┌─────────────────────────────────────────────────────────────┐
│               ANTI-STARVATION SELECTION                      │
│                                                             │
│  INPUT: ReadyPool, threshold (Duration), now (Instant)      │
│  OUTPUT: Selected event                                     │
│                                                             │
│  ALGORITHM:                                                 │
│                                                             │
│  1. if pool is empty: return None                          │
│                                                             │
│  2. // Check for starving events                            │
│     starving = []                                           │
│     for each event in pool:                                │
│       total_wait = event.accumulated_ready_time +           │
│                    (now - event.entry_time)                 │
│       if total_wait > threshold:                            │
│         starving.append(event)                              │
│                                                             │
│  3. if starving is not empty:                              │
│       // Priority selection among starving                  │
│       // Still use entropy among starving events            │
│       R = random_in_range(0, len(starving))                │
│       selected = starving[R]                                │
│       pool.remove(selected.lane_id)                         │
│       return selected                                       │
│                                                             │
│  4. // Normal weighted entropy selection                    │
│     return weighted_entropy_select(pool)                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
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

## Chapter 4: Anti-Starvation Timer Semantics

### Timer Fields

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

### Timer Behavior Through Transitions

```
TIMER BEHAVIOR THROUGH STATE TRANSITIONS:

┌─────────────────────────────────────────────────────────────┐
│                    STATE TRANSITIONS                         │
│                                                             │
│  ENTER READY POOL:                                          │
│  ─────────────────                                          │
│  // From INACTIVE (new event)                                │
│  accumulated_ready_time = 0                                  │
│  entry_time = now()                                          │
│  is_in_ready_pool = true                                     │
│                                                             │
│  // From STALLED (resource available)                        │
│  // accumulated_ready_time preserved from stall              │
│  entry_time = now()                                          │
│  is_in_ready_pool = true                                     │
│                                                             │
│  EXIT READY POOL → EXECUTING:                               │
│  ─────────────────────────                                   │
│  // Timer stops accumulating                                │
│  // accumulated_ready_time NOT modified                     │
│  // Value preserved for potential future stall               │
│  is_in_ready_pool = false                                    │
│                                                             │
│  EXIT READY POOL → STALLED:                                 │
│  ─────────────────────────                                   │
│  // Add current stint to accumulated                         │
│  accumulated_ready_time += (now() - entry_time)             │
│  is_in_ready_pool = false                                    │
│  // Value preserved in StalledEntry                          │
│                                                             │
│  COMPLETE EXECUTION → NEW HEAD EVENT:                       │
│  ─────────────────────────                                   │
│  // New event becomes head                                   │
│  accumulated_ready_time = 0  // RESET for new event         │
│  entry_time = now()                                          │
│  is_in_ready_pool = true                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Current Wait Calculation

```
CALCULATING CURRENT TOTAL WAIT:

┌─────────────────────────────────────────────────────────────┐
│                 CURRENT WAIT CALCULATION                     │
│                                                             │
│  get_total_ready_wait(event, now):                          │
│    if event.is_in_ready_pool:                               │
│      current_stint = now - event.entry_time                 │
│      return event.accumulated_ready_time + current_stint    │
│    else:                                                    │
│      return event.accumulated_ready_time                    │
│                                                             │
│  // This correctly returns:                                 │
│  // - Only Ready Pool time                                  │
│  // - Does NOT include time spent stalled                   │
│  // - Accumulates across multiple Ready Pool visits         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
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

## Chapter 5: Multi-Core Single-Pool Routing

### Selector Thread Implementation

```
SELECTOR THREAD ARCHITECTURE:

┌─────────────────────────────────────────────────────────────┐
│                    SELECTOR THREAD                           │
│                                                             │
│  STATE:                                                     │
│  - ready_pool: ReadyPool                                    │
│  - stalled_list: StalledList                                │
│  - core_available: [bool; NUM_CORES]                        │
│  - core_executing: [Option<Uuid>; NUM_CORES]  // Container  │
│  - from_cores: Receiver<CoreMessage>                        │
│  - to_cores: [Sender<SelectorMessage>; NUM_CORES]           │
│  - entropy: KernelEntropy                                   │
│  - resource_signals: Receiver<ResourceSignal>               │
│                                                             │
│  MAIN LOOP:                                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ loop:                                               │   │
│  │   // Step 1: Process core messages                  │   │
│  │   while let Ok(msg) = from_cores.try_recv():       │   │
│  │     match msg:                                      │   │
│  │       ExecutionComplete { core_id, lane_id }:       │   │
│  │         core_available[core_id] = true              │   │
│  │         // Check if more work in lane               │   │
│  │         if has_next_event(lane_id):                 │   │
│  │           add_to_pool(get_next_event(lane_id))      │   │
│  │       ExecutionStalled { core_id, lane_id, res }:   │   │
│  │         core_available[core_id] = true              │   ��─┤
│  │         stalled_list.stall(lane_id, res)            │   │
│  │                                                     │   │
│  │   // Step 2: Process resource signals               │   │
│  │   while let Ok(signal) = resource_signals.try_recv():│   │
│  │     process_resource_signal(signal)                 │   │
│  │                                                     │   │
│  │   // Step 3: Process timer events                   │   │
│  │   for timer in get_fired_timers():                 │   │
│  │     ready_pool.add(timer_event(timer))              │   │
│  │                                                     │   │
│  │   // Step 4: Anti-starvation check                 │   │
│  │   check_anti_starvation()                           │   │
│  │                                                     │   │
│  │   // Step 5: Select and route                       │   │
│  │   if let Some(core_id) = find_available_core():    │   │
│  │     if let Some(event) = select_event():            │   │
│  │       route_event(event, core_id)                   │   │
│  │       core_available[core_id] = false               │   │
│  │                                                     │   │
│  │   // Step 6: Yield if nothing to do                │   │
│  │   if ready_pool.is_empty() && stalled_list.is_empty():│  │
│  │     yield()                                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
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

---

## Chapter 6: Configuration System

### Configuration File Format

```
CONFIGURATION FILE FORMAT:

┌─────────────────────────────────────────────────────────────┐
│                 /boot/cibos.conf                             │
│                                                             │
│  # CIBOS Boot Configuration                                 │
│  # This file must be signed with cibos-sign                 │
│                                                             │
│  [scheduling]                                               │
│  # Weight values (positive integers)                        │
│  system_weight = 3                                          │
│  user_weight = 1                                            │
│  background_weight = 1                                      │
│                                                             │
│  # Anti-starvation threshold (milliseconds)                 │
│  # Set to 0 to disable                                      │
│  anti_starvation_threshold_ms = 100                         │
│                                                             │
│  [resources]                                                │
│  # Per-container limits                                     │
│  memory_limit_mb = 512                                      │
│  io_bandwidth_mbps = 100                                    │
│                                                             │
│  [channels]                                                 │
│  max_channels_per_container = 16                            │
│  message_queue_size = 256                                   │
│                                                             │
│  [signature]                                                │
│  algorithm = "ed25519"                                      │
│  signature = "<base64-encoded-signature>"                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Loading

```
CONFIGURATION LOADING:

┌─────────────────────────────────────────────────────────────┐
│                 CONFIGURATION LOADER                         │
│                                                             │
│  load_config(path, pubkey): Result<Config, Error>           │
│                                                             │
│  1. Read config file                                        │
│  2. Read signature file                                     │
│  3. Verify signature with embedded public key               │
│     - If invalid: return Error, use compiled defaults       │
│     - If missing: use compiled defaults                     │
│  4. Parse configuration                                    │
│  5. Validate values:                                       │
│     - weights > 0                                           │
│     - threshold >= 0                                        │
│     - limits reasonable                                     │
│  6. Return validated config                                │
│                                                             │
│  COMPILED DEFAULTS:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Defaults by Profile:                                 │   │
│  │                                                     │   │
│  │ Maximum Isolation:                                  │   │
│  │   system_weight = 1                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation = disabled (not compiled)         │   │
│  │                                                     │   │
│  │ Balanced:                                            │   │
│  │   system_weight = 3                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation = 100ms                           │   │
│  │                                                     │   │
│  │ Performance:                                         │   │
│  │   system_weight = 5                                 │   │
│  │   user_weight = 2                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation = 50ms                            │   │
│  │                                                     │   │
│  │ Compute:                                             │   │
│  │   system_weight = 1                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation = optional                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Signature Verification

```
SIGNATURE VERIFICATION:

┌─────────────────────────────────────────────────────────────┐
│                 SIGNATURE VERIFICATION                       │
│                                                             │
│  verify_config(data, signature, pubkey): Result<(), Error>  │
│                                                             │
│  1. Parse signature as Ed25519 Signature                   │
│  2. Verify data with pubkey                                │
│  3. Return Ok if valid, Error if invalid                  │
│                                                             │
│  KEY MANAGEMENT:                                            │
│  - Public key embedded in CIBIOS at build time             │
│  - Private key managed externally                          │
│  - Sign config with: cibos-sign --key priv.pem config      │
│  - Verify with: cibos-verify --key pub.pem config sig      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 7: Resource Signals

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

## Chapter 8: No-Global-Locks Verification

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
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 9: Profile Build Configuration

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
│                                                             │
│  PERFORMANCE:                                               │
│  features = [                                               │
│    "anti-starvation",                                       │
│    "full-fairness",                                         │
│    "cryptographic-entropy",                                 │
│    "cli-interface",                                         │
│    "handoff-cryptographic",                                 │
│  ]                                                          │
│                                                             │
│  COMPUTE:                                                   │
│  features = [                                               │
│    "per-lane-weights",                                      │
│    "lightweight-handshake",                                 │
│    "cli-interface",                                         │
│    "handoff-lightweight",                                   │
│    # anti-starvation = optional                             │
│    # cryptographic-entropy = compiled                       │
│  ]                                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 10: CIBIOS Implementation Notes

### no_std Requirements

```
NO_STD REQUIREMENTS:

┌─────────────────────────────────────────────────────────────┐
│                   CIBIOS CONSTRAINTS                         │
│                                                             │
│  NO STANDARD LIBRARY:                                       │
│  - No std::collections (use heapless or custom)             │
│  - No std::sync (no Mutex, RwLock, etc.)                    │
│  - No std::thread (no OS threads)                           │
│  - No std::net (no OS networking)                           │
│  - No std::fs (no OS filesystem)                            │
│  - No std::time (implement hardware timers)                 │
│  - No std::io (implement serial output)                     │
│                                                             │
│  NO ALLOCATOR BY DEFAULT:                                   │
│  - Implement bump allocator                                │
│  - Never frees (acceptable for firmware)                    │
│  - Reset at CIBOS handoff                                  │
│                                                             │
│  NO PANIC HANDLER BY DEFAULT:                               │
│  - Implement custom panic handler                          │
│  - Write to serial, halt                                   │
│                                                             │
│  NO RNG BY DEFAULT:                                         │
│  - Implement hardware RNG                                  │
│  - RDRAND (x86_64), RNDR (ARM64), SEED (RISC-V)            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Handoff Protocol

```
HANDOFF PROTOCOL:

┌─────────────────────────────────────────────────────────────┐
│                   HANDOFF PROTOCOL                           │
│                                                             │
│  CRYPTOGRAPHIC HANDOFF (Standard Profile):                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. CIBIOS loads CIBOS kernel image                  │   │
│  │ 2. CIBIOS computes SHA-256 hash of image           │   │
│  │ 3. CIBIOS verifies Ed25519 signature               │   │
│  │ 4. If verification fails: halt with error          │   │
│  │ 5. CIBIOS prepares HandoffData structure           │   │
│  │ 6. CIBIOS writes HandoffData to known address      │   │
│  │ 7. CIBIOS transfers control to CIBOS entry point   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  LIGHTWEIGHT HANDOFF (Lightweight Profile):                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. CIBIOS loads CIBOS kernel image                  │   │
│  │ 2. CIBIOS prepares HandoffData structure           │   │
│  │ 3. CIBIOS writes HandoffData to known address      │   │
│  │ 4. CIBIOS transfers control to CIBOS entry point   │   │
│  │    (No signature verification)                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  HANDOFF DATA STRUCTURE:                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ struct HandoffData {                                │   │
│  │   version: u32,                                      │   │
│  │   hardware_config: HardwareConfig,                   │   │
│  │   memory_layout: MemoryLayout,                       │   │
│  │   isolation_boundaries: IsolationBoundaries,        │   │
│  │   config_ptr: *const Config,                        │   │
│  │ }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

*End of Developer Guide*
