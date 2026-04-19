# CIBOS: Complete Isolation-Based Operating System
**Quantum-Like First, Security Optional**

## The Democratic Computation Revolution

The Complete Isolation-Based Operating System (CIBOS) provides quantum-like computational properties and strong privacy guarantees across all hardware platforms. CIBOS is designed with a clear hierarchy: quantum-like computational capabilities are the foundation; security features are an optional layer built on top.

This design philosophy enables deployment across a wide range of contexts. Compute deployments (air-gapped, single-user) gain maximum throughput with minimal overhead. Security-critical deployments (multi-user, networked) add security features appropriate to their threat model. All deployments share the same quantum-like computational foundation.

The foundational insight: proper isolation architecture simultaneously eliminates coordination overhead (enabling quantum-like properties) and prevents cascade failures (enabling security). These are not in tension — they are both consequences of the same architectural principle: eliminating global locks and shared state.

---

## Architecture Foundation: No Global Locks

The core architectural innovation in CIBOS is the complete elimination of global locks and shared-state coordination. This is not mitigation. It is elimination.

**No global locks anywhere in the system.** No component waits on another component's lock. Contention does not exist because there is nothing to contend over.

**No shared state between containers.** Containers cannot observe each other's state. No shared memory regions between containers.

**No observable retry behavior.** When resources are unavailable, requesting containers stall without spinning, polling, or retrying. There is nothing for an observer to measure.

---

## The Two-Layer Execution Model

### Layer 1: Catch and Release — Determines What CAN Run

**Purpose:** Determine which events have all required resources and are eligible to execute.

**Process:**
1. Monitor resource availability
2. When any resource availability changes: find containers in Stalled List waiting for this resource; for each, verify ALL required resources are now available; move only fully-qualified containers to Ready Pool
3. Ready Pool = Events that CAN execute now

This layer has no concept of how many will run simultaneously. It only determines eligibility.

### Layer 2: Dispatch — Determines What RUNS NOW

**Purpose:** Determine which eligible events actually execute.

When N ≤ C (no competition): All N events dispatch simultaneously. Weighted entropy is NOT used. Zero selection overhead.

When N > C (competition exists): Weighted entropy selects which C events are dispatched. Remaining N-C events stay in Ready Pool (not stalled).

Dispatch is triggered by resource availability changes and execution context availability, not by fixed time intervals.

### Container States

```
CATCH AND RELEASE STATE MACHINE:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  ┌───────────┐                                                              │
│  │ INACTIVE  │ No work pending                                             │
│  │           │◄─────────────────────────────────────┐                      │
│  └─────┬─────┘                                      │                      │
│        │                                            │                      │
│        │ Work created                               │                      │
│        │                                            │                      │
│        ▼                                            │                      │
│  All resources?                                     │                      │
│        │                                            │                      │
│  ┌─────┴─────┐                                      │                      │
│  │           │                                      │                      │
│ Yes         No                                      │                      │
│  │           │                                      │                      │
│  ▼           ▼                                      │                      │
│  ┌───────────┐  ┌───────────┐                       │                      │
│  │   READY   │  │  STALLED  │                       │                      │
│  │   POOL    │  │   LIST    │                       │                      │
│  │(Eligible) │  │(Waiting)  │                       │                      │
│  └─────┬─────┘  └─────┬─────┘                       │                      │
│        │              │                             │                      │
│  Dispatched      Resource                           │                      │
│        │         available                          │                      │
│        │         (ALL required)                     │                      │
│        │              │                             │                      │
│        ▼              ▼                             │                      │
│  ┌───────────┐   Move to Ready                      │                      │
│  │ EXECUTING │◄──Pool if all                        │                      │
│  │           │   qualify                            │                      │
│  └─────┬─────┘                                      │                      │
│        │                                            │                      │
│   ┌────┴────┐                                       │                      │
│   │         │                                       │                      │
│ Completes  Needs                                    │                      │
│   │        resource                                 │                      │
│   │        during exec                              │                      │
│   │         │                                       │                      │
│   │         ▼                                       │                      │
│   │  ┌───────────┐                                  │                      │
│   │  │  STALLED  │                                  │                      │
│   │  │   LIST    │                                  │                      │
│   │  └───────────┘                                  │                      │
│   │                                                 │                      │
│   ├── More work ──► READY POOL                      │                      │
│   │                                                 │                      │
│   └── No more work ─────────────────────────────────┘                      │
│                     → INACTIVE                                             │
│                                                                             │
│  KEY: All arrows are event-driven. No polling. No retry loops.              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quantum-Like Properties in CIBOS

CIBOS delivers all four HIP quantum-like properties. These are the zero-overhead architectural foundation:

```
QUANTUM-LIKE PROPERTIES — ZERO OVERHEAD FOUNDATION:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Property P (Parallel Pathways):                                            │
│    Traditional OS: 500-5000 cycles per parallel unit (locks)                │
│    CIBOS:          0 cycles (no locks — lanes ARE the design)               │
│                                                                             │
│  Property I (Interference-Free):                                            │
│    Traditional OS: 30-70% of cycles on coordination                        │
│    CIBOS:          ~0% (message passing only, no shared state)             │
│                                                                             │
│  Property N (Non-Deterministic):                                            │
│    CIBOS:          ~10-20 cycles per selection (DEFAULT = LOWEST OVERHEAD)  │
│                                                                             │
│  Property A (Application Control):                                          │
│    Traditional OS: Not built-in                                             │
│    CIBOS:          0 cycles (architecture preserves all results)            │
│                                                                             │
│  ════════════════════════════════════════════════════════════════════════   │
│                                                                             │
│  SECURITY FEATURES ADD OVERHEAD ON TOP OF THIS FOUNDATION:                  │
│  Anti-starvation: +5-10 cyc/event  │  RTRO: +2-5% throughput              │
│  Full-fairness:   +200-400 cyc/evt │  Crypto IPC: +5-10% IPC              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

Non-determinism is the default lowest-overhead state. Security features add overhead. For Compute, maximum quantum-like with minimum overhead is the goal. For Maximum Isolation, security overhead is worth the protection.

---

## Async/Await and the Lane Model

Lane work is submitted as async blocks. Each `.await` point is a potential stall point in the Catch and Release mechanism. This maps directly and correctly to HIP's event model.

```
ASYNC/AWAIT TO HIP EVENT MAPPING:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  lane.submit(async {                                                        │
│                                                                             │
│      let data = channel.receive().await;                                    │
│      //                            ▲                                        │
│      //                    Potential stall point                            │
│      //                                                                     │
│      //  If channel empty:                                                  │
│      //    → Poll::Pending returned                                         │
│      //    → Kernel tracks dependency (ChannelData resource)                │
│      //    → Event moves to Stalled List                                    │
│      //    → NO polling, NO retry, NO spin-wait                             │
│      //    → When data arrives: resource signal emitted                     │
│      //    → Kernel qualifies ALL resources for this event                  │
│      //    → Event moves to Ready Pool                                      │
│      //    → Dispatched → waker fires → Future polls again                  │
│      //    → Poll::Ready(data) returned                                     │
│      //    → Execution resumes here                                         │
│                                                                             │
│      process(data);                                                         │
│                                                                             │
│      Timer::sleep(Duration::from_millis(100)).await;                        │
│      //   Kernel timer event — no thread sleeping                           │
│                                                                             │
│      send_result(result).await;                                             │
│      //   If buffer full → stalls until space available                     │
│  });                                                                        │
│                                                                             │
│  KEY MAPPING:                                                               │
│  async block = ExecutionEvent                                               │
│  .await      = Potential stall point (resource check)                       │
│  Poll::Ready = Resource available, continue                                 │
│  Poll::Pending = Resource unavailable, kernel tracks, event stalls          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Critical:** CIBOS uses its own async runtime, not Tokio or async-std. Standard runtimes use global task queues with locks — incompatible with HIP. CIBOS's async runtime delegates waiting to the kernel's Catch and Release. See the CIBOS Async Runtime Guide for implementation details.

---

## Weighted Entropy Scheduling

Weighted entropy selection is for CONFLICT RESOLUTION, not for all dispatch.

**When no competition:** All ready events dispatch simultaneously. No selection needed. Zero overhead.
**When competition exists:** Weighted entropy selects which events dispatch.

```
WEIGHTED ENTROPY SELECTION EXAMPLE:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  SELECT 2 FROM 5 EVENTS (competition exists: 5 ready, 2 contexts):         │
│                                                                             │
│  Ready Pool:                                                                │
│  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐                    │
│  │   A   │  │   B   │  │   C   │  │   D   │  │   E   │                    │
│  │ w = 3 │  │ w = 1 │  │ w = 1 │  │ w = 1 │  │ w = 1 │                    │
│  └───────┘  └───────┘  └───────┘  └───────┘  └───────┘                    │
│                                                                             │
│  Total weight: 7                                                             │
│                                                                             │
│  First selection: R = random(0,7) = 4                                       │
│    Walk: A(3)→accumulated=3, 4>3 continue                                   │
│          B(1)→accumulated=4, 4≤4 → SELECT B                                 │
│                                                                             │
│  Remaining: A, C, D, E (weight=6)                                           │
│  Second selection: R = random(0,6) = 2                                      │
│    Walk: A(3)→accumulated=3, 2<3 → SELECT A                                 │
│                                                                             │
│  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐                    │
│  │ SELCT │  │ SELCT │  │   C   │  │   D   │  │   E   │                    │
│  │   A   │  │   B   │  │ stays │  │ stays │  │ stays │                    │
│  └───────┘  └───────┘  └───────┘  └───────┘  └───────┘                    │
│                                                                             │
│  C, D, E remain in Ready Pool — NOT stalled, still eligible                 │
│                                                                             │
│  Higher weight = more tickets = higher probability (not certainty)          │
│  Selection is probabilistic, entropy-based, not deterministic               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

Weight classes by default: System class (window managers, input handlers, compositors), User class (standard applications), Background class (non-critical processes).

Weight values per profile:

| Profile | System | User | Background |
|---|---|---|---|
| Maximum Isolation | 1 | 1 | 1 |
| Balanced | 3 | 1 | 1 |
| Performance | 5 | 2 | 1 |
| Compute | 1 | 1 | 1 (or per-lane) |

Weights are boot-time configuration. They do not change during operation in standard configurations. Dynamic weights (Compute profile only) allow runtime modification via message to selector — no locks required, selector owns all weight data exclusively.

---

## Anti-Starvation (Optional)

Anti-starvation ensures no lane waits indefinitely in the Ready Pool without being dispatched. It tracks time each head event spends in the Ready Pool (not time stalled — only Ready Pool time counts).

```
ANTI-STARVATION TIMER BEHAVIOR:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  WHAT IS TRACKED:                                                           │
│  accumulated_ready_time: Total time in Ready Pool across ALL visits         │
│  entry_time: When event entered Ready Pool (current visit)                  │
│  is_in_ready_pool: Currently in Ready Pool?                                 │
│                                                                             │
│  STATE TRANSITIONS:                                                         │
│  Event enters Ready Pool:                                                   │
│    accumulated = preserved from before (or 0 if new)                        │
│    entry_time = now()                                                       │
│                                                                             │
│  Event dispatched:                                                          │
│    accumulated NOT updated (preserved for potential stall)                  │
│                                                                             │
│  Event stalls during execution:                                             │
│    accumulated += (now() - entry_time)  ← add current visit                │
│    Value preserved in StalledEntry                                          │
│                                                                             │
│  Event returns from Stalled to Ready:                                       │
│    accumulated carried forward from StalledEntry                            │
│    entry_time = now()  ← new visit begins                                  │
│                                                                             │
│  Event completes, new head event forms:                                     │
│    new event: accumulated = 0  ← RESET for new event                       │
│    entry_time = now()                                                       │
│                                                                             │
│  Current wait = accumulated + (now() - entry_time)  if in Ready Pool       │
│               = accumulated                           if stalled            │
│                                                                             │
│  ONLY Ready Pool time counts. Stalled time does NOT count.                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why absent from Maximum Isolation:** Anti-starvation introduces a deadline-based behavioral pattern. When a lane exceeds the threshold, dispatch becomes predictable — information leakage in adversarial environments.

Default threshold: 100ms (configurable via signed boot configuration).

---

## Full Fairness (Optional)

Full fairness tracking ensures proportional execution time across all lanes. Overhead: ~200-400 cycles per event. Compiled only into Performance profile.

---

## Multi-Core Execution: Single Pool with Routing

### Architecture

CIBOS implements multi-core execution through a single Ready Pool managed by a dedicated kernel selector.

**Single Ready Pool:** One pool for the entire system. Selector owns it exclusively — no locks needed.

**Kernel Selector:** One entity. Processes resource signals, updates pool, assesses competition, applies weighted entropy only when needed, routes events potentially multiple simultaneously.

**No Global Locks:** Selector owns pool exclusively. Contexts communicate via SPSC message queues. No shared mutable state between contexts.

**A Single Selector Is Correct for All Scales:** Work per dispatch opportunity is bounded. Multiple selectors would require lock-like coordination — never appropriate.

### Execution Capacity

Total simultaneous executions = Physical Cores × SMT Factor

| Configuration | Simultaneous Events |
|---|---|
| 4 cores, no SMT | 4 |
| 4 cores, 2-way SMT | 8 |
| 8 cores, 2-way SMT | 16 |
| 8 cores, 4-way SMT | 32 |

### Cache-Aware Routing

When multiple execution contexts are available, the selector routes based on cache affinity. No shared state between contexts required.

### Class Core Affinity (Optional)

When `class-core-affinity` is enabled, execution contexts are partitioned by weight class. Static configuration read by selector — no locks, single owner, O(1) routing.

---

## Channel Communication

### What Channels Are

A channel is a point-to-point communication link between exactly two containers. Created by mutual agreement, bound to specific container identifiers, isolated from all other channels, subject to rate limits and terms established at creation time. Not broadcast. Not discoverable.

### Channel Security Model (Profile-Dependent)

**Cryptographic Mode** (`cryptographic-ipc` compiled in): Every message is signed by the sender and verified by the receiver. Transparent to application code — CIBOS API handles signing/verification.

**Lightweight Handshake Mode** (`lightweight-handshake` compiled in): Channel identity verified once at creation. Messages flow without per-message crypto. Isolation boundaries prevent injection. Physical security provides outer protection.

Application code is identical for both modes.

### Channel Establishment

Terms are proposed by the requester. The receiver accepts all or rejects. No counter-proposal — if different terms needed, requester sends a new request. This prevents negotiation overhead and timing leakage from negotiation patterns.

---

## RTRO: Real-Time Resource Obfuscation

RTRO is a kernel-integrated behavioral obfuscation layer that operates alongside execution in profiles where adversarial observation is a concern. It intercepts and transforms externally visible system signals without modifying actual execution.

RTRO randomizes reported CPU usage per container, memory usage reports, and event sequencing visibility in system interfaces. It does not introduce artificial delays or modify actual execution timing.

**Present in:** Maximum Isolation (always), Balanced (optional build flag).
**Absent from:** Performance and Compute — no adversarial observer in those threat models.

---

## Complete Feature Flag Reference

### Core Architectural (Always Present — Not Feature Flags)

These ARE the architecture. Cannot be disabled:
- `isolation-boundaries` — Enables P, I, A
- `channels` — Enables I, A
- `catch-and-release` — Enables I
- `weighted-entropy` — Enables N

### Scheduling Mechanisms

| Flag | What It Enables | Overhead | Profiles |
|---|---|---|---|
| `anti-starvation` | Ready Pool wait tracking, priority dispatch at threshold | ~5-10 cycles/event | Balanced, Performance, Compute (optional) |
| `full-fairness` | Proportional execution time guarantee | ~200-400 cycles/event | Performance only |
| `per-lane-weights` | Application assigns weights at lane creation | ~5-10 cycles/dispatch | Compute only |
| `dynamic-weights` | Runtime weight modification via message | ~45-110 cycles/change; zero/dispatch | Compute only; requires per-lane-weights |

**dynamic-weights implementation note:** No locks required — selector owns all weight data exclusively. Container sends message; selector updates weight in Ready Pool entry; container does not wait. Overhead: ~45-110 cycles per change, zero per dispatch. Acceptable for Compute (no adversary). NOT appropriate for Maximum Isolation (observable timing patterns).

### Optional Performance Features

| Flag | What It Enables | Overhead | Profiles |
|---|---|---|---|
| `signal-coalescence` | Batch process resource signals | ~125 cyc/signal (vs ~400 without); +30-50% throughput | All |
| `signal-coalescence-threshold` | Backstop ensures signals don't wait too long | ~16 bytes for timestamp | All |
| `class-resource-pools` | Separate memory pools per weight class | ~64 bytes per class | All (optional) |
| `class-core-affinity` | Route events to contexts by weight class | ~16 bytes for mapping | All (optional) |

**Shared timing infrastructure:** When `anti-starvation` and `signal-coalescence-threshold` are both compiled in, they automatically share timing source and threshold logic — single timing subsystem, no additional overhead for the second feature. When `anti-starvation` and `full-fairness` are both compiled in, they share execution time tracking.

```
SIGNAL COALESCENCE TIMING:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  WITHOUT COALESCENCE:                                                       │
│  Signal 1 ──► Process ──► ~400 cycles                                      │
│  Signal 2 ──► Process ──► ~400 cycles                                      │
│  Signal 3 ──► Process ──► ~400 cycles                                      │
│  Signal 4 ──► Process ──► ~400 cycles                                      │
│  Total: ~1600 cycles                                                        │
│                                                                             │
│  WITH COALESCENCE (opportunistic):                                          │
│  Signal 1 ──┐                                                               │
│  Signal 2 ──┼──► Batch process ──► ~500 cycles total                       │
│  Signal 3 ──┤   (all 4 signals)   = ~125 cycles per signal                 │
│  Signal 4 ──┘                                                               │
│                                                                             │
│  WITH THRESHOLD BACKSTOP:                                                   │
│  t=0ms: Signal 1 arrives → buffer                                           │
│  t=2ms: Signal 2 arrives → buffer                                           │
│  t=4ms: Signal 3 arrives → buffer                                           │
│  t=5ms: BACKSTOP exceeded → process immediately (even without Signal 4)     │
│                                                                             │
│  THRESHOLD IS A SIGNAL PROCESSING DEADLINE — NOT A DISPATCH DEADLINE        │
│  Affects WHEN signals are processed                                         │
│  Does NOT affect WHICH events are dispatched or HOW MANY                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Mechanisms

| Flag | What It Enables | Overhead | Profiles |
|---|---|---|---|
| `rtro` | Behavioral obfuscation at system interfaces | ~2-5% throughput | Maximum Isolation (required), Balanced (optional) |
| `cryptographic-ipc` | Per-message signing and verification | ~5-10% IPC | Maximum Isolation, Balanced |
| `lightweight-handshake` | Channel-establishment-only authentication | Minimal | Compute only |
| `user-authentication` | Identity verification infrastructure | Variable | Maximum Isolation, Balanced |
| `multi-user-isolation` | User-level isolation between users | Variable | Maximum Isolation |
| `audit-logging` | Cryptographic event logging | Variable | Maximum Isolation |
| `cryptographic-entropy` | CSPRNG quality entropy for dispatch | Minimal | All |
| `hardware-rng` | Hardware random number generator | Minimal | All |

### Handoff Mechanisms (Shared with CIBIOS, Mutually Exclusive)

| Flag | What It Enables |
|---|---|
| `handoff-cryptographic` | Cryptographic CIBIOS-to-CIBOS handoff; required for security features |
| `handoff-lightweight` | Lightweight CIBIOS-to-CIBOS handoff; enables per-lane-weights, dynamic-weights |

### Capability Features (All Mutually Compatible, Neutral Impact on P/I/N/A)

| Flag | What It Enables | Exception |
|---|---|---|
| `network-stack` | TCP/IP networking | — |
| `usb-stack` | USB device support | — |
| `gui-subsystem` | Graphics and window management | — |
| `cli-interface` | Text-based command line | — |
| `audio-subsystem` | Sound input and output | — |
| `dynamic-lanes` | Runtime lane creation on demand | Improves P (adaptive parallelism) |
| `touch-subsystem` | Touch input with isolation | — |
| `sensor-subsystem` | All sensors with per-sensor isolation | — |
| `mobile-connectivity` | Cellular, Bluetooth, NFC | — |
| `power-management` | Battery and power state management | — |
| `display-subsystem` | Display control with isolation | — |

---

## Feature Flag Interaction Matrix

### Key Incompatibilities

| Feature | Incompatible With | Reason |
|---|---|---|
| `full-fairness` | `per-lane-weights` | Different fairness models |
| `full-fairness` | `dynamic-weights` | Different fairness models |
| `cryptographic-ipc` | `lightweight-handshake` | Mutually exclusive IPC modes |
| `rtro` | `lightweight-handshake` | RTRO requires cryptographic handoff |
| `multi-user-isolation` | `lightweight-handshake` | Requires cryptographic IPC |
| `audit-logging` | `lightweight-handshake` | Requires cryptographic IPC |
| `handoff-cryptographic` | `handoff-lightweight` | Mutually exclusive |

### Key Dependencies

| Feature | Requires |
|---|---|
| `rtro` | `cryptographic-entropy`, `handoff-cryptographic` |
| `cryptographic-ipc` | `cryptographic-entropy`, `handoff-cryptographic` |
| `multi-user-isolation` | `user-authentication`, `cryptographic-ipc` |
| `audit-logging` | `cryptographic-ipc` |
| `user-authentication` | `cryptographic-ipc` |
| `dynamic-weights` | `per-lane-weights` |

### Shared Infrastructure Opportunities

When both `anti-starvation` and `signal-coalescence-threshold` are compiled in: they share timing source and threshold check logic automatically.

When both `anti-starvation` and `full-fairness` are compiled in: they share execution time tracking.

When all three are compiled in: unified timing subsystem serves all three features with minimal additional overhead.

---

## Operational Profiles

### Maximum Isolation

**Threat model:** Adversarial observers exist. Timing attacks are a realistic threat. Maximum observation resistance required.

**Scheduling:** All weights equal (1:1:1). Anti-starvation NOT compiled. Full fairness NOT compiled. Maximum non-determinism — equal probability for all events when competition exists.

**Why equal weights are required:** Unequal weights create observable behavioral patterns. Maximum Isolation requires pure entropy selection. This is a SECURITY REQUIREMENT.

**Security mechanisms:** RTRO compiled. Cryptographic IPC compiled. User authentication compiled. Multi-user isolation compiled. Audit logging compiled.

**SMT:** Disabled. (Hardware side-channel elimination.)

**Required flags:** `handoff-cryptographic`, `cryptographic-entropy`, `hardware-rng`, `rtro`, `cryptographic-ipc`, `user-authentication`, `multi-user-isolation`, `audit-logging`, `cli-interface`

**Optional flags:** `signal-coalescence`, `signal-coalescence-threshold`, `class-resource-pools`, `class-core-affinity`, `network-stack`, `gui-subsystem`, `dynamic-lanes`

**Prohibited flags:** `anti-starvation`, `full-fairness`, `per-lane-weights`, `dynamic-weights`, `lightweight-handshake`, `hardware-vendor-*`

**Quantum-Like Properties:** P = moderate (SMT disabled), I = high, N = maximum (pure entropy + RTRO obfuscates external observation), A = high

**QTM Score:** ~75,000

### Balanced

**Threat model:** Network connectivity exists. Single or small number of trusted users.

**Scheduling:** System weight 3, user weight 1, background weight 1. Anti-starvation compiled (100ms default).

**Security mechanisms:** Cryptographic IPC compiled. User authentication compiled. RTRO optional.

**SMT:** Disabled by default; user may enable.

**Required flags:** `handoff-cryptographic`, `cryptographic-entropy`, `hardware-rng`, `cryptographic-ipc`, `user-authentication`, `cli-interface`

**Optional flags:** `anti-starvation`, `rtro`, `signal-coalescence`, `signal-coalescence-threshold`, `class-resource-pools`, `class-core-affinity`, `network-stack`, `gui-subsystem`, `dynamic-lanes`

**Prohibited flags:** `full-fairness`, `per-lane-weights`, `dynamic-weights`, `lightweight-handshake`, `multi-user-isolation`, `audit-logging`, `hardware-vendor-*`

**Quantum-Like Properties:** P = high, I = high, N = high-moderate (anti-starvation slightly reduces), A = high

**QTM Score:** ~85,000

### Performance

**Threat model:** Single trusted user. Physical security provides primary protection. Responsiveness is priority.

**Scheduling:** System weight 5, user weight 2, background weight 1. Anti-starvation compiled (50ms default). Full fairness compiled.

**Security mechanisms:** RTRO NOT compiled. Cryptographic IPC optional. No multi-user.

**SMT:** Enabled. (Maximize throughput on limited hardware.)

**Required flags:** `handoff-cryptographic`, `cryptographic-entropy`, `cli-interface`

**Optional flags:** `anti-starvation`, `full-fairness`, `signal-coalescence`, `signal-coalescence-threshold`, `class-resource-pools`, `class-core-affinity`, `network-stack`, `gui-subsystem`, `dynamic-lanes`, `hardware-vendor-*` (with documented implications)

**Prohibited flags:** `rtro`, `multi-user-isolation`, `audit-logging`, `per-lane-weights`, `dynamic-weights`, `lightweight-handshake`

**Quantum-Like Properties:** P = high (SMT enabled), I = high, N = moderate (fairness creates predictability), A = high

**QTM Score:** ~50,000

### Compute

**Threat model:** Single trusted user. Air-gapped. Physically secured. No adversarial observer.

**Scheduling:** All weights equal by default. Per-lane-weights available (application assigns at creation). Dynamic weights available (runtime modification via message). Anti-starvation optional.

**Compute-specific features:**
- `per-lane-weights`: Application assigns lane weights at creation time
- `dynamic-weights`: Runtime weight modification — no locks (selector owns all weights exclusively); ~45-110 cycles per change, zero per dispatch; acceptable because no adversary exists to exploit predictability
- `lightweight-handshake`: Minimal IPC overhead, no per-message crypto

**Security mechanisms:** No RTRO. Lightweight handshake IPC. No user authentication. No multi-user.

**SMT:** Enabled. (Maximum parallel computation.)

**Required flags:** `handoff-lightweight`, `cryptographic-entropy`, `cli-interface`

**Optional flags:** `anti-starvation`, `per-lane-weights`, `dynamic-weights`, `lightweight-handshake`, `signal-coalescence`, `signal-coalescence-threshold`, `class-resource-pools`, `class-core-affinity`, `dynamic-lanes`

**Prohibited flags:** `rtro`, `cryptographic-ipc`, `user-authentication`, `multi-user-isolation`, `audit-logging`, `full-fairness`, `handoff-cryptographic`, `network-stack`, `hardware-vendor-*`

**Quantum-Like Properties:** P = maximum (SMT enabled, unlimited lanes, dynamic-lanes optional), I = maximum (no coordination overhead, lightweight IPC), N = maximum (default — pure entropy; application can influence with per-lane/dynamic-weights without security concern), A = maximum (per-lane weights + dynamic control)

**QTM Score:** ~100,000+

---

## Platform Variants

Platform variants are convenience presets describing capability sets. They compose with operational profiles.

### CIBOS-CLI: Command Line Interface

Required: `cli-interface`
Optional: `network-stack`, `usb-stack`, `audio-subsystem`
All profiles: Supported

### CIBOS-GUI: Desktop Computing

Required: `gui-subsystem`, `display-subsystem`, `cli-interface`
Optional: `network-stack`, `usb-stack`, `audio-subsystem`, `touch-subsystem`
All profiles: Supported

### CIBOS-MOBILE: Smartphone and Tablet

Required: `touch-subsystem`, `sensor-subsystem`, `display-subsystem`, `power-management`, `cli-interface`
Optional: `mobile-connectivity`, `network-stack`, `audio-subsystem`, `gui-subsystem`
Recommended profiles: Maximum Isolation, Balanced

**Sensor Isolation in CIBOS-MOBILE:** Each sensor is an isolated resource requiring per-access authorization. Camera, microphone, GPS, accelerometer, and all other sensors provide data only to the requesting container. System indicators show when sensors are active. Authorization can be revoked at any time.

**Power Management:** Battery state tracking, power state transitions, and per-container power budgets managed by the kernel. Background containers throttled when battery is low.

---

## Application-Level Time

Time is available to applications as one event source among many. Applications request timer events and receive them when the duration expires.

**The kernel does NOT use time to make coordination decisions** in Maximum Isolation or Balanced profiles — no fixed time-slice preemption, no time-based backoff, no timer-driven arbitration among events. Time generates events; dispatch decides which events run.

**For Performance and Compute profiles:** Timer → Selector → Events is a pipeline (triggering, not coordination). Timer does not wait for selector; selector does not wait for timer. No coordination occurs. Time-based triggering is fully acceptable for profiles where temporal isolation is not a security requirement.

---

## What CIBIOS Establishes, What CIBOS Builds

CIBOS does not set up its own isolation boundaries. CIBIOS establishes them at hardware level before CIBOS begins executing. CIBOS inherits: memory isolation boundaries already enforced by hardware, lane memory regions already reserved and isolated, SMT configuration already established, hardware configuration record already written.

CIBOS builds on this foundation: the weighted entropy scheduler, container management, channel infrastructure, the CIBOS async runtime, security infrastructure, and user interface subsystems appropriate to the built profile.

---

## Development Roadmap

**Phase 1 (Months 1-12):** Core microkernel and isolation implementation. Weighted entropy dispatcher with Catch and Release. Lane creation and management. CIBOS async runtime. All four operational profiles implemented and validated.

**Phase 2 (Months 10-20):** Isolated system services. CIBOS-CLI, CIBOS-GUI, and CIBOS-MOBILE development.

**Phase 3 (Months 18-28):** Native application development framework. System-wide performance optimization.

**Phase 4 (Months 26-36):** Comprehensive security testing. Independent security analysis. Production deployment preparation.

---

**Project Repository:** github.com/cibos/complete-isolation-os
**Profiles:** Maximum Isolation, Balanced, Performance, Compute
**Platform Variants:** CIBOS-CLI, CIBOS-GUI, CIBOS-MOBILE
**Supported Architectures:** ARM, x64, x86, RISC-V
**License:** Privacy-focused open source with strong copyleft protections
