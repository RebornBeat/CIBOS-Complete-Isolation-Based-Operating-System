# ARCHITECTURE DECISION RECORDS

**CIBIOS/CIBOS/HIP — Why Each Decision Was Made**
**Version:** 1.0.0
**Audience:** Future contributors, researchers, curious developers

---

## Format

Each ADR follows this structure:
- **Context:** The problem or situation requiring a decision
- **Decision:** What was decided
- **Consequences:** What becomes easier or harder
- **Alternatives Considered:** What else was evaluated and why it was rejected

---

## ADR-001: No Global Locks

**Date:** Initial architecture
**Status:** Accepted (inviolable)

### Context

Operating systems traditionally use locks (mutexes, spinlocks, semaphores) to protect shared data structures. The scheduler's ready queue, the memory allocator, the IPC message queues — all are typically protected by global locks.

The performance cost of global locks is well-documented:
- Lock contention causes serialization of parallel work
- Spinlocks waste CPU cycles
- Priority inversion can cause high-priority threads to wait on low-priority lock holders
- Global locks create a scalability ceiling as core counts increase

More importantly for HIP: global locks **fundamentally destroy the I (Interference-Free) property**. If two containers coordinate through a shared lock, they are not interference-free. The lock is the interference.

### Decision

No global locks. Ever. The kernel, firmware, and runtime may not contain any mutex, rwlock, semaphore, or similar synchronization primitive that can be held by more than one container simultaneously.

All coordination is through:
1. **Single ownership**: Each data structure has exactly one owner. No sharing.
2. **Message passing**: Cross-boundary coordination through the kernel channel system.
3. **Atomic operations**: For hardware-level single-value coordination only.

### Consequences

**Positive:**
- HIP property I (Interference-Free) is mechanically guaranteed
- No lock contention at any scale
- No deadlock possibility in kernel code
- Linear scalability with core count (no serialization point)
- No priority inversion

**Negative:**
- Some algorithms that naturally use locks must be redesigned
- Contributor learning curve: "how do I do X without a lock?" (answer: message passing)
- The no-lock verifier must run on every PR

### Alternatives Considered

**Fine-grained locking (per-container locks instead of global):**
- Rejected: Per-container locks still create interference between lanes in the same container. The I property requires zero interference, not reduced interference.

**Lock-free data structures (Michael-Scott queue, etc.):**
- Rejected: Lock-free ≠ interference-free. Lock-free structures use atomic CAS operations that still create observable interference patterns. CAS loops also create latency variance.

**Read-Copy-Update (RCU):**
- Rejected: RCU still requires synchronization points (grace periods) that create interference. Not compatible with the I property.

**Conclusion:** Message passing and single ownership are the only approaches that provide true interference-freedom. Locks in any form compromise HIP.

---

## ADR-002: Single Selector

**Date:** Initial architecture
**Status:** Accepted (inviolable)

### Context

The selector determines which container to dispatch next. The question is: should there be one selector per core (multiple selectors) or one selector for the entire system?

Multiple selectors appears to offer performance benefits: each core selects independently, no coordination between selectors, scales linearly.

### Decision

One selector for the entire system. Single selector is always correct.

### Consequences

**Positive:**
- Selection is globally consistent — all cores see the same Ready Pool state
- Entropy is consumed from one source — uniform distribution guaranteed
- No coordination between selectors needed (multiple selectors would need to coordinate)
- Weighted entropy properties hold globally (not per-core)

**Negative:**
- Selector becomes a potential bottleneck at very high dispatch rates
- Selector must be implemented efficiently (it is — ~10-20 cycles per selection)

### Alternatives Considered

**Per-core selectors:**
- **Fatal flaw**: Multiple selectors must coordinate to avoid double-dispatching the same container. This coordination requires — a lock. Or some other form of synchronization. Which violates ADR-001.
- **Second flaw**: Per-core selectors create uneven selection distributions. Container A might always be selected by Core 0's selector (because of locality), and Core 1's selector never sees it. This breaks the I (Interference-Free) property at the multi-core level.
- **Third flaw**: Weighted entropy from multiple selectors does not compose to the correct global distribution. The math doesn't work.

**Work-stealing between per-core queues:**
- Rejected: Work-stealing requires a lock or CAS loop at steal time. Violates ADR-001.

**NUMA-aware per-socket selectors:**
- Rejected: Same coordination problem as per-core. Considered for future as an optimization if the selector can be proven lock-free and globally consistent, but no viable design has been found.

**Conclusion:** Single selector is the only design that is simultaneously lock-free, globally consistent, and provides correct weighted entropy distribution.

---

## ADR-003: Lane Architecture

**Date:** Initial architecture
**Status:** Accepted

### Context

The question: what is the fundamental unit of parallel execution in HIP?

Options considered:
- Traditional threads (shared memory, OS-managed)
- Goroutine-style (green threads, runtime-managed)
- Actor model (message-passing entities)
- Lane (future-based, kernel-aware, isolated)

### Decision

Lanes: lightweight, kernel-registered, future-executing units of work within a container's isolation boundary. A lane is a logical execution pathway. It holds a Rust `Future` and is dispatched by the kernel.

### Consequences

**Positive:**
- Lanes map directly to Rust's `Future` trait — no new language needed
- Lane state is minimal: just the future's state machine
- Lanes are created and destroyed cheaply (~microseconds)
- Lane count can be much higher than core count (stalling lanes don't consume cores)
- Lanes are the natural unit for HIP's P (Parallel Pathway Maintenance) property

**Negative:**
- Developers must think in terms of futures and async/await rather than threads
- Stack size must be bounded (no dynamic stack growth like threads)
- Long-running synchronous operations must be explicitly yielded

### Alternatives Considered

**Traditional threads:**
- Rejected: Threads share memory. Shared memory = shared mutable state = locks needed = violates ADR-001.

**Goroutines (Go-style green threads with shared heap):**
- Rejected: Shared heap = shared mutable state = same problem as threads.

**Actor model (Erlang/Akka style):**
- Considered seriously. Actors are message-passing, isolated, and fit HIP well.
- Why not actors: Actors in Erlang/Akka are coarser-grained than lanes. Each actor has its own message inbox (a queue with a lock). In HIP, lanes don't have individual inboxes — work is submitted and the kernel dispatches. The lane model is simpler and maps more directly to Rust futures.
- Lanes can BE actors: a lane can receive from a channel and process messages — actor pattern is a design pattern within lanes, not the fundamental primitive.

**WebAssembly components:**
- Interesting for isolation, but not appropriate as the kernel primitive. Too heavy for the dispatch granularity HIP requires.

---

## ADR-004: Weighted Entropy Over Priority

**Date:** Initial architecture
**Status:** Accepted

### Context

How should the selector choose which container to dispatch? Two main approaches exist:

**Priority-based:** Assign priorities. Always run the highest-priority ready container. Simple, predictable, familiar.

**Weighted entropy:** Assign weights. Use weighted random selection. Each dispatch round, the probability of selecting a container is proportional to its weight.

### Decision

Weighted entropy. No priority queues.

### Consequences

**Positive:**
- Non-determinism is the natural result — HIP property N (Non-Deterministic Correct Execution) is mechanically achieved
- No priority inversion (low-priority containers can always get some dispatch time)
- Anti-starvation is probabilistic — even weight-1 containers get time
- Equal weights = equal probability = fair scheduling by default
- On Maximum Isolation: all weights equal → perfect non-determinism → no timing side channels from scheduling

**Negative:**
- Developers accustomed to priority-based scheduling must adjust
- "Why didn't my high-weight container run immediately?" — it's probabilistic, not deterministic
- Harder to reason about exact dispatch timing

### Alternatives Considered

**Pure priority queues:**
- Rejected for several reasons:
  1. Priority inversion: low-priority holds a resource that high-priority needs. High-priority waits. Classic problem.
  2. Priority queues are deterministic — violates property N.
  3. On Maximum Isolation, priority queues create timing side channels: the scheduler's behavior reveals which containers are high/low priority.
  4. Starvation: low-priority containers may never run if high-priority containers are always ready.

**Fair-share scheduling (CFS-style):**
- Rejected: CFS tracks virtual runtime and selects the container with the least runtime. This creates DETERMINISTIC scheduling (least-runtime is always known). Deterministic scheduling violates property N.

**Earliest-deadline-first (EDF):**
- Rejected: Deadlines create deterministic ordering. Same problem as priority queues for property N.

**Round-robin:**
- Considered as a simpler alternative. Round-robin with equal turns is deterministic (fixed order). Also creates timing side channels.
- Weighted round-robin is slightly better but still deterministic in the long run.

**Pure random (no weights):**
- Considered for Maximum Isolation profile. Would be perfect for non-determinism.
- Rejected for general use: no way to differentiate interactive (high-weight) from background (low-weight). Performance profile would be unusable.
- Solution: weights are optional feature. Maximum Isolation uses 1:1:1 (effectively pure equal probability). Other profiles use weights.

---

## ADR-005: Custom Async Runtime

**Date:** Architecture confirmation (post-Rust selection)
**Status:** Accepted

### Context

After deciding to use Rust for CIBOS (the only viable systems language with the type safety and no_std support needed), the question arose: can we use an existing async runtime?

The candidates were:
- **Tokio**: The dominant Rust async runtime. Production-proven, well-maintained.
- **async-std**: Alternative runtime, similar capabilities.
- **smol**: Smaller footprint, still uses executor threads.
- **embassy**: Embedded async runtime, closest to CIBOS needs.

### Decision

Custom async runtime. No Tokio, no async-std, no smol.

The CIBOS async runtime implements:
- `LaneExecutor`: lane-local task queue, no global state
- `CibosWaker`: sends kernel message on wake, no polling
- `KernelInterface` trait: connects async runtime to CIBOS kernel events
- Async primitives: `Channel::receive()`, `Timer::sleep()`, `select!`

### Consequences

**Positive:**
- Runtime integrates directly with Catch and Release — `.await` IS the stall point
- No global task queues (Tokio's work-stealing queue is a global lock)
- `CibosWaker` uses kernel message passing — zero-polling wake notification
- Timer events go through the kernel event system — no background timer threads
- Future-agnostic: any `impl Future` works with CIBOS runtime

**Negative:**
- Tokio ecosystem crates don't work (tokio::time, tokio::sync, tokio::net, etc.)
- Developers must learn CIBOS async primitives
- More code to maintain

### Alternatives Considered

**Tokio:**
- **Fatal flaw 1**: Tokio's executor uses a global work-stealing queue. Work-stealing requires a lock (or CAS loop — still interference). Violates ADR-001.
- **Fatal flaw 2**: Tokio has background threads (timer thread, I/O polling thread). Background threads are not lanes — they run outside the HIP model. This means parts of the application bypass the kernel's Catch and Release entirely.
- **Fatal flaw 3**: `tokio::sync::Mutex` and similar types are explicitly built for sharing across async tasks. Sharing = interference. Violates the I property.

**async-std:**
- Same problems as Tokio: global executor, background threads, shared state types.

**smol:**
- Smaller than Tokio, but still uses an executor with a global queue.
- Same lock issue.

**embassy:**
- Embassy is designed for embedded systems and avoids many of Tokio's problems.
- Embassy uses a per-task waker and single-executor model.
- **Why not embassy**: Embassy's executor is designed for single-core embedded. CIBOS is multi-core. Adapting embassy to multi-core CIBOS would require significant modification. At that point, writing a CIBOS-native runtime is cleaner.
- Embassy is the closest to what CIBOS implements. The CIBOS runtime is conceptually similar to embassy but designed for multi-core and kernel-integrated operation.

**Conclusion:**

Rust's `Future` trait is executor-agnostic. This was the crucial insight: Rust does not require Tokio. Any code written as `async fn` can run on any executor. The CIBOS runtime implements the executor role, delegating scheduling decisions to the kernel's Catch and Release. The `.await` syntax maps directly to potential stall points in the HIP model. No language extension needed.

---

## ADR-006: Rust as Implementation Language

**Date:** Early architecture
**Status:** Accepted

### Context

Which language should implement CIBIOS and CIBOS?

Key requirements:
- `no_std` support (kernel runs without standard library)
- Memory safety (isolation depends on memory correctness)
- Zero-overhead abstractions (kernel cannot afford runtime cost)
- Cross-architecture support (x86-64, ARM64, RISC-V)
- Type system expressiveness (feature flag system, error handling)

### Decision

Rust.

### Consequences

**Positive:**
- `no_std` support is first-class — the standard library is optional
- Ownership type system enforces single ownership (ADR-003) at compile time
- No garbage collector — deterministic memory management
- `Future` trait enables HIP's lane model without language extension
- Feature flags via `#[cfg(feature = "...")]` map directly to CIBOS profile system
- `Result<T, E>` error handling — no unchecked exceptions
- Cross-compilation to all target architectures

**Negative:**
- Steeper learning curve than C for contributors
- Nightly Rust required for some no_std features
- Rust's borrow checker can be frustrating for kernel patterns (but usually finds real bugs)

### Alternatives Considered

**C:**
- No ownership enforcement at compile time — single ownership must be maintained by convention
- No `Result` type — error handling is ad-hoc
- No `Future` trait — async kernel model requires custom infrastructure
- Memory safety depends entirely on programmer discipline
- **Rejected**: The type system expressiveness Rust provides is essential for correctness in the CIBOS kernel.

**C++:**
- Better abstractions than C, but safety is still opt-in
- Complex language — kernel code benefits from smaller, safer language
- **Rejected**: Same fundamental safety concerns as C, with more complexity.

**Zig:**
- Excellent `comptime` feature maps well to CIBOS feature flags
- Good `no_std` story
- **Not chosen**: Zig lacks the `Future` trait and async ecosystem. Building the async model for HIP on Zig would require the same custom infrastructure as Rust, without Rust's type system advantages. Rust was chosen; Zig remains a viable alternative for a future reimplementation.

**Go:**
- Goroutines map conceptually to lanes
- **Fatal flaw**: Go has a garbage collector (not suitable for real-time kernel), runtime requires OS support (not no_std), and goroutines share memory (violates single ownership).

---

## ADR-007: Profile System as Compile-Time Feature Flags

**Date:** Architecture confirmation
**Status:** Accepted

### Context

CIBOS supports four profiles with significantly different feature sets. How should this variation be managed?

Options:
1. **Runtime configuration**: One binary, features enabled/disabled at boot via config file
2. **Compile-time feature flags**: Different binary per profile, features selected at compile time
3. **Loadable modules**: Core binary, features loaded as modules at boot

### Decision

Compile-time feature flags. Each profile produces a different binary.

### Consequences

**Positive:**
- Eliminated dead code: Maximum Isolation binary contains no anti-starvation code at all
- Security: prohibited features cannot be enabled at runtime — they don't exist in the binary
- CIBIOS self-enforcing profile pairing: if CIBIOS Standard tries to load CIBOS Compute, the signature hash mismatch causes boot failure. This is automatic.
- Performance: zero overhead for features not compiled in
- Auditability: the binary is exactly what was compiled. No runtime surprises.

**Negative:**
- Separate build per profile
- Cannot switch profiles without rebuilding and rebooting
- More complex build system

### Alternatives Considered

**Runtime configuration:**
- **Rejected**: A Maximum Isolation system that has anti-starvation code compiled in but "disabled by config" is still potentially exploitable. An attacker with kernel access could enable it. Compile-time exclusion is the only reliable guarantee.
- Security products require that prohibited features genuinely do not exist in the binary.

**Loadable modules:**
- **Rejected**: Modules are loaded at runtime — same security problem as runtime configuration. A module that "shouldn't be loaded" can be loaded by an attacker.
- Also: modules introduce complexity (module loading mechanism) without benefit in CIBOS's use case.

**Separate repositories per profile:**
- Considered briefly. Too much code duplication. Feature flags in one repository is cleaner.

**Conclusion:** Compile-time feature flags are the only approach that provides genuine elimination of prohibited features. This is essential for the security guarantees of Maximum Isolation profile, and provides clean zero-overhead guarantees for all profiles.

---

## ADR-008: CIBIOS and CIBOS as Separate Binaries with Cryptographic Handoff

**Date:** Initial architecture
**Status:** Accepted

### Context

Should the firmware (hardware initialization) and kernel (execution environment) be one binary or two?

### Decision

Two separate binaries: CIBIOS (firmware) and CIBOS (kernel). CIBIOS verifies CIBOS's signature before handoff.

### Consequences

**Positive:**
- Clear separation of concerns: hardware initialization vs execution model
- Profile pairing is self-enforcing: CIBIOS Standard + CIBOS Compute = hash mismatch = boot failure
- CIBIOS can be in ROM/SPI flash; CIBOS can be on the boot disk — different trust roots
- Independent development and testing of firmware and kernel layers
- CIBIOS can be formally verified independently (smaller, simpler scope)

**Negative:**
- Build system must coordinate building both
- Handoff protocol adds boot complexity
- Signature verification adds a few milliseconds to boot time

### Alternatives Considered

**Single binary (monolithic firmware+kernel):**
- **Rejected**: A single binary cannot enforce profile pairing — it would need to "detect" its own profile at boot, which is trivially bypassed.
- Separation of trust roots is valuable: CIBIOS can be hardware-locked while CIBOS is updated.

**Three-layer (bootloader + CIBIOS + CIBOS):**
- Considered for environments with secure boot (UEFI Secure Boot, etc.)
- UEFI can serve the bootloader role, with CIBIOS as the first-stage firmware
- Not adopted as standard architecture — too complex for initial design. UEFI compatibility is handled by the CIBIOS build system producing UEFI-compatible images.

---

**Document Type:** Architecture Decision Records
**Part of:** CIBIOS/CIBOS/HIP Documentation Suite
**Related Documents:** HIP README, CIBIOS README, CIBOS README, Developer Guide, Contributor Guide, Technical White Paper
