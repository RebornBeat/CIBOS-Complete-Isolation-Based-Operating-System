# CONTRIBUTOR GUIDE

**CIBIOS/CIBOS/HIP — Contributing to the Project**
**Version:** 1.0.0
**Audience:** Open source contributors

---

## Overview

Welcome to the CIBIOS/CIBOS/HIP project. This guide covers everything you need to contribute effectively: development setup, code organization, coding standards, testing requirements, and the pull request process.

**The most important thing to understand before contributing:**

```
THE TWO INVIOLABLE CONSTRAINTS:

  1. NO GLOBAL LOCKS
     The entire HIP architecture depends on this.
     A single global lock anywhere in the kernel destroys
     the I (Interference-Free) property.
     Every PR is reviewed for lock-freedom.

  2. ISOLATION BOUNDARIES
     All cross-container state is mediated by the kernel.
     No bypass of isolation is ever acceptable,
     regardless of performance benefit.

Contributions that violate either constraint will not be merged.
No exceptions. The architecture is the product.
```

---

## Chapter 1: Development Environment Setup

### 1.1 Clone and Initial Build

```bash
# Clone the repository
git clone https://github.com/RebornBeat/CIBOS-Complete-Isolation-Based-Operating-System.git
cd cibos

# Install required tools
./scripts/setup-dev.sh

# What setup-dev.sh does:
# - Installs Rust nightly
# - Adds all target architectures
# - Installs rust-src and llvm-tools-preview
# - Installs lld linker
# - Installs cargo tools: cargo-audit, cargo-deny, cargo-tarpaulin
# - Installs no-lock-verify tool (CIBOS-specific static analysis)

# Verify setup
make dev-check

# Build all profiles in debug mode
make all-profiles-debug
```

### 1.2 Development Build

```bash
# Build a specific profile in debug mode (fast compile, more debug info)
make profile=balanced debug=true

# Build with extra diagnostic output
make profile=balanced debug=true CIBOS_DIAGNOSTIC=1

# Run in QEMU for quick testing
make qemu profile=balanced debug=true
# QEMU starts with GDB server on port 1234

# In another terminal, attach GDB:
rust-gdb target/debug/cibos -ex "target remote :1234"
```

### 1.3 Running Tests

```bash
# Run all tests
make test

# Run specific test categories
make test-unit              # Unit tests (host-side, no QEMU needed)
make test-integration       # Integration tests (requires QEMU)
make test-no-lock           # No-lock verification tests
make test-security          # Security tests

# Run tests for specific crates
cargo test -p cibos-kernel
cargo test -p cibos-scheduler
cargo test -p cibos-channel

# Run with test output visible
cargo test -- --nocapture
```

---

## Chapter 2: Code Organization

### 2.1 Repository Structure

```
cibos/
├── cibios/                     CIBIOS firmware
│   ├── src/
│   │   ├── main.rs             Entry point and boot sequence
│   │   ├── hardware.rs         Hardware initialization
│   │   ├── memory.rs           Memory isolation setup
│   │   ├── smt.rs              SMT configuration
│   │   ├── rng.rs              Hardware RNG
│   │   └── handoff.rs          Kernel handoff and signing
│   └── Cargo.toml
│
├── cibos/                      CIBOS kernel
│   ├── src/
│   │   ├── main.rs             Kernel entry point
│   │   ├── catch_release/      Two-layer execution model
│   │   │   ├── catch.rs        Catch (eligibility determination)
│   │   │   ├── release.rs      Release (dispatch)
│   │   │   └── stall.rs        Stall list management
│   │   ├── selector/           Weighted entropy selector
│   │   │   ├── selector.rs     Single selector implementation
│   │   │   └── entropy.rs      Entropy source management
│   │   ├── lane/               Lane management
│   │   │   ├── lane.rs         Lane lifecycle
│   │   │   └── pool.rs         Ready Pool
│   │   ├── channel/            Channel implementation
│   │   │   ├── channel.rs      Channel state machine
│   │   │   ├── crypto.rs       Cryptographic IPC
│   │   │   └── lightweight.rs  Lightweight IPC (Compute)
│   │   ├── container/          Container isolation
│   │   │   ├── container.rs    Container lifecycle
│   │   │   ├── memory.rs       Per-container allocator
│   │   │   └── policy.rs       Authorization policy
│   │   ├── timer/              Timer subsystem
│   │   └── sensor/             Sensor isolation (mobile)
│   └── Cargo.toml
│
├── async-runtime/              CIBOS async runtime
│   ├── src/
│   │   ├── executor.rs         LaneExecutor
│   │   ├── waker.rs            CibosWaker
│   │   ├── channel.rs          Async channel primitives
│   │   ├── timer.rs            Async timer primitives
│   │   └── macros.rs           #[cibos::main] and select!
│   └── Cargo.toml
│
├── cibos-sdk/                  Application SDK (what apps link against)
│   ├── src/
│   │   ├── lane.rs             Lane API
│   │   ├── channel.rs          Channel API
│   │   ├── timer.rs            Timer API
│   │   ├── sensor.rs           Sensor API (mobile)
│   │   └── container.rs        Container API
│   └── Cargo.toml
│
├── examples/                   Example applications (see Examples doc)
├── docs/                       Documentation source
├── tests/                      Integration tests
│   ├── unit/                   Host-side unit tests
│   ├── integration/            QEMU-based integration tests
│   └── security/               Security verification tests
└── scripts/                    Build and tooling scripts
    ├── setup-dev.sh             Development setup
    ├── no-lock-verify.sh        Lock-freedom verification
    └── check-env.sh             Environment check
```

### 2.2 Module Responsibilities

```
CLEAR OWNERSHIP RULES:

  catch_release/: ONLY determines eligibility and dispatches.
    Must never: allocate, communicate between containers, make policy decisions.
    May: move containers between Ready Pool and Stalled List.

  selector/: ONLY selects which container to dispatch next.
    Must never: execute containers, modify container state.
    May: read Ready Pool, read weights, use entropy.

  lane/: ONLY manages lane lifecycle.
    Must never: execute futures directly, access other container's lanes.
    May: register/deregister with catch_release.

  channel/: ONLY manages message transfer between containers.
    Must never: share container memory, bypass isolation boundary.
    May: buffer messages in kernel-owned memory.

  container/: ONLY manages container isolation boundaries.
    Must never: allow cross-container memory access.
    May: establish and enforce memory regions.
```

---

## Chapter 3: Coding Standards

### 3.1 Rust Style

```rust
// Follow standard Rust idioms with these additions:

// 1. All public items must have documentation comments
/// Creates a new lane in the current container.
///
/// # Errors
/// Returns `LaneError::ContainerAtCapacity` if the container is at its lane limit.
pub fn create() -> Result<Lane, LaneError> { ... }

// 2. No unwrap() in kernel code — all errors must be handled
// WRONG:
let lane = Lane::create().unwrap();

// RIGHT:
let lane = Lane::create().map_err(|e| KernelError::LaneCreation(e))?;

// 3. Use type aliases for semantic clarity
type LaneId = u64;        // Not just u64
type ContainerId = u64;   // Not just u64
type Weight = u32;        // Not just u32

// 4. Mark all unsafe blocks with explicit justification
// WRONG:
unsafe { do_thing(); }

// RIGHT:
// SAFETY: `ptr` is guaranteed valid because [specific reason].
// This pointer was obtained from [source] and has not been freed
// because [lifetime argument].
unsafe { ptr.as_ref().unwrap() }

// 5. Feature gates must be in pairs: compile-time check + runtime note
#[cfg(feature = "dynamic-weights")]
pub fn update_weight(&mut self, weight: u32) -> Result<(), LaneError> {
    // ...
}
// And in documentation: clearly mark as #[cfg(feature = "dynamic-weights")]
```

### 3.2 No-Lock Verification

Every function that could potentially acquire a lock must be verified:

```bash
# Run the no-lock verifier on a specific module
cargo run --bin no-lock-verify -- cibos/src/catch_release/

# The verifier checks for:
# - Mutex, RwLock, Semaphore usage
# - std::sync::* usage
# - Any type in banned_sync_list.txt
# - parking_lot, spin::Mutex, and similar crates

# Expected output:
# Checking cibos/src/catch_release/catch.rs ... PASS
# Checking cibos/src/catch_release/release.rs ... PASS
# Checking cibos/src/catch_release/stall.rs ... PASS
# All checks passed. No locks found.
```

**Allowed synchronization mechanisms:**

```
ALLOWED:
  - Message passing (through kernel channel system)
  - Atomic operations on single values (AtomicU64, AtomicBool, etc.)
  - Per-lane data (no sharing = no synchronization needed)

PROHIBITED IN KERNEL:
  - Mutex (std or external)
  - RwLock
  - Semaphore
  - spin::Mutex
  - parking_lot::Mutex
  - Any type containing the word "lock" or "mutex"
  - Channel (std) — use CIBOS kernel channel system instead
```

### 3.3 Documentation Requirements

```
DOCUMENTATION REQUIREMENTS BY ITEM TYPE:

  Public function:        Required doc comment with:
                          - One-sentence summary
                          - Parameters description (if non-obvious)
                          - Return value description
                          - Errors section (for Result-returning functions)
                          - Example (for SDK functions)

  Public struct/enum:     Required doc comment with:
                          - Purpose
                          - Field descriptions

  Private function:       Recommended if non-obvious
                          Required if contains unsafe

  Feature-gated items:    Must clearly state which feature gates them
                          Must state which profiles support that feature

  Unsafe blocks:          Required SAFETY comment (see above)
```

### 3.4 Comment Conventions

```rust
// Standard comments for CIBOS:

// TODO: Used sparingly — should become issues instead
// SAFETY: Required before every unsafe block
// INVARIANT: Documents an invariant that must be maintained
// PROFILE: Notes profile-specific behavior

// Example:
fn dispatch_next(&mut self) -> Option<ContainerId> {
    // INVARIANT: Ready Pool is never empty when this is called.
    // Caller verified ready_pool.len() > 0 before calling dispatch_next().

    // PROFILE: On Maximum Isolation, weights are always 1:1:1.
    // On Compute with per-lane-weights, weights vary.
    // Both cases handled by weighted_entropy_select().

    let selected = self.selector.weighted_entropy_select(&self.ready_pool)?;
    // SAFETY: selected is guaranteed in ready_pool (returned from it).
    // ready_pool contains only valid ContainerIds.
    Some(selected)
}
```

---

## Chapter 4: Testing Requirements

### 4.1 Unit Tests

```rust
// Unit tests for kernel code run on the host (no QEMU needed)
// Use the test doubles provided in cibos-testkit

#[cfg(test)]
mod tests {
    use super::*;
    use cibos_testkit::{MockHardware, TestContainer};

    #[test]
    fn catch_and_release_moves_ready_containers_to_pool() {
        let mut catch_release = CatchAndRelease::new(MockHardware::with_cores(4));
        let container = TestContainer::new_with_resources_available();

        catch_release.catch(container.id());

        assert!(catch_release.ready_pool().contains(container.id()));
        assert!(!catch_release.stalled_list().contains(container.id()));
    }

    #[test]
    fn catch_and_release_moves_unavailable_to_stalled() {
        let mut catch_release = CatchAndRelease::new(MockHardware::with_cores(4));
        let container = TestContainer::new_with_channel_unavailable();

        catch_release.catch(container.id());

        assert!(!catch_release.ready_pool().contains(container.id()));
        assert!(catch_release.stalled_list().contains(container.id()));
    }
}
```

### 4.2 Integration Tests

```rust
// Integration tests run in QEMU
// Located in tests/integration/

// Run with: make test-integration

#[cibos_test::integration]
async fn test_channel_between_containers() {
    // Launch sender container
    let sender = cibos_test::launch_container("test-sender").await;

    // Launch receiver container
    let receiver = cibos_test::launch_container("test-receiver").await;

    // Wait for both to complete
    let sender_result = sender.wait().await;
    let receiver_result = receiver.wait().await;

    assert_eq!(sender_result, ContainerExitStatus::Clean);
    assert_eq!(receiver_result, ContainerExitStatus::Clean);

    // Verify messages were transferred
    let log = receiver.log().await;
    assert!(log.contains("Received 10 messages"));
}
```

### 4.3 No-Lock Verification Tests

```bash
# These run as part of make test-no-lock
# They verify the entire kernel codebase for lock usage

make test-no-lock

# Expected output:
# Scanning cibos/ for lock usage...
# Scanning async-runtime/ for lock usage...
# Scanning cibos-sdk/ for lock usage...
#
# Results:
#   Files scanned: 47
#   Lock usages found: 0
#   PASS: No locks found in kernel, runtime, or SDK.
```

### 4.4 Security Tests

```bash
# Security tests verify isolation boundaries
make test-security

# What they check:
# - Container A cannot read Container B's memory
# - Container A cannot send to Container B without channel
# - Sensor access is exclusive (two containers can't hold same sensor)
# - Cryptographic IPC rejects replayed messages
# - CIBIOS Standard + CIBOS Compute = boot failure (intentional)
```

---

## Chapter 5: Pull Request Process

### 5.1 PR Template

Every PR must complete this template:

```markdown
## Summary
[One paragraph: what does this PR do and why?]

## Type of Change
- [ ] Bug fix (existing behavior, now correct)
- [ ] New feature (new capability)
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Test addition/improvement

## No-Lock Verification
- [ ] I have run `make test-no-lock` and it passes
- [ ] I have reviewed every line of kernel code I added for lock usage
- [ ] I can confirm no global locks are introduced

## Isolation Verification
- [ ] No cross-container memory sharing is introduced
- [ ] All new IPC is through the kernel channel system
- [ ] Isolation boundaries are maintained

## Tests
- [ ] Unit tests added/updated for new code
- [ ] Integration tests added for new behavior
- [ ] All existing tests pass (`make test`)

## Profile Impact
Which profiles are affected by this change?
- [ ] Maximum Isolation
- [ ] Balanced
- [ ] Performance
- [ ] Compute
- [ ] All profiles

## Documentation
- [ ] Public APIs are documented
- [ ] SAFETY comments on all unsafe blocks
- [ ] CHANGELOG.md updated
```

### 5.2 Review Process

```
PR REVIEW FLOW:

  1. Author opens PR (completes template above)

  2. CI runs automatically:
     ├─ make test (all tests)
     ├─ make test-no-lock (lock verification)
     ├─ cargo clippy (lint)
     ├─ cargo fmt --check (formatting)
     └─ cargo deny (license/security audit)

  3. Core reviewer assigned (automatic based on files changed)

  4. Review focuses on:
     ├─ Lock-freedom (primary concern)
     ├─ Isolation integrity
     ├─ Correctness of async handling
     ├─ Profile-appropriate feature gating
     └─ Documentation completeness

  5. Author addresses feedback

  6. Second review for kernel changes (required for: catch_release, selector, channel)

  7. Merge (squash commits for clean history)
```

### 5.3 CI Requirements

All CI checks must pass before merge. No exceptions.

```bash
# Run the full CI check locally before opening a PR:
make ci-check

# This runs:
# cargo fmt --check
# cargo clippy -- -D warnings
# cargo deny check
# make test
# make test-no-lock
# make test-security
```

---

## Chapter 6: Architectural Constraints

### 6.1 No Global Locks — How to Verify

```bash
# Tool: no-lock-verify
# Usage: cargo run --bin no-lock-verify -- <path>

# Example: check a new file
cargo run --bin no-lock-verify -- cibos/src/my-new-module.rs

# Check for indirect lock usage (through external crates)
cargo run --bin no-lock-verify -- --check-deps cibos/

# Banned types (will fail verification):
# - std::sync::Mutex
# - std::sync::RwLock
# - parking_lot::Mutex
# - parking_lot::RwLock
# - spin::Mutex
# - crossbeam::Mutex
# - Any type containing "Mutex", "Lock", "Semaphore" in type name
```

**When you need coordination without locks:**

```rust
// Pattern 1: Message passing through kernel channels
// (for cross-container coordination — always correct)
kernel_channel.send(CoordinationMessage::WeightUpdate { lane_id, weight }).await?;

// Pattern 2: Atomics for single-value coordination
// (for kernel-internal state that is truly atomic)
let count = AtomicU64::new(0);
count.fetch_add(1, Ordering::Relaxed);

// Pattern 3: Per-lane data
// (no sharing = no synchronization needed)
// Each lane owns its own data. No coordination required.
struct LaneState { ... }  // owned by exactly one lane
```

### 6.2 Single Ownership — How to Verify

```
SINGLE OWNERSHIP RULE:
  Every piece of data is owned by exactly one entity at a time.
  When data moves between entities, ownership transfers.
  No shared mutable state ever exists.

HOW TO CHECK:
  - Does any type implement Clone and is it used across lane boundaries?
    → If yes: data is being shared. Consider if this is safe (immutable data via Arc).

  - Does any reference cross an isolation boundary?
    → This is always a violation. References must not cross container boundaries.

  - Does any static mut exist?
    → This is a violation. Global mutable state violates single ownership.
```

### 6.3 Message Passing — When and How

```
MESSAGE PASSING RULES:

  WHEN to use message passing:
  - Any coordination between containers (always)
  - Any state change that needs to be seen by the kernel (always)
  - Weight updates from lanes to selector (always)
  - Timer events from hardware to kernel (always)

  WHEN NOT to use message passing:
  - Within a single lane's async code (just update local state)
  - Pure computation within a lane (no coordination needed)
  - Immutable data that multiple lanes read (use Arc, not messages)

  HOW to implement message passing:
  - Use the CIBOS kernel channel system (Channel::request(), etc.)
  - For kernel-internal coordination: use the KernelMessage enum
  - Never implement your own message queue with locks
```
