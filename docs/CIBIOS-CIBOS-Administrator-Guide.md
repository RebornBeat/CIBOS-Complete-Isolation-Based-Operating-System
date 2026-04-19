# CIBIOS/CIBOS Administrator Guide
**Deployment, Configuration, and Operations Reference**

## Introduction

This guide covers everything an administrator needs to deploy, configure, and operate CIBIOS and CIBOS systems. It assumes familiarity with the CIBIOS and CIBOS READMEs and understanding of HIP architectural principles. This guide explains how to apply those principles to real deployments.

---

## Chapter 1: Deployment Planning

### The Quantum-Like to Security Spectrum

All profiles provide HIP's quantum-like computational properties (P, I, N, A). The profiles differ in which security features are added on top of that foundation. Every profile has high QTM scores because the foundation is always present. Security features add overhead; they do not reduce quantum-like properties.

```
PROFILE SPECTRUM:

MAXIMUM QUANTUM-LIKE                        MAXIMUM SECURITY
(Minimum Overhead)                          (Additional Overhead)

◄────────────────────────────────────────────────────────────────────►

┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   COMPUTE    │  │  BALANCED    │  │ PERFORMANCE  │  │   MAXIMUM    │
│              │  │              │  │              │  │  ISOLATION   │
│ P = maximum  │  │ P = high     │  │ P = high     │  │ P = moderate │
│ I = maximum  │  │ I = high     │  │ I = high     │  │ I = high     │
│ N = maximum  │  │ N = high-mod │  │ N = moderate │  │ N = maximum  │
│ A = maximum  │  │ A = high     │  │ A = high     │  │ A = high     │
│              │  │              │  │              │  │              │
│ Security:    │  │ Security:    │  │ Security:    │  │ Security:    │
│  None needed │  │  Crypto IPC  │  │  None        │  │  Full stack  │
│  (air-gapped)│  │  User auth   │  │  (physical)  │  │  RTRO        │
│              │  │  RTRO (opt)  │  │              │  │  Multi-user  │
│ SMT: Enabled │  │              │  │ SMT: Enabled │  │  Audit       │
│ Overhead:    │  │ SMT: Disabled│  │ Overhead:    │  │              │
│  ~10-20 cyc  │  │ (default)    │  │  ~30-50 cyc  │  │ SMT: Disabled│
│  /selection  │  │ Overhead:    │  │  + fairness  │  │ Overhead:    │
│              │  │  ~5-15%      │  │              │  │  ~10-20%     │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

ALL PROFILES HAVE HIGH QTM — FOUNDATION (P, I, N, A) PRESENT IN ALL
SECURITY FEATURES ADD OVERHEAD, DON'T REDUCE PROPERTIES
```

### Profile Selection Decision Tree

```
START: What is your threat model?

├── Adversarial network observer?
│   └── Multi-user system?
│       └── MAXIMUM ISOLATION Profile
│
├── Network-connected but no sophisticated adversary?
│   └── Single user or small trusted group?
│       └── BALANCED Profile
│
├── Limited hardware, responsiveness priority?
│   └── PERFORMANCE Profile
│
├── Air-gapped system, maximum throughput?
│   └── COMPUTE Profile
│
└── Unsure?
    └── BALANCED Profile (safe default)
```

### Profile Summary Reference

**Maximum Isolation:**
- RTRO: Always compiled | Weights: 1:1:1 (equal) | Anti-starvation: NOT compiled
- Full-fairness: NOT compiled | SMT: Disabled | IPC: Cryptographic
- Multi-user: Yes | Handoff: Cryptographic | Overhead: Higher (security features)
- Use: Enterprise servers, high-security multi-user workstations

**Balanced:**
- RTRO: Optional | Weights: 3:1:1 (configurable) | Anti-starvation: 100ms
- Full-fairness: NOT compiled | SMT: Disabled (default) | IPC: Cryptographic
- Multi-user: Optional | Handoff: Cryptographic | Overhead: Low
- Use: Developer laptops, personal workstations, home computing

**Performance:**
- RTRO: NOT compiled | Weights: 5:2:1 (configurable) | Anti-starvation: 50ms
- Full-fairness: Compiled | SMT: Enabled | IPC: Optional
- Multi-user: No | Handoff: Cryptographic | Overhead: Moderate (fairness mechanisms)
- Use: Legacy hardware, embedded systems, resource-constrained devices

**Compute:**
- RTRO: NOT compiled | Weights: Equal or per-lane | Anti-starvation: Optional
- Full-fairness: NOT compiled | SMT: Enabled | IPC: Lightweight handshake
- Multi-user: No | Handoff: Lightweight | Overhead: Minimum
- Use: Air-gapped research, maximum throughput computation

### Hardware Requirements

| Profile | Minimum | Recommended | Note |
|---|---|---|---|
| Maximum Isolation | 2 cores, 4 GB RAM, 20 GB storage | 4+ cores, 8+ GB RAM, SSD | Equal weights create more contention — hardware headroom helps |
| Balanced | 1 core, 2 GB RAM, 10 GB storage | 2+ cores, 4+ GB RAM, SSD | — |
| Performance | 1 core, 1 GB RAM, 5 GB storage | 2+ cores, 2+ GB RAM | SMT enabled doubles effective contexts |
| Compute | 1 core, 128 MB RAM | 2+ cores, 1+ GB RAM, fast storage | More cores = more simultaneous lane executions |

### Execution Context Planning

```
WHEN WEIGHTS MATTER — VISUAL:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  WHEN WEIGHTS DON'T MATTER:                                                 │
│                                                                             │
│  Ready Pool: 4 events       Available contexts: 8                          │
│                                                                             │
│  4 ≤ 8 → ALL 4 DISPATCH SIMULTANEOUSLY                                     │
│  Weight values: IRRELEVANT                                                  │
│  Selection: NONE NEEDED                                                     │
│                                                                             │
│  ┌───┐  ┌───┐  ┌───┐  ┌───┐                                                │
│  │ A │  │ B │  │ C │  │ D │   ─────►   All dispatch simultaneously         │
│  │w=1│  │w=1│  │w=1│  │w=1│                                                │
│  └───┘  └───┘  └───┘  └───┘                                                │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│  WHEN WEIGHTS MATTER:                                                       │
│                                                                             │
│  Ready Pool: 10 events      Available contexts: 4                          │
│                                                                             │
│  10 > 4 → COMPETITION EXISTS — weighted entropy selects 4                  │
│  Weight values: DETERMINE PROBABILITY                                       │
│                                                                             │
│  System (weight 3):  3 tickets each                                        │
│  User (weight 1):    1 ticket each                                         │
│  Bg (weight 1):      1 ticket each                                         │
│                                                                             │
│  Example: 2 system, 5 user, 3 bg = 6+5+3=14 tickets                       │
│  Each system event: 3/14 = 21.4% probability                               │
│  Each user event:   1/14 =  7.1% probability                               │
│  Each bg event:     1/14 =  7.1% probability                               │
│                                                                             │
│  KEY INSIGHT:                                                               │
│  On well-provisioned systems (many contexts, low load),                     │
│  weight tuning has minimal effect.                                          │
│  Weight tuning matters most on limited hardware under heavy load.           │
│  Maximum Isolation ALWAYS requires equal weights (security).                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

Execution contexts = Physical Cores × SMT Factor. More contexts → less competition → less weight influence → more simultaneous execution.

---

## Chapter 2: Building and Installation

### Build Commands

```bash
# Maximum Isolation
cargo build --profile maximum-isolation

# Balanced
cargo build --profile balanced

# Performance
cargo build --profile performance

# Compute
cargo build --profile compute

# Custom feature combination
cargo build --no-default-features \
  --features "anti-starvation,signal-coalescence,cryptographic-ipc,gui-subsystem"

# Architecture-specific
cargo build --target x86_64-unknown-none
cargo build --target aarch64-unknown-none
cargo build --target riscv64-unknown-none

# Verify feature combination before building
cargo run --package builder -- --verify-features \
  --features "anti-starvation,signal-coalescence-threshold"
```

### Build Verification Output Examples

```
# Valid combination:
#   ✓ anti-starvation: valid
#   ✓ signal-coalescence-threshold: valid
#   ✓ Shared infrastructure available: YES (timing shared)
#   VALID: Feature combination is legal

# Invalid combination:
#   cargo run --package builder -- --verify-features \
#     --features "rtro,lightweight-handshake"
#   ✓ rtro: valid
#   ✗ lightweight-handshake: PROHIBITS rtro
#   INVALID: Feature conflict detected
```

### Installation Media

```
/boot/
  ├── cibios.bin
  ├── cibos-kernel
  ├── cibos.conf
  └── cibos.sig       (Standard profile only)
```

---

## Chapter 3: Configuration Management

### Configuration File

```toml
# /boot/cibos.conf

[scheduling]
# Weights control selection probability
# ONLY apply when Ready Pool > execution contexts
system_weight = 3
user_weight = 1
background_weight = 1

# Anti-starvation threshold (milliseconds)
# Only effective if compiled in (Balanced and Performance profiles)
# Tracks ONLY Ready Pool time — stalled time does NOT count
anti_starvation_threshold_ms = 100

[resources]
# Per-container memory limit (MB)
memory_limit_mb = 512
io_bandwidth_mbps = 100

[channels]
max_channels_per_container = 16
message_queue_size = 256

[signal-coalescence]
# Enable signal coalescence (if compiled in)
enabled = true
# Backstop threshold (milliseconds) — signal processing deadline, NOT dispatch deadline
backstop_threshold_ms = 5

[resource-pools]
# Per-class memory pools (if compiled in)
# Percentages must sum to 100
system_pool_pct = 40
user_pool_pct = 50
background_pool_pct = 10

[core-affinity]
# Execution context assignment by class (if compiled in)
# Values must sum to total execution contexts (physical × SMT factor)
system_contexts = 8
user_contexts = 7
background_contexts = 1

[signature]
algorithm = "ed25519"
signature = "<base64-encoded-signature>"
```

### Configuration Fallback

| Scenario | Result |
|---|---|
| Config file missing | Compiled defaults applied, system operational |
| Config signature invalid | Compiled defaults applied, warning logged, system operational |
| Config parsed correctly | Signed config values used |

Missing or invalid configuration is NOT a fatal error. System always remains operational.

### Compiled Defaults by Profile

| Profile | system_weight | user_weight | background_weight | anti_starvation |
|---|---|---|---|---|
| Maximum Isolation | 1 | 1 | 1 | Not compiled |
| Balanced | 3 | 1 | 1 | 100ms |
| Performance | 5 | 2 | 1 | 50ms |
| Compute | 1 | 1 | 1 | Optional |

### Signing Configuration

```bash
# Generate keys
cibos-keygen --output /secure/keys

# Sign configuration
cibos-sign \
  --config /boot/cibos.conf \
  --key /secure/keys/signing.key \
  --output /boot/cibos.sig

# Verify signature
cibos-verify \
  --config /boot/cibos.conf \
  --sig /boot/cibos.sig \
  --key /secure/keys/verifying.key
```

Key management: Private key offline/air-gapped. Public key embedded in CIBIOS at build time. Rotation requires rebuilding CIBIOS with new public key.

**Key rotation schedule:** Maximum Isolation: 90 days. Balanced: 180 days. Performance: 365 days. Compute: Before each major deployment.

---

## Chapter 4: SMT Configuration

CIBIOS configures SMT at boot. CIBOS inherits the configuration. CIBOS cannot change SMT configuration after boot.

| Profile | SMT Default | Security Reason |
|---|---|---|
| Maximum Isolation | Disabled | Eliminates hardware side-channels entirely |
| Balanced | Disabled by default | Security-conscious; user may enable |
| Performance | Enabled | Maximize throughput on limited hardware |
| Compute | Enabled | Maximum parallel computation |

**SMT in CIBOS vs traditional systems:** Traditional systems with SMT suffer from thread contention, cache thrashing, and time-slice serialization. CIBOS with SMT has none of these — no locks means no contention; isolated memory means no shared state interference; event-driven dispatch means no time-slicing. SMT in CIBOS adds execution capacity without adding coordination overhead. The only remaining concern is hardware-level cache sharing between logical cores on the same physical core, which is why security-conscious profiles disable SMT.

---

## Chapter 5: Weight Tuning

### Tuning Guidelines

| Symptom | Cause | Solution |
|---|---|---|
| UI lagging under load | Window manager selected infrequently | Increase system_weight to 4 or 5 |
| Background tasks never complete | Low-weight events rarely selected | Enable anti-starvation or increase background_weight to 2 |
| Unpredictable performance | High entropy in selection | Use more differentiated weights |
| Observable patterns (Maximum Isolation) | Weights not equal | ALL weights MUST be 1 — security requirement |
| Anti-starvation fires too often | Threshold too low | Increase anti_starvation_threshold_ms |
| Anti-starvation never fires | Threshold too high | Decrease anti_starvation_threshold_ms |

### Profile-Specific Weight Guidance

**Maximum Isolation:** DO NOT TUNE WEIGHTS. All weights MUST remain equal (1:1:1). Unequal weights create observable patterns — a security violation.

**Balanced:** Default 3:1:1 works for most workloads. If UI feels sluggish: increase system_weight to 4-5. If background tasks stall: check anti-starvation threshold or increase background_weight to 2. For compute-heavy workloads: reduce system_weight to 2, accept slightly slower UI.

**Performance:** Default 5:2:1 for limited hardware. Very limited (2 cores, 2GB): system=7, user=3, bg=1. Moderate hardware (4 cores, 4GB): system=4, user=2, bg=1. Full fairness ensures all lanes get time eventually — adjust weights for responsiveness preference.

**Compute:** Default equal weights (1:1:1) for maximum entropy and parallel computation. For interactive monitoring: system_weight=2, user_weight=1 provides CLI responsiveness. Per-lane weights (if compiled in) allow application-level fine-grained control. Dynamic weights (if compiled in) allow phase management at runtime.

### Tuning Process

1. Start with profile defaults
2. Run representative workloads
3. Observe which components feel slow
4. Adjust weights incrementally (change by 1 at a time)
5. Re-run workloads and observe change
6. Sign new configuration file and deploy
7. Monitor for unintended effects

---

## Chapter 6: Resource Management

### Memory Limits

When a container reaches its memory limit, allocation stalls (Catch and Release). This is NOT an OOM crash — the container waits invisibly until memory is freed. No retry loop needed.

Choosing values: Browser containers 512-2048 MB. Office applications 128-512 MB. System services 64-256 MB. Compute containers: match workload dataset size.

### Class Resource Pools (When Compiled)

```toml
[resource-pools]
system_pool_pct = 40
user_pool_pct = 50
background_pool_pct = 10
```

- System containers allocate ONLY from system_pool
- User containers allocate ONLY from user_pool
- Background containers allocate ONLY from background_pool
- No cross-pool borrowing
- Pool metadata owned by selector (no locks)

Trade-off: Class pools prevent one class from starving others but may underutilize memory if one pool is idle while another is exhausted.

### Core Affinity Configuration (When Compiled)

```toml
[core-affinity]
# Example for 16-context system (8 cores, 2-way SMT)
system_contexts = 8
user_contexts = 7
background_contexts = 1
```

Routing is deterministic by class. Class membership is not secret information. No locks needed: selector owns routing configuration exclusively.

### Understanding Stalls

Stalls are NOT errors. A container waiting for a resource is in the Stalled List — it waits invisibly and resumes automatically when the resource becomes available.

Common stall causes: Memory limit exceeded (free memory or increase limit), channel buffer full (receiver reads), channel buffer empty (sender writes), I/O operation pending (wait for completion).

Multi-resource stalls: A container may need multiple resources. ALL must be available before the container moves to the Ready Pool. If memory becomes available but channel buffer is still full — container stays stalled.

---

## Chapter 7: Monitoring and Diagnostics

### Key Commands

```bash
# Scheduler status
cibos-ctl scheduler
# Output: Ready Pool size, Stalled List size, core availability, SMT status,
#         execution contexts

# Dispatch statistics
cibos-ctl scheduler --stats
# Output: Dispatch opportunities, no-competition %, competition %,
#         avg events per dispatch, max simultaneous

# Memory status
cibos-ctl memory

# Container status
cibos-ctl containers

# Channel status
cibos-ctl channels

# Execution contexts
cibos-ctl cores
# Output: Physical cores, SMT factor, logical cores, busy/available

# Signal coalescence (if compiled in)
cibos-ctl signal-coalescence --stats

# Core affinity (if compiled in)
cibos-ctl core-affinity --stats

# Resource pools (if compiled in)
cibos-ctl resource-pools

# Diagnose specific container
cibos-ctl diagnose --container <id>

# Per-lane status (Compute profile)
cibos-ctl lanes --container <id>
```

### Interpreting Dispatch Statistics

| Metric | Interpretation |
|---|---|
| High no-competition % (>80%) | System handling load well; weights have minimal effect |
| High competition % (>30%) | Heavy load; weights significantly influence selection; consider more contexts |
| Low events per dispatch | Small events or high competition |
| Max simultaneous = context count | Expected; system using all available contexts |
| Max simultaneous < context count | Light load or resource constraints |

### Common Issues

**Unresponsive system:**
1. Check Ready Pool — if empty, check Stalled List
2. Check Stalled List — identify which resources are waited for
3. Check resource availability — are resources being released?
4. Check execution contexts — are they available?

**Container stalled:**
1. `cibos-ctl diagnose --container <id>` — identifies stalled resource
2. Check if resource can be freed (memory: reduce usage; channel: clear buffers; I/O: wait)
3. Check for multi-resource stall — ALL required resources must become available simultaneously

**Slow background tasks:**
1. Check if competition is frequent (if no competition, weights are irrelevant)
2. Check anti-starvation threshold (if compiled)
3. Check resource constraints
4. Verify background_weight > 0

---

## Chapter 8: Compute Profile Operations

### Compute-Specific Configuration

```toml
# For fire-and-wait workflows (maximum entropy, maximum quantum-like)
[scheduling]
system_weight = 1
user_weight = 1
background_weight = 1

# For interactive monitoring during computation
[scheduling]
system_weight = 2    # CLI remains responsive
user_weight = 1      # Compute lanes compete fairly

[resources]
memory_limit_mb = 2048  # Match workload dataset size
```

### Per-Lane Weights

When `per-lane-weights` is compiled in, applications assign weights at lane creation. High-priority computation (weight 3-5): primary algorithm, time-sensitive, user-facing results. Normal priority (weight 1): parallel branches, peer computations. Equal weights: fire-and-wait workflows, maximum entropy.

### Dynamic Weights

When `dynamic-weights` is compiled in, applications send weight-change messages to the selector at runtime. The selector updates the weight — no locks (selector owns all weight data). Overhead: ~45-110 cycles per change, zero per dispatch.

**When to use:** Scientific computing phases where priority shifts (high weight for data loading, equal weights during parallel computation, high weight for result aggregation).

**When NOT to use:** Any profile with an adversarial observer. Weight change timing is observable and could reveal application state.

### Compute Monitoring

```bash
cibos-ctl lanes --container <id>       # Per-lane state and weights
cibos-ctl throughput --container <id>   # Events/sec, wait times
cibos-ctl resources --container <id>    # Memory, I/O, channels
cibos-ctl cores                         # All cores busy = good for compute
```

---

## Chapter 9: Mobile Device Configuration

### Sensor Authorization

All sensor access requires per-access authorization:

```bash
cibos-ctl sensor --camera --authorize <container-id>
cibos-ctl sensor --microphone --authorize <container-id>
cibos-ctl sensor --gps --authorize <container-id> --precision coarse
```

### Power Management Configuration

```toml
[power-management]
critical_threshold = 5      # System-only below this %
low_threshold = 15           # Background suspended below this %
normal_threshold = 30        # Normal operation above this %

system_budget = 50           # % of available power for system class
user_budget = 40
background_budget = 10
```

---

## Chapter 10: Maintenance

### Update Procedure

1. Build new CIBIOS/CIBOS
2. Re-sign configuration if changed
3. Keep backup of previous working version
4. Flash CIBIOS firmware
5. Copy CIBOS kernel to boot media
6. Verify boot completes
7. Check version numbers and expected features
8. Run acceptance tests
9. Monitor for 24 hours
10. Archive previous version

---

## Appendix: Complete Configuration Reference

```toml
# /boot/cibos.conf — Complete Reference

[scheduling]
system_weight = 3
user_weight = 1
background_weight = 1
anti_starvation_threshold_ms = 100

[resources]
memory_limit_mb = 512
io_bandwidth_mbps = 100

[channels]
max_channels_per_container = 16
message_queue_size = 256

[signal-coalescence]
enabled = true
backstop_threshold_ms = 5

[resource-pools]
system_pool_pct = 40
user_pool_pct = 50
background_pool_pct = 10

[core-affinity]
system_contexts = 8
user_contexts = 7
background_contexts = 1

[power-management]
critical_threshold = 5
low_threshold = 15
normal_threshold = 30
system_budget = 50
user_budget = 40
background_budget = 10

[mobile-connectivity]
cellular_enabled = true
roaming_allowed = false
container_data_limit = 100

[mobile-connectivity.bluetooth]
enabled = true
discoverable = false
pairing_required = true

[mobile-connectivity.nfc]
enabled = true
secure_element = true

[signature]
algorithm = "ed25519"
signature = "<base64-encoded-signature>"
```

---

*For implementation details, see the Developer Guide. For writing applications, see the Application Developer Guide. For security verification, see the Security Analysis Guide.*
