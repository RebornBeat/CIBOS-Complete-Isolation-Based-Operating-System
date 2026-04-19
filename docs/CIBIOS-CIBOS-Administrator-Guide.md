# CIBIOS/CIBOS Administrator Guide
**Deployment, Configuration, and Operations Reference**

## Introduction

This guide covers everything an administrator needs to deploy, configure, and operate CIBIOS and CIBOS systems. It assumes you have read the CIBIOS and CIBOS READMEs and understand the architectural principles. This guide explains how to apply those principles to real deployments.

---

## Chapter 1: Deployment Planning

### Profile Selection Decision Tree

```
PROFILE SELECTION:

┌─────────────────────────────────────────────────────────────┐
│                  THREAT MODEL ASSESSMENT                     │
│                                                             │
│  START: What is your threat model?                          │
│                                                             │
│  ├─► Adversarial network observer?                          │
│  │   └─► Multi-user system?                                 │
│  │       └─► Maximum Isolation Profile                      │
│                                                             │
│  ├─► Network-connected but no sophisticated adversary?      │
│  │   └─► Single user or small trusted group?                │
│  │       └─► Balanced Profile                               │
│                                                             │
│  ├─► Limited hardware?                                      │
│  │   └─► Responsiveness priority?                           │
│  │       └─► Performance Profile                            │
│                                                             │
│  ├─► Air-gapped system?                                     │
│  │   └─► Maximum computational throughput?                  │
│  │       └─► Compute Profile                                │
│                                                             │
│  └─► Unsure?                                                │
│      └─► Balanced Profile (safe default)                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Profile Summary

```
PROFILE SUMMARY:

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  MAXIMUM ISOLATION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Primary use: Adversarial multi-user environments     │   │
│  │ RTRO: Yes (always)                                  │   │
│  │ Weights: Equal (1:1:1)                              │   │
│  │ Anti-starvation: Not compiled                        │   │
│  │ Full fairness: Not compiled                          │   │
│  │ SMT: Disabled                                        │   │
│  │ Network: Yes                                         │   │
│  │ Multi-user: Yes                                      │   │
│  │ Handoff: Cryptographic                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BALANCED:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Primary use: General personal workstations           │   │
│  │ RTRO: Optional (build flag)                          │   │
│  │ Weights: 3:1:1 (default, configurable)               │   │
│  │ Anti-starvation: Yes (100ms default)                 │   │
│  │ Full fairness: Not compiled                          │   │
│  │ SMT: Disabled by default (user may enable)           │   │
│  │ Network: Yes                                         │   │
│  │ Multi-user: Optional                                 │   │
│  │ Handoff: Cryptographic                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PERFORMANCE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Primary use: Limited hardware, offline systems       │   │
│  │ RTRO: Not compiled                                   │   │
│  │ Weights: 5:2:1 (default, configurable)               │   │
│  │ Anti-starvation: Yes (50ms default)                  │   │
│  │ Full fairness: Yes                                   │   │
│  │ SMT: Enabled                                         │   │
│  │ Network: Optional                                    │   │
│  │ Multi-user: No                                       │   │
│  │ Handoff: Cryptographic                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  COMPUTE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Primary use: Air-gapped computation                  │   │
│  │ RTRO: Not compiled                                   │   │
│  │ Weights: Equal or per-lane (application-controlled)  │   │
│  │ Anti-starvation: Optional                            │   │
│  │ Full fairness: Optional                              │   │
│  │ SMT: Enabled                                         │   │
│  │ Network: No                                          │   │
│  │ Multi-user: No                                       │   │
│  │ Handoff: Lightweight                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Hardware Requirements

```
HARDWARE REQUIREMENTS BY PROFILE:

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  MAXIMUM ISOLATION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 2 cores, 4 GB RAM, 20 GB storage           │   │
│  │ Recommended: 4+ cores, 8+ GB RAM, SSD               │   │
│  │ Reason: Equal weights create contention             │   │
│  │          Need hardware headroom for fairness         │   │
│  │          SMT disabled reduces execution contexts     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BALANCED:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 2 GB RAM, 10 GB storage            │   │
│  │ Recommended: 2+ cores, 4+ GB RAM, SSD               │   │
│  │ Reason: Weighted scheduling reduces contention      │   │
│  │          Anti-starvation ensures fairness           │   │
│  │          SMT can be enabled if needed               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PERFORMANCE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 1 GB RAM, 5 GB storage             │   │
│  │ Recommended: 2+ cores, 2+ GB RAM, any storage       │   │
│  │ Reason: Designed for limited hardware               │   │
│  │          Full fairness guarantees progress          │   │
│  │          SMT enabled maximizes throughput            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  COMPUTE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 128 MB RAM, any storage            │   │
│  │ Recommended: 2+ cores, 1+ GB RAM, fast storage      │   │
│  │ Reason: Minimal overhead for computation            │   │
│  │          Scales with workload, not profile           │   │
│  │          SMT enabled for max parallelism            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Execution Context Planning

```
EXECUTION CONTEXT PLANNING:

┌─────────────────────────────────────────────────────────────┐
│              UNDERSTANDING EXECUTION CONTEXTS                │
│                                                             │
│  EXECUTION CONTEXTS = PHYSICAL CORES × SMT FACTOR           │
│                                                             │
│  Examples:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 4 cores, no SMT:     4 execution contexts          │   │
│  │ 4 cores, 2-way SMT:   8 execution contexts          │   │
│  │ 8 cores, 2-way SMT:   16 execution contexts         │   │
│  │ 8 cores, 4-way SMT:   32 execution contexts         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  WHY THIS MATTERS:                                          │
│                                                             │
│  When Ready Pool has N events and C execution contexts:     │
│                                                             │
│  - If N ≤ C: ALL N events dispatch simultaneously          │
│    No weighted entropy needed                              │
│    Maximum throughput                                       │
│                                                             │
│  - If N > C: Weighted entropy selects C events             │
│    Remaining N-C events stay in Ready Pool                  │
│    Selection determined by weights                         │
│                                                             │
│  IMPLICATION:                                               │
│  More execution contexts = less competition =               │
│  less weight influence = more simultaneous execution        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 2: Building and Installation

### Build Prerequisites

```
BUILD PREREQUISITES:

┌─────────────────────────────────────────────────────────────┐
│                    REQUIREMENTS                              │
│                                                             │
│  SOFTWARE:                                                  │
│  - Rust toolchain (stable with nightly features)            │
│  - Cross-compilation targets for target architectures      │
│  - Linker scripts for target hardware                      │
│  - Signing tool for configuration files                    │
│                                                             │
│  HARDWARE:                                                  │
│  - Target hardware or emulator (QEMU supported)            │
│  - Boot media (USB, SD card, or direct flash)              │
│                                                             │
│  KEYS:                                                      │
│  - Ed25519 key pair for config signing                     │
│  - Public key embedded at build time                       │
│  - Private key for signing configs                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Build Commands

```
BUILD COMMANDS:

┌─────────────────────────────────────────────────────────────┐
│                    BUILD PROCESS                             │
│                                                             │
│  BUILD SPECIFIC PROFILE:                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ # Maximum Isolation                                  │   │
│  │ cargo build --profile maximum-isolation             │   │
│  │                                                      │   │
│  │ # Balanced                                           │   │
│  │ cargo build --profile balanced                      │   │
│  │                                                      │   │
│  │ # Performance                                        │   │
│  │ cargo build --profile performance                   │   │
│  │                                                      │   │
│  │ # Compute                                            │   │
│  │ cargo build --profile compute                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BUILD FOR SPECIFIC ARCHITECTURE:                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ # x86_64                                             │   │
│  │ cargo build --target x86_64-unknown-none            │   │
│  │                                                      │   │
│  │ # ARM64                                              │   │
│  │ cargo build --target aarch64-unknown-none           │   │
│  │                                                      │   │
│  │ # RISC-V                                             │   │
│  │ cargo build --target riscv64-unknown-none           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CUSTOM FEATURE COMBINATION:                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ cargo build --no-default-features \                 │   │
│  │   --features "anti-starvation,network-stack,gui"    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  VERIFY BUILD:                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ cargo run --package builder -- \                     │   │
│  │   --verify-features --binary target/firmware.bin     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Installation Media Creation

```
INSTALLATION MEDIA:

┌─────────────────────────────────────────────────────────────┐
│                  INSTALLATION PROCESS                        │
│                                                             │
│  CREATE BOOT MEDIA:                                        │
│  1. Format USB as FAT32                                    │
│  2. Copy CIBIOS firmware image                             │
│  3. Copy CIBOS kernel                                      │
│  4. Copy configuration (if needed)                         │
│  5. Copy signature (Standard profile)                      │
│                                                             │
│  DIRECTORY STRUCTURE:                                       │
│  /boot/                                                     │
│    ├── cibios.bin                                          │
│    ├── cibos-kernel                                        │
│    ├── cibos.conf                                          │
│    └── cibos.sig                                           │
│                                                             │
│  FLASH TO DEVICE:                                           │
│  - Use device-specific flashing tool                       │
│  - Or boot from USB for testing                            │
│                                                             │
│  VERIFY INSTALLATION:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ # Verify files present                               │   │
│  │ ls -la /boot/                                        │   │
│  │                                                      │   │
│  │ # Verify signature (if applicable)                   │   │
│  │ cibos-verify --config cibos.conf --sig cibos.sig    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 3: Configuration Management

### Configuration File

```
CONFIGURATION FILE:

┌─────────────────────────────────────────────────────────────┐
│                 /boot/cibos.conf                             │
│                                                             │
│  [scheduling]                                               │
│  # Weights control selection probability                    │
│  # Only apply when competition exists                       │
│  # (more ready events than execution contexts)              │
│  system_weight = 3        # System components               │
│  user_weight = 1          # User applications               │
│  background_weight = 1    # Background tasks                │
│                                                             │
│  # Anti-starvation threshold (milliseconds)                 │
│  # Only effective if compiled in                           │
│  # Balanced and Performance profiles only                   │
│  anti_starvation_threshold_ms = 100                         │
│                                                             │
│  [resources]                                                │
│  # Per-container memory limit (MB)                          │
│  memory_limit_mb = 512                                      │
│                                                             │
│  # I/O bandwidth limit (MB/s)                               │
│  io_bandwidth_mbps = 100                                    │
│                                                             │
│  [channels]                                                 │
│  max_channels_per_container = 16                            │
│  message_queue_size = 256                                   │
│                                                             │
│  [signature]                                                │
│  algorithm = "ed25519"                                      │
│  signature = "<base64>"                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Understanding Weight Application

```
WHEN WEIGHTS MATTER:

┌─────────────────────────────────────────────────────────────┐
│              WEIGHT APPLICATION RULES                        │
│                                                             │
│  WEIGHTS ONLY APPLY WHEN COMPETITION EXISTS                │
│                                                             │
│  Competition = More ready events than execution contexts    │
│                                                             │
│  EXAMPLE 1: No Competition                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Ready Pool: 3 events                                │   │
│  │ Available execution contexts: 8                     │   │
│  │                                                     │   │
│  │ Result: All 3 events dispatch simultaneously       │   │
│  │ Weight values: IRRELEVANT                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  EXAMPLE 2: Competition Exists                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Ready Pool: 10 events                               │   │
│  │ Available execution contexts: 4                     │   │
│  │                                                     │   │
│  │ Result: Weighted entropy selects 4 events           │   │
│  │ Weight values: DETERMINE SELECTION                  │   │
│  │ Remaining 6 stay in Ready Pool                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  IMPLICATION:                                               │
│  On systems with many cores and low load,                   │
│  weight configuration has minimal effect.                   │
│  Weight tuning is most important on:                        │
│  - Limited hardware (few execution contexts)                │
│  - High load (many ready events)                           │
│  - Maximum Isolation (equal weights required)               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Signing Configuration

```
SIGNING CONFIGURATION:

┌─────────────────────────────────────────────────────────────┐
│                  SIGNING PROCESS                             │
│                                                             │
│  GENERATE KEYS:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ cibos-keygen --output /path/to/keys                 │   │
│  │                                                      │   │
│  │ Creates:                                             │   │
│  │   /path/to/keys/signing.key (private)               │   │
│  │   /path/to/keys/verifying.key (public)              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  SIGN CONFIGURATION:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ cibos-sign \                                         │   │
│  │   --config /boot/cibos.conf \                       │   │
│  │   --key /path/to/keys/signing.key \                 │   │
│  │   --output /boot/cibos.sig                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  VERIFY SIGNATURE:                                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ cibos-verify \                                       │   │
│  │   --config /boot/cibos.conf \                       │   │
│  │   --sig /boot/cibos.sig \                           │   │
│  │   --key /path/to/keys/verifying.key                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  KEY MANAGEMENT:                                            │
│  - Public key embedded in CIBIOS at build time             │
│  - Private key never stored on deployed system             │
│  - Rotate keys periodically                                │
│  - Rebuild CIBIOS to embed new public key                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### What Happens Without Valid Configuration

```
CONFIGURATION FALLBACK:

┌─────────────────────────────────────────────────────────────┐
│                  FALLBACK BEHAVIOR                           │
│                                                             │
│  IF CONFIG FILE MISSING:                                    │
│  └─► System uses compiled defaults                         │
│      └─► Boot proceeds normally                            │
│                                                             │
│  IF CONFIG SIGNATURE INVALID:                               │
│  └─► System uses compiled defaults                         │
│      └─► Warning logged                                    │
│      └─► Boot proceeds normally                            │
│                                                             │
│  COMPILED DEFAULTS BY PROFILE:                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Maximum Isolation:                                  │   │
│  │   system_weight = 1                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  │                                                     │   │
│  │ Balanced:                                            │   │
│  │   system_weight = 3                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation_threshold_ms = 100                │   │
│  │                                                     │   │
│  │ Performance:                                         │   │
│  │   system_weight = 5                                 │   │
│  │   user_weight = 2                                   │   │
│  │   background_weight = 1                             │   │
│  │   anti_starvation_threshold_ms = 50                 │   │
│  │                                                     │   │
│  │ Compute:                                             │   │
│  │   system_weight = 1                                 │   │
│  │   user_weight = 1                                   │   │
│  │   background_weight = 1                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  IMPORTANT: Absent or invalid config is NOT an error         │
│            System remains operational                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 4: SMT Configuration

### Understanding SMT in CIBOS

```
SMT OVERVIEW:

┌─────────────────────────────────────────────────────────────┐
│                 SMT IN CIBOS                                 │
│                                                             │
│  SMT (Simultaneous Multithreading) is configured by CIBIOS   │
│  at boot before CIBOS receives control.                     │
│                                                             │
│  CIBOS inherits the SMT state from CIBIOS.                  │
│                                                             │
│  EXECUTION CONTEXTS:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                                                     │   │
│  │  Without SMT:                                       │   │
│  │  Physical Cores = Execution Contexts                │   │
│  │  4 cores = 4 simultaneous events                    │   │
│  │                                                     │   │
│  │  With 2-way SMT:                                    │   │
│  │  Execution Contexts = Physical Cores × 2            │   │
│  │  4 cores = 8 simultaneous events                    │   │
│  │                                                     │   │
│  │  With 4-way SMT:                                    │   │
│  │  Execution Contexts = Physical Cores × 4            │   │
│  │  4 cores = 16 simultaneous events                   │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### SMT by Profile

```
SMT CONFIGURATION BY PROFILE:

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  MAXIMUM ISOLATION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SMT: DISABLED                                        │   │
│  │ Reason: Eliminate hardware side channels            │   │
│  │ Trade-off: Fewer execution contexts                 │   │
│  │           Acceptable for security priority           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BALANCED:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SMT: DISABLED by default (user may enable)           │   │
│  │ Reason: Security-conscious default                  │   │
│  │ Note: User can enable if threat model permits       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PERFORMANCE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SMT: ENABLED                                         │   │
│  │ Reason: Maximize throughput on limited hardware     │   │
│  │ Trade-off: Hardware side channels present           │   │
│  │           Acceptable for non-adversarial use         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  COMPUTE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SMT: ENABLED                                         │   │
│  │ Reason: Maximum parallel computation                │   │
│  │ Trade-off: Hardware side channels present           │   │
│  │           Acceptable for air-gapped environment      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why SMT Doesn't Create Traditional Bottlenecks

```
SMT IN CIBOS vs TRADITIONAL SYSTEMS:

┌─────────────────────────────────────────────────────────────┐
│           WHY SMT IS DIFFERENT IN CIBOS                      │
│                                                             │
│  TRADITIONAL SYSTEMS WITH SMT:                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Problems:                                            │   │
│  │ - Thread contention for locks                        │   │
│  │ - Cache thrashing from shared state                  │   │
│  │ - Time-slice serialization                           │   │
│  │ - Observable contention patterns                     │   │
│  │                                                     │   │
│  │ Result: SMT often degrades performance              │   │
│  │         under high load                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CIBOS WITH SMT:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ No locks: No thread contention                      │   │
│  │ Isolated memory: No cache thrashing (intentional)   │   │
│  │ Event-driven: No time-slicing                       │   │
│  │ No shared state: No contention patterns            │   │
│  │                                                     │   │
│  │ Result: SMT provides additional execution          │   │
│  │         contexts without software overhead          │   │
│  │                                                     │   │
│  │ Only hardware-level sharing remains:               │   │
│  │ - L1/L2 cache sharing between logical cores         │   │
│  │ - Execution unit sharing                            │   │
│  │ - This is the ONLY overhead                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CONCLUSION:                                                │
│  SMT in CIBOS adds capacity without adding contention.      │
│  The hardware-level side channels are the only              │
│  security consideration.                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Changing SMT Configuration

SMT is determined at build time by profile selection. To change:
1. Select a different profile, or
2. Build with custom feature flag override
3. Rebuild CIBIOS and CIBOS
4. Flash new CIBIOS firmware
5. System boots with new SMT configuration

---

## Chapter 5: Weight Tuning

### Understanding Weight Impact

```
WEIGHT IMPACT:

┌─────────────────────────────────────────────────────────────┐
│                  WEIGHT SELECTION PROBABILITY                │
│                                                             │
│  REMEMBER: Weights only apply when competition exists       │
│                                                             │
│  EXAMPLE: system_weight=3, user_weight=1, bg_weight=1       │
│                                                             │
│  Ready Pool has 10 events, 4 execution contexts:            │
│    2 system events (weight 3 each = 6 tickets)              │
│    5 user events (weight 1 each = 5 tickets)                │
│    3 background events (weight 1 each = 3 tickets)          │
│                                                             │
│  Total: 14 tickets                                          │
│                                                             │
│  Selection probabilities (per event):                       │
│    Each system event: 3/14 ≈ 21%                           │
│    Each user event: 1/14 ≈ 7%                              │
│    Each background event: 1/14 ≈ 7%                         │
│                                                             │
│  Collective probabilities:                                  │
│    System events: 6/14 ≈ 43%                               │
│    User events: 5/14 ≈ 36%                                 │
│    Background events: 3/14 ≈ 21%                            │
│                                                             │
│  BUT if only 3 events ready and 8 contexts:                 │
│    All 3 dispatch simultaneously                           │
│    Weights irrelevant                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Tuning Guidelines

```
TUNING GUIDELINES:

┌─────────────────────────────────────────────────────────────┐
│                    TUNING GUIDE                              │
│                                                             │
│  UI LAGGING UNDER LOAD:                                     │
│  Problem: Window manager, input handler slow                │
│  Solution: Increase system_weight                           │
│  Example: system_weight = 5                                 │
│  Note: Only helps when competition exists                   │
│                                                             │
│  BACKGROUND TASKS NEVER COMPLETE:                           │
│  Problem: Low-weight events starved                         │
│  Solution: Enable anti-starvation or increase weight        │
│  Example: background_weight = 2                             │
│  Alternative: Reduce anti_starvation_threshold_ms           │
│                                                             │
│  UNPREDICTABLE PERFORMANCE:                                 │
│  Problem: Too much entropy in selection                     │
│  Solution: Use more differentiated weights                  │
│  Example: system=5, user=2, background=1                    │
│                                                             │
│  TOO PREDICTABLE (for Maximum Isolation):                  │
│  Problem: Weights not equal                                 │
│  Solution: All weights = 1                                  │
│  Example: system=1, user=1, background=1                    │
│  Note: REQUIRED for Maximum Isolation                       │
│                                                             │
│  ANTI-STARVATION FIRING TOO OFTEN:                          │
│  Problem: Threshold too low                                 │
│  Solution: Increase threshold                               │
│  Example: anti_starvation_threshold_ms = 200                │
│                                                             │
│  ANTI-STARVATION NEVER FIRES:                               │
│  Problem: Threshold too high                                │
│  Solution: Lower threshold                                  │
│  Example: anti_starvation_threshold_ms = 50                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Weight Tuning by Profile

```
PROFILE-SPECIFIC TUNING:

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  MAXIMUM ISOLATION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ DO NOT TUNE WEIGHTS                                  │   │
│  │                                                     │   │
│  │ All weights must remain equal (1:1:1)               │   │
│  │ Unequal weights create observable patterns          │   │
│  │ This is a SECURITY REQUIREMENT                      │   │
│  │                                                     │   │
│  │ Exception: Only change if you have analyzed         │   │
│  │ the security implications                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BALANCED:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Default 3:1:1 is good for most workloads           │   │
│  │                                                     │   │
│  │ If UI feels sluggish:                               │   │
│  │   Increase system_weight to 4 or 5                  │   │
│  │                                                     │   │
│  │ If background tasks stall:                          │   │
│  │   Check anti_starvation_threshold                   │   │
│  │   Or increase background_weight to 2               │   │
│  │                                                     │   │
│  │ For compute-heavy workloads:                        │   │
│  │   Reduce system_weight to 2                         │   │
│  │   Accept slightly slower UI                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PERFORMANCE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Default 5:2:1 for limited hardware                  │   │
│  │                                                     │   │
│  │ Very limited (2 cores, 2GB):                        │   │
│  │   system_weight = 7, user = 3, bg = 1              │   │
│  │                                                     │   │
│  │ Moderate hardware (4 cores, 4GB):                   │   │
│  │   system_weight = 4, user = 2, bg = 1              │   │
│  │                                                     │   │
│  │ Full fairness ensures all lanes get time            │   │
│  │ Adjust weights for responsiveness preference        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  COMPUTE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ For fire-and-wait: equal weights (1:1:1)            │   │
│  │ Maximize entropy, minimize predictability           │   │
│  │                                                     │   │
│  │ For interactive monitoring:                         │   │
│  │   system_weight = 2 (CLI responsive)               │   │
│  │   user_weight = 1 (compute lanes)                  │   │
│  │                                                     │   │
│  │ Per-lane weights available for applications         │   │
│  │ Tune within application, not system config          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Tuning Process

1. Start with profile defaults
2. Run representative workloads
3. Observe which components feel slow or unresponsive
4. Adjust weights incrementally (change by 1 at a time)
5. Re-run workloads and observe change
6. Sign new configuration file and deploy
7. Monitor for unintended effects

---

## Chapter 6: Resource Management

### Memory Limits

```
MEMORY MANAGEMENT:

┌─────────────────────────────────────────────────────────────┐
│                   MEMORY LIMITS                              │
│                                                             │
│  SETTING LIMITS:                                            │
│  memory_limit_mb = 512                                       │
│                                                             │
│  WHAT THIS MEANS:                                           │
│  - Container can allocate up to 512 MB                      │
│  - Allocation above limit causes stall                      │
│  - Stall resolves when memory freed within container        │
│  - NOT an OOM crash - container waits invisibly             │
│                                                             │
│  CHOOSING VALUES:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Browser containers: 512-2048 MB                      │   │
│  │ Office applications: 128-512 MB                      │   │
│  │ System services: 64-256 MB                           │   │
│  │ Compute containers: Match workload dataset size      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MONITORING:                                                │
│  cibos-ctl memory --container <id>                          │
│  Shows:                                                     │
│    - Current usage                                          │
│    - Limit                                                  │
│    - Stalled allocations                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Channel Limits

```
CHANNEL MANAGEMENT:

┌─────────────────────────────────────────────────────────────┐
│                   CHANNEL LIMITS                             │
│                                                             │
│  SETTING LIMITS:                                            │
│  max_channels_per_container = 16                            │
│  message_queue_size = 256                                   │
│                                                             │
│  WHAT THIS MEANS:                                           │
│  - Container can have up to 16 channels                     │
│  - Each channel holds up to 256 pending messages            │
│  - Sending to full channel causes stall                     │
│  - Receiving from empty channel causes stall                │
│                                                             │
│  CHOOSING VALUES:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Most applications: 8-16 channels                     │   │
│  │ Complex pipelines: 32-64 channels                    │   │
│  │ Message queue: 64-256 depending on throughput       │   │
│  │ High-throughput: 512+                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MONITORING:                                                │
│  cibos-ctl channels --container <id>                        │
│  Shows:                                                     │
│    - Active channels                                        │
│    - Pending messages                                       │
│    - Stalled senders/receivers                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Understanding Stalls

```
UNDERSTANDING STALLS:

┌─────────────────────────────────────────────────────────────┐
│                    STALL BEHAVIOR                            │
│                                                             │
│  WHAT STALLS ARE:                                           │
│  - Container cannot proceed until resource available        │
│  - NOT an error condition                                  │
│  - No retry loops, no polling                              │
│  - Kernel tracks dependency                                 │
│  - Container resumes when resource available                │
│                                                             │
│  COMMON STALL CAUSES:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Memory:                                              │   │
│  │   Container limit exceeded                          │   │
│  │   Solution: Free memory or increase limit           │   │
│  │                                                     │   │
│  │ Channel buffer:                                      │   │
│  │   Send to full buffer                               │   │
│  │   Solution: Receiver reads from buffer               │   │
│  │                                                     │   │
│  │ Channel data:                                        │   │
│  │   Receive from empty buffer                          │   │
│  │   Solution: Sender writes to buffer                  │   │
│  │                                                     │   │
│  │ I/O:                                                 │   │
│  │   Disk or network operation pending                 │   │
│  │   Solution: Wait for completion                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MULTI-RESOURCE STALLS:                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Container may need multiple resources               │   │
│  │ All must be available before moving to Ready Pool   │   │
│  │ Example: Needs memory AND channel buffer            │   │
│  │   Memory freed but buffer still full               │   │
│  │   Container stays in Stalled List                   │   │
│  │   Moved to Ready Pool only when BOTH available     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 7: Monitoring and Diagnostics

### System Status

```
MONITORING COMMANDS:

┌─────────────────────────────────────────────────────────────┐
│                  MONITORING                                  │
│                                                             │
│  SCHEDULER STATUS:                                          │
│  cibos-ctl scheduler                                        │
│  Output:                                                    │
│    Ready Pool: 15 events                                    │
│    Stalled List: 3 containers                               │
│    Cores: 4 (2 busy, 2 available)                          │
│    Entropy source: hardware RNG                             │
│    SMT: Disabled                                            │
│    Execution Contexts: 4                                    │
│                                                             │
│  DISPATCH STATISTICS:                                       │
│  cibos-ctl scheduler --stats                                │
│  Output:                                                    │
│    Dispatch Opportunities: 1,245,832                        │
│    No-competition dispatches: 1,112,456 (89.3%)            │
│    Competition dispatches: 133,376 (10.7%)                  │
│    Average events per dispatch: 3.8                         │
│    Max simultaneous dispatches: 8                           │
│                                                             │
│  MEMORY STATUS:                                             │
│  cibos-ctl memory                                           │
│  Output:                                                    │
│    Total: 8192 MB                                           │
│    Used: 4521 MB                                            │
│    Available: 3671 MB                                       │
│    Top consumers:                                           │
│      container-a: 1024 MB                                   │
│      container-b: 512 MB                                    │
│                                                             │
│  CONTAINER STATUS:                                          │
│  cibos-ctl containers                                       │
│  Output:                                                    │
│    container-a: RUNNING (2 lanes active)                    │
│    container-b: STALLED (waiting: memory)                   │
│    container-c: INACTIVE                                    │
│                                                             │
│  CHANNEL STATUS:                                            │
│  cibos-ctl channels                                         │
│  Output:                                                    │
│    Total channels: 24                                        │
│    Pending messages: 156                                    │
│    Stalled senders: 2                                       │
│    Stalled receivers: 1                                      │
│                                                             │
│  EXECUTION CONTEXTS:                                        │
│  cibos-ctl cores                                            │
│  Output:                                                    │
│    Physical Cores: 4                                         │
│    SMT Factor: 2x (enabled)                                 │
│    Logical Cores: 8                                          │
│    Busy: 6                                                  │
│    Available: 2                                              │
│    Last-container affinity hits: 78%                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Dispatch Efficiency Monitoring

```
DISPATCH EFFICIENCY:

┌─────────────────────────────────────────────────────────────┐
│              DISPATCH EFFICIENCY                              │
│                                                             │
│  CIBOS dispatches multiple events simultaneously            │
│  when no competition exists.                                │
│                                                             │
│  INTERPRETING STATS:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                                                     │   │
│  │ High no-competition % (> 80%):                      │   │
│  │   System has sufficient resources                   │   │
│  │   Weights have minimal effect                      │   │
│  │   System handling load well                         │   │
│  │                                                     │   │
│  │ High competition % (> 30%):                         │   │
│  │   System under heavy load                           │   │
│  │   Weights significantly influence selection        │   │
│  │   Consider more execution contexts                  │   │
│  │   Or reduce number of ready events                  │   │
│  │                                                     │   │
│  │ Low events per dispatch:                            │   │
│  │   Most dispatches are 1-2 events                   │   │
│  │   Either many small events or high competition     │   │
│  │                                                     │   │
│  │ Max simultaneous = execution context count:         │   │
│  │   This is expected                                 │   │
│  │   System using all available contexts              │   │
│  │                                                     │   │
│  │ Max simultaneous < execution context count:         │   │
│  │   Either light load                                │   │
│  │   Or resource constraints limiting dispatch         │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Diagnosing Problems

```
DIAGNOSTICS:

┌─────────────────────────────────────────────────────────────┐
│                    DIAGNOSTICS                               │
│                                                             │
│  UNRESPONSIVE SYSTEM:                                       │
│  1. Check Ready Pool size                                  │
│     cibos-ctl scheduler --ready-pool                        │
│     If empty, check Stalled List                           │
│                                                             │
│  2. Check Stalled List                                     │
│     cibos-ctl scheduler --stalled                           │
│     Identify what resources are waited for                  │
│                                                             │
│  3. Check resource availability                            │
│     cibos-ctl resources                                     │
│     Verify resources are being released                     │
│                                                             │
│  4. Check execution contexts                               │
│     cibos-ctl cores                                         │
│     Verify contexts are available                           │
│                                                             │
│  CONTAINER STALLED:                                         │
│  1. Check what resource                                    │
│     cibos-ctl diagnose --container <id>                     │
│                                                             │
│  2. Check if resource can be freed                         │
│     - Memory: Reduce container's usage                      │
│     - Channel: Clear buffers                                │
│     - I/O: Wait for completion                              │
│                                                             │
│  3. Check for multi-resource stall                         │
│     Container may need multiple resources                   │
│     All must be available before moving to Ready Pool      │
│                                                             │
│  PERFORMANCE PROBLEMS:                                      │
│  1. Check weight distribution                              │
│  2. Check anti-starvation firing frequency                 │
│  3. Check core utilization                                 │
│  4. Check Ready Pool depth                                 │
│  5. Check dispatch statistics                              │
│                                                             │
│  SLOW BACKGROUND TASKS:                                     │
│  1. Check if competition is frequent                       │
│     If yes, weights matter                                 │
│     If no, other issue                                     │
│  2. Check anti-starvation threshold                        │
│ 3. Check for resource constraints                          │
│ 4. Verify background_weight > 0                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 8: Security Operations

### Key Management

```
KEY MANAGEMENT:

┌─────────────────────────────────────────────────────────────┐
│                   KEY MANAGEMENT                             │
│                                                             │
│  KEY GENERATION:                                           │
│  cibos-keygen --output /secure/keys                        │
│                                                             │
│  KEY STORAGE:                                               │
│  - Private key: Offline, air-gapped                        │
│  - Public key: Embedded in CIBIOS                          │
│  - Backup: Encrypted offline storage                       │
│                                                             │
│  KEY ROTATION:                                              │
│  1. Generate new key pair                                  │
│  2. Build new CIBIOS with new public key                   │
│  3. Re-sign all configurations                             │
│  4. Deploy new CIBIOS                                      │
│  5. Deploy new configurations                              │
│  6. Retire old keys                                        │
│                                                             │
│  KEY SECURITY:                                              │
│  - Never store private key on deployed system               │
│  - Use hardware security module for signing                │
│  - Audit key usage                                         │
│  - Implement key escrow for recovery                       │
│                                                             │
│  KEY ROTATION SCHEDULE:                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Maximum Isolation: Every 90 days                    │   │
│  │ Balanced: Every 180 days                            │   │
│  │ Performance: Every 365 days                         │   │
│  │ Compute: Before each major deployment               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Security

```
CONFIGURATION SECURITY:

┌─────────────────────────────────────────────────────────────┐
│              CONFIGURATION SECURITY                          │
│                                                             │
│  SIGNING REQUIREMENTS:                                      │
│  - All profiles accept signed config                        │
│  - Standard profile: Required                               │
│  - Lightweight profile: Optional (physical security)        │
│                                                             │
│  VERIFICATION:                                              │
│  - CIBIOS verifies signature at boot                        │
│  - Invalid signature → compiled defaults                    │
│  - Missing file → compiled defaults                         │
│                                                             │
│  TAMPER DETECTION:                                          │
│  - Signature verification detects modification             │
│  - Boot fails if verification fails (Standard)             │
│  - Warning logged if verification fails (Lightweight)       │
│                                                             │
│  AUDIT TRAIL:                                               │
│  - Log all config load attempts                             │
│  - Log signature verification results                       │
│  - Log which config source used                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 9: Troubleshooting

### Common Issues

```
TROUBLESHOOTING:

┌─────────────────────────────────────────────────────────────┐
│                    COMMON ISSUES                             │
│                                                             │
│  BOOT FAILS - SIGNATURE ERROR:                              │
│  Cause: Config signature invalid                           │
│  Check: cibos-verify --config --sig --key                   │
│  Fix: Re-sign configuration                                 │
│                                                             │
│  SYSTEM UNRESPONSIVE:                                       │
│  Cause: Ready Pool empty, Stalled List full                │
│  Check: cibos-ctl scheduler --all                           │
│  Fix: Identify stalled resource, release                    │
│                                                             │
│  CONTAINER NEVER EXECUTES:                                  │
│  Cause: Weight too low or anti-starvation off               │
│  Check: cibos-ctl container <id> --stats                    │
│  Fix: Increase weight or enable anti-starvation             │
│                                                             │
│  MEMORY ALLOCATION FAILS:                                   │
│  Cause: Container limit reached                            │
│  Check: cibos-ctl memory --container <id>                   │
│  Fix: Increase limit or reduce usage                        │
│                                                             │
│  CHANNEL STALLED:                                           │
│  Cause: Buffer full or empty                               │
│  Check: cibos-ctl channels --container <id>                 │
│  Fix: Clear buffers, check receiver/sender                  │
│                                                             │
│  PERFORMANCE DEGRADES UNDER LOAD:                           │
│  Cause: Competition exceeds capacity                        │
│  Check: Dispatch statistics                                │
│  Fix: Add execution contexts, tune weights                  │
│                                                             │
│  SMT SIDE CHANNELS (Performance/Compute only):              │
│  Cause: Hardware cache sharing                             │
│  Check: cibos-ctl cores (SMT enabled)                      │
│  Fix: Accept (threat model permits) or disable SMT          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Recovery Procedures

```
RECOVERY:

┌─────────────────────────────────────────────────────────────┐
│                    RECOVERY                                  │
│                                                             │
│  SYSTEM HANG:                                               │
│  1. Check selector thread status                           │
│  2. Check Ready Pool state                                 │
│  3. Check Stalled List state                               │
│  4. Force resource signal                                  │
│  5. Last resort: reboot                                    │
│                                                             │
│  MEMORY EXHAUSTION:                                         │
│  1. Identify consuming container                           │
│  2. Reduce container limit                                 │
│  3. Restart container                                      │
│  4. Check for leak                                         │
│                                                             │
│  CHANNEL DEADLOCK:                                          │
│  1. Identify blocked containers                            │
│  2. Check channel buffer states                            │
│  3. Clear buffers                                          │
│  4. Restart affected containers                            │
│                                                             │
│  CONFIGURATION RECOVERY:                                    │
│  1. Remove invalid config file                             │
│  2. System uses compiled defaults                          │
│  3. Create new signed config                               │
│  4. Deploy and reboot                                      │
│                                                             │
│  FIRMWARE RECOVERY:                                         │
│  1. Boot from recovery media                              │
│  2. Flash known-good CIBIOS                                │
│ 3. Flash known-good CIBOS                                  │
│  4. Deploy known-good config                               │
│  5. Reboot                                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 10: Compute Profile Operations

### Compute-Specific Configuration

```
COMPUTE PROFILE OPERATIONS:

┌─────────────────────────────────────────────────────────────┐
│                 COMPUTE PROFILE                              │
│                                                             │
│  LIGHTWEIGHT HANDSHAKE:                                     │
│  - No cryptographic verification                           │
│  - Physical security required                              │
│  - Config signing optional                                 │
│                                                             │
│  PER-LANE WEIGHTS:                                          │
│  - Container controls weights                              │
│  - System does not assign weights                          │
│  - Configure in application code                           │
│                                                             │
│  TYPICAL CONFIGURATION:                                     │
│  [scheduling]                                               │
│  system_weight = 1  # CLI priority option: 2               │
│  user_weight = 1                                            │
│  background_weight = 1                                      │
│                                                             │
│  [resources]                                                │
│  memory_limit_mb = 2048  # Match workload                  │
│                                                             │
│  ANTI-STARVATION:                                           │
│  - Optional (compile flag)                                  │
│  - Recommended for most workloads                           │
│  - Disable for pure parallel computation                   │
│                                                             │
│  CLI PRIORITY CONFIGURATION:                                │
│  If interactive monitoring needed:                          │
│  system_weight = 2  # CLI responsive                       │
│  user_weight = 1  # Compute lanes                          │
│                                                             │
│  UNSIGNED CONFIG (acceptable in air-gapped):                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ # /boot/cibos.conf (unsigned)                       │   │
│  │ [scheduling]                                        │   │
│  │ system_weight = 1                                   │   │
│  │ user_weight = 1                                     │   │
│  │ background_weight = 1                               │   │
│  │                                                     │   │
│  │ [resources]                                         │   │
│  │ memory_limit_mb = 2048                              │   │
│  │                                                     │   │
│  │ # No signature section                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Monitoring Compute Workloads

```
COMPUTE MONITORING:

┌─────────────────────────────────────────────────────────────┐
│                 COMPUTE MONITORING                           │
│                                                             │
│  LANE STATUS:                                               │
│  cibos-ctl lanes --container <id>                           │
│  Output:                                                    │
│    Lane 1: READY (weight=1, wait=50ms)                     │
│    Lane 2: EXECUTING (weight=1)                             │
│    Lane 3: STALLED (weight=1, waiting: I/O)                │
│    Lane 4: READY (weight=3, wait=10ms)  # High priority    │
│                                                             │
│  THROUGHPUT:                                                │
│  cibos-ctl throughput --container <id>                      │
│  Output:                                                    │
│    Events/sec: 12,450                                       │
│    Avg wait: 23ms                                           │
│    Max wait: 145ms                                          │
│    Anti-starvation rescues: 3                               │
│                                                             │
│  RESOURCE USAGE:                                            │
│  cibos-ctl resources --container <id>                       │
│  Output:                                                    │
│    Memory: 1024 / 2048 MB                                  │
│    I/O pending: 5 operations                                │
│    Channels: 8 active, 156 pending messages                 │
│                                                             │
│  EXECUTION CONTEXT UTILIZATION:                             │
│  cibos-ctl cores                                            │
│  Output:                                                    │
│    Physical Cores: 4                                         │
│    SMT Factor: 2x (enabled)                                 │
│    Logical Cores: 8                                          │
│    Busy: 8  # All cores active (good for compute)           │
│    Available: 0                                              │
│                                                             │
│  INTERPRETING COMPUTE STATS:                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ High events/sec: Good throughput                    │   │
│  │ Low avg wait: Minimal competition                   │   │
│  │ High max wait: Some lanes waited long              │   │
│  │ Anti-starvation rescues: Starvation occurred        │   │
│  │ All cores busy: System fully utilized              │   │
│  │ Cores available: More capacity than workload       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Per-Lane Weight Application

```
PER-LANE WEIGHTS (APPLICATION LEVEL):

┌─────────────────────────────────────────────────────────────┐
│               APPLICATION WEIGHT TUNING                      │
│                                                             │
│  In Compute profile, applications assign weights            │
│  to individual lanes at creation time.                      │
│                                                             │
│  GUIDELINES:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                                                     │   │
│  │ High-priority computation (weight 3-5):             │   │
│  │   - Primary algorithm execution                     │   │
│  │   - Time-sensitive computations                    │   │
│  │   - User-facing results                            │   │
│  │                                                     │   │
│  │ Normal priority (weight 1):                         │   │
│  │   - Standard computations                          │   │
│  │   - Peer computations                             │   │
│  │   - Parallel algorithm branches                    │   │
│  │                                                     │   │
│  │ Low priority (weight 1):                           │   │
│  │   - Cleanup tasks                                  │   │
│  │   - Logging/monitoring                             │   │
│  │   - Background aggregation                         │   │
│  │                                                     │   │
│  │ Equal weights:                                     │   │
│  │   - All lanes are peers                           │   │
│  │   - Fire-and-wait workflows                        │   │
│  │   - Maximum entropy selection                      │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MONITORING PER-LANE BEHAVIOR:                              │
│  cibos-ctl lanes --container <id> --show-weights            │
│                                                             │
│  Look for:                                                  │
│  - Lanes with high wait times                               │
│  - Weight imbalance effects                                 │
│  - Anti-starvation threshold appropriateness                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 11: Maintenance

### Updates

```
MAINTENANCE:

┌─────────────────────────────────────────────────────────────┐
│                    UPDATES                                   │
│                                                             │
│  FIRMWARE UPDATE:                                           │
│  1. Build new CIBIOS                                       │
│  2. Flash to device                                        │
│  3. Verify boot succeeds                                   │
│  4. Keep backup of previous version                        │
│                                                             │
│  KERNEL UPDATE:                                             │
│  1. Build new CIBOS                                        │
│  2. Copy to boot media                                     │
│  3. Update configuration if needed                         │
│  4. Re-sign if Standard profile                            │
│                                                             │
│  CONFIGURATION UPDATE:                                      │
│  1. Edit cibos.conf                                        │
│  2. Sign with cibos-sign                                   │
│  3. Copy to boot media                                     │
│  4. Reboot to apply                                        │
│                                                             │
│  ROLLBACK:                                                  │
│  Keep previous working:                                     │
│  - Previous CIBIOS image                                   │
│  - Previous CIBOS kernel                                   │
│  - Previous configuration                                  │
│  Restore if update fails                                   │
│                                                             │
│  UPDATE VERIFICATION:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Verify boot completes                           │   │
│  │ 2. Check version numbers                          │   │
│  │ 3. Verify expected features present                │   │
│  │ 4. Run acceptance tests                           │   │
│  │ 5. Monitor for 24 hours                           │   │
│  │ 6. Archive previous version                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Appendix: Configuration Reference

```toml
# Complete Configuration Reference

[scheduling]
# Weight values (positive integers)
# Maximum Isolation: all must be equal (1:1:1)
# Other profiles: configurable
system_weight = 3
user_weight = 1
background_weight = 1

# Anti-starvation threshold (milliseconds)
# Only effective if compiled in (Balanced, Performance)
# Set to 0 to disable
anti_starvation_threshold_ms = 100

[resources]
# Per-container memory limit (MB)
max_memory_per_container_mb = 512

# Total application memory percentage
max_total_application_memory_pct = 80

# Channel limits
max_channels_per_container = 32
max_pending_channel_requests = 8
channel_buffer_default_kb = 64

[security]
# Require hardware RNG
hardware_rng_required = true

[signature]
algorithm = "ed25519"
public_key = "<base64-encoded-public-key>"
signature = "<base64-encoded-signature>"
```

---

## Appendix: Quick Reference Commands

```
QUICK REFERENCE:

┌─────────────────────────────────────────────────────────────┐
│                    COMMON COMMANDS                           │
│                                                             │
│  System Status:                                             │
│  cibos-ctl scheduler        # Scheduler state               │
│  cibos-ctl cores            # Execution contexts           │
│  cibos-ctl memory           # Memory usage                 │
│  cibos-ctl containers       # Container states             │
│  cibos-ctl channels         # Channel states               │
│                                                             │
│  Diagnostics:                                               │
│  cibos-ctl diagnose --container <id>                        │
│  cibos-ctl scheduler --stats                                │
│  cibos-ctl lanes --container <id>                           │
│                                                             │
│  Configuration:                                             │
│  cibos-sign --config <file> --key <key> --output <sig>     │
│  cibos-verify --config <file> --sig <sig> --key <key>       │
│                                                             │
│  Build:                                                     │
│  cargo build --profile <profile>                            │
│  cargo run --package builder -- --verify-features           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

*This Administrator Guide covers deployment and operations for CIBIOS and CIBOS. For implementation details, see the Developer Guide. For writing applications, see the Application Developer Guide.*
