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
│  │                                                          │
│  ├─► Network-connected but no sophisticated adversary?      │
│  │   └─► Single user or small trusted group?                │
│  │       └─► Balanced Profile                               │
│  │                                                          │
│  ├─► Limited hardware?                                      │
│  │   └─► Responsiveness priority?                           │
│  │       └─► Performance Profile                            │
│  │                                                          │
│  ├─► Air-gapped system?                                     │
│  │   └─► Maximum computational throughput?                  │
│  │       └─► Compute Profile                                │
│  │                                                          │
│  └─► Unsure?                                                │
│      └─► Balanced Profile (safe default)                    │
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
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BALANCED:                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 2 GB RAM, 10 GB storage            │   │
│  │ Recommended: 2+ cores, 4+ GB RAM, SSD               │   │
│  │ Reason: Weighted scheduling reduces contention      │   │
│  │          Anti-starvation ensures fairness           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  PERFORMANCE:                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 1 GB RAM, 5 GB storage             │   │
│  │ Recommended: 2+ cores, 2+ GB RAM, any storage       │   │
│  │ Reason: Designed for limited hardware               │   │
│  │          Full fairness guarantees progress          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  COMPUTE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Minimum: 1 core, 128 MB RAM, any storage            │   │
│  │ Recommended: 2+ cores, 1+ GB RAM, fast storage      │   │
│  │ Reason: Minimal overhead for computation            │   │
│  │          Scales with workload, not profile           │   │
│  └─────────────────────────────────────────────────────┘   │
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
│  system_weight = 3        # System components               │
│  user_weight = 1          # User applications               │
│  background_weight = 1    # Background tasks                │
│                                                             │
│  # Anti-starvation threshold (milliseconds)                 │
│  # Only effective if compiled in                           │
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

---

## Chapter 4: Weight Tuning

### Understanding Weight Impact

```
WEIGHT IMPACT:

┌─────────────────────────────────────────────────────────────┐
│                  WEIGHT SELECTION PROBABILITY                │
│                                                             │
│  EXAMPLE: system_weight=3, user_weight=1, bg_weight=1       │
│                                                             │
│  Ready Pool has:                                            │
│    2 system events (weight 3 each = 6 tickets)              │
│    5 user events (weight 1 each = 5 tickets)                │
│    2 background events (weight 1 each = 2 tickets)          │
│                                                             │
│  Total: 13 tickets                                          │
│                                                             │
│  Selection probabilities:                                   │
│    Each system event: 3/13 ≈ 23%                           │
│    Each user event: 1/13 ≈ 8%                              │
│    Each background event: 1/13 ≈ 8%                         │
│                                                             │
│  System events collectively: 6/13 ≈ 46%                    │
│  User events collectively: 5/13 ≈ 38%                      │
│  Background events collectively: 2/13 ≈ 15%                 │
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
│                                                             │
│  BACKGROUND TASKS NEVER COMPLETE:                           │
│  Problem: Low-weight events starved                         │
│  Solution: Enable anti-starvation or increase weight        │
│  Example: background_weight = 2                             │
│                                                             │
│  UNPREDICTABLE PERFORMANCE:                                 │
│  Problem: Too much entropy                                  │
│  Solution: Use more differentiated weights                  │
│  Example: system=5, user=2, background=1                    │
│                                                             │
│  TOO PREDICTABLE (for Maximum Isolation):                  │
│  Problem: Weights not equal                                 │
│  Solution: All weights = 1                                  │
│  Example: system=1, user=1, background=1                    │
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

---

## Chapter 5: Resource Management

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
│                                                             │
│  CHOOSING VALUES:                                           │
│  - Browser containers: 512-2048 MB                          │
│  - Office applications: 128-512 MB                          │
│  - System services: 64-256 MB                               │
│  - Compute containers: Match workload dataset size          │
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
│                                                             │
│  CHOOSING VALUES:                                           │
│  - Most applications: 8-16 channels                         │
│  - Complex pipelines: 32-64 channels                        │
│  - Message queue: 64-256 depending on throughput            │
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

---

## Chapter 6: Monitoring and Diagnostics

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
│  CONTAINER STALLED:                                         │
│  1. Check what resource                                    │
│     cibos-ctl diagnose --container <id>                     │
│                                                             │
│  2. Check if resource can be freed                         │
│     - Memory: Reduce container's usage                      │
│     - Channel: Clear buffers                                │
│     - I/O: Wait for completion                              │
│                                                             │
│  PERFORMANCE PROBLEMS:                                      │
│  1. Check weight distribution                              │
│  2. Check anti-starvation firing frequency                 │
│  3. Check core utilization                                 │
│  4. Check Ready Pool depth                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 7: Security Operations

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
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 8: Troubleshooting

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
│  3. Force resource signal                                  │
│  4. Last resort: reboot                                    │
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
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 9: Compute Profile Operations

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
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 10: Maintenance

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
└─────────────────────────────────────────────────────────────┘
```

---

*End of Administrator Guide*
