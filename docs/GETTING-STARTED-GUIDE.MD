# GETTING STARTED GUIDE

**CIBIOS/CIBOS/HIP — Getting Started**
**Version:** 1.0.0
**Audience:** New users, first-time builders, evaluators

---

## Overview

This guide takes you from zero to a running CIBOS system with a working application. It assumes no prior knowledge of HIP, CIBIOS, or CIBOS. It does assume familiarity with Rust and basic command-line usage.

**What you will accomplish:**

```
GETTING STARTED PATH:

  Prerequisites     Quick Start      First App        Next Steps
  ─────────────     ───────────      ─────────        ──────────
  Hardware ──┐      Clone ──┐        Create ──┐       Profile ──┐
  Software ──┤      Build ──┤        Build  ──┤       Features──┤
  Env setup ─┘      Boot   ──┤       Deploy  ──┤       Docs    ──┘
                    Verify ─┘        Run    ──┘

  ~30 minutes to a running system
  ~45 minutes to your first application
```

**What you will NOT need:**

- Special hardware (any modern x86-64, ARM64, or RISC-V machine works)
- A quantum computer (HIP runs on commodity hardware)
- Prior operating systems knowledge beyond basic usage

---

## Chapter 1: Prerequisites

### 1.1 Hardware Requirements

CIBOS runs on commodity hardware. The profile you choose determines which hardware features are used, but all profiles run on standard machines.

```
HARDWARE REQUIREMENTS BY PROFILE:

┌──────────────────────┬─────────────────────┬──────────────────────────────┐
│ Profile              │ Minimum             │ Recommended                  │
├──────────────────────┼─────────────────────┼──────────────────────────────┤
│ Maximum Isolation    │ 2 cores, 4 GB RAM   │ 4+ cores, 16+ GB RAM         │
│                      │ No SMT requirement  │ Hardware RNG (RDRAND/RNDR)   │
│                      │ TPM optional        │ TPM 2.0 for full RTRO        │
├──────────────────────┼─────────────────────┼──────────────────────────────┤
│ Balanced             │ 2 cores, 2 GB RAM   │ 4+ cores, 8+ GB RAM          │
│                      │ No SMT requirement  │ Hardware RNG preferred       │
│                      │ SMT disabled        │ SMT disabled                 │
├──────────────────────┼─────────────────────┼──────────────────────────────┤
│ Performance          │ 4 cores, 4 GB RAM   │ 8+ cores, 16+ GB RAM         │
│                      │ SMT supported       │ SMT enabled                  │
│                      │ 2+ physical cores   │ 4+ physical cores            │
├──────────────────────┼─────────────────────┼──────────────────────────────┤
│ Compute              │ 8 cores, 8 GB RAM   │ 32+ cores, 64+ GB RAM        │
│                      │ SMT supported       │ SMT enabled                  │
│                      │ Bare metal required │ Bare metal server            │
└──────────────────────┴─────────────────────┴──────────────────────────────┘

ALL PROFILES — Absolute minimum for evaluation:
  CPU: Any x86-64, ARM64, or RISC-V64 processor
  RAM: 2 GB (4 GB recommended)
  Storage: 1 GB free space for build artifacts
  Boot: USB or direct disk boot capability

VIRTUAL MACHINES:
  VMs are supported for development and evaluation only.
  Maximum Isolation profile has reduced security guarantees in VMs
  (hardware isolation boundaries are emulated, not physical).
  Performance and Compute profiles may show reduced throughput in VMs.
  Balanced profile is recommended for VM-based evaluation.

HARDWARE RNG:
  Intel: RDRAND instruction (Ivy Bridge and later, 2012+)
  AMD:   RDRAND instruction (Ryzen/EPYC, 2017+)
  ARM:   RNDR instruction (ARMv8.5-A, 2020+)
  RISC-V: SEED CSR (proposed extension)
  Fallback: Software CSPRNG seeded from hardware entropy (automatic)
```

### 1.2 Software Requirements

**Build host requirements (the machine you build CIBOS on):**

```
SOFTWARE REQUIREMENTS:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  REQUIRED:                                                                  │
│                                                                             │
│  Rust toolchain (stable + nightly)                                         │
│    Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh│
│    Version: rustup default nightly  (CIBOS requires nightly for no_std)    │
│                                                                             │
│  Rust targets:                                                              │
│    x86-64:  rustup target add x86_64-unknown-none                          │
│    ARM64:   rustup target add aarch64-unknown-none                         │
│    RISC-V:  rustup target add riscv64gc-unknown-none-elf                   │
│                                                                             │
│  Rust components:                                                           │
│    rustup component add rust-src                                            │
│    rustup component add llvm-tools-preview                                 │
│                                                                             │
│  Build tools:                                                               │
│    lld (linker): sudo apt install lld   / brew install llvm                │
│    make:         sudo apt install make  / brew install make                │
│    dd:           included on all Unix systems                              │
│                                                                             │
│  OPTIONAL (but recommended):                                               │
│                                                                             │
│  QEMU (for VM testing before bare metal):                                  │
│    sudo apt install qemu-system-x86  (x86-64 testing)                      │
│    sudo apt install qemu-system-aarch64  (ARM64 testing)                   │
│                                                                             │
│  cargo-binutils (for inspecting binaries):                                 │
│    cargo install cargo-binutils                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Verify your environment:**

```bash
# Check Rust
rustc --version          # Should show nightly
cargo --version

# Check targets
rustup target list --installed
# Should include your target architecture

# Check lld
lld --version            # or ld.lld --version

# Check QEMU (optional)
qemu-system-x86_64 --version
```

### 1.3 Environment Setup

```bash
# Clone the repository
git clone https://github.com/hip-os/cibos.git
cd cibos

# Run the environment check script
./scripts/check-env.sh

# Expected output:
# [OK] Rust nightly installed
# [OK] Target x86_64-unknown-none available
# [OK] lld available
# [OK] rust-src component installed
# [OK] llvm-tools-preview component installed
# [OPTIONAL] qemu-system-x86_64 available
# Environment ready.

# If anything shows [MISSING], follow the instructions printed
```

---

## Chapter 2: Quick Start

**Goal:** Boot a running CIBOS system in under 5 minutes.

### 2.1 Choose Your Profile

If you are evaluating CIBOS for the first time, use **Balanced** profile. It runs on any hardware, requires no special configuration, and demonstrates HIP's core properties clearly.

```
PROFILE QUICK SELECTION:

  "I want to evaluate HIP"                → Balanced
  "I'm building a security product"       → Maximum Isolation
  "I'm building a desktop/mobile app"     → Performance
  "I'm doing scientific computation"      → Compute
  "I'm not sure"                          → Balanced
```

### 2.2 Build CIBIOS + CIBOS

The build system compiles CIBIOS (firmware) and CIBOS (kernel) together for your chosen profile. A single command produces a bootable image.

```bash
# Build for Balanced profile (default, recommended for first run)
make profile=balanced

# Build for other profiles:
make profile=maximum-isolation
make profile=performance
make profile=compute

# Build output:
# build/
# ├── cibios.bin          Firmware binary
# ├── cibos.bin           Kernel binary
# ├── cibios-cibos.img    Combined bootable disk image
# └── build.log           Complete build log

# Verify the build
make verify profile=balanced
# Output:
# [OK] CIBIOS signature valid
# [OK] CIBOS signature matches CIBIOS expectation
# [OK] Profile: Balanced
# [OK] Feature flags compiled:
#      anti-starvation (100ms threshold)
#      cryptographic-ipc
#      handoff-cryptographic
#      network-stack
#      gui-subsystem
# Build verified.
```

**Build times (approximate):**

```
First build (downloads crates):  3-8 minutes
Subsequent builds (cached):      30-90 seconds
Profile switch (recompile):      1-3 minutes
```

### 2.3 Create Boot Media

**Option A: USB boot (bare metal — recommended)**

```bash
# Find your USB device
lsblk
# Look for your USB drive, e.g., /dev/sdb

# Write the image (DESTROYS ALL DATA on the USB drive)
sudo dd if=build/cibios-cibos.img of=/dev/sdb bs=4M status=progress
sudo sync

# Verify the write
make verify-media device=/dev/sdb
# [OK] Boot sector present
# [OK] Signature readable
# Ready to boot.
```

**Option B: QEMU (virtual machine — for evaluation)**

```bash
# Boot directly in QEMU (no USB needed)
make qemu profile=balanced

# This launches QEMU and boots CIBOS directly
# Press Ctrl+A, X to exit QEMU
```

**Option C: Existing disk partition**

```bash
# Install to a partition (advanced — see Administrator Guide)
make install profile=balanced target=/dev/sda2
```

### 2.4 Boot and Verify

**Bare metal boot:**

1. Insert the USB drive
2. Boot your machine from USB (F12, F2, or Del during POST for boot menu)
3. Select the USB drive

**Expected boot sequence:**

```
CIBIOS/CIBOS BOOT SEQUENCE:

  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [CIBIOS] Hardware initialization...                            │
  │  [CIBIOS] Memory isolation boundaries established               │
  │  [CIBIOS] Lane memory regions allocated                         │
  │  [CIBIOS] SMT disabled (Balanced profile)                       │
  │  [CIBIOS] Hardware config: 4 physical cores, 8 GB RAM           │
  │  [CIBIOS] Hardware RNG: RDRAND detected                         │
  │  [CIBIOS] Signature verification: PASS                          │
  │  [CIBIOS] Kernel signature matches. Handoff authorized.         │
  │  [CIBIOS] ──► Transferring control to CIBOS                    │
  │                                                                  │
  │  [CIBOS] Kernel starting (Balanced profile)                     │
  │  [CIBOS] Catch and Release initialized                          │
  │  [CIBOS] Selector initialized                                   │
  │  [CIBOS] Lane scheduler ready                                   │
  │  [CIBOS] Anti-starvation: 100ms threshold                       │
  │  [CIBOS] Cryptographic IPC: enabled                             │
  │  [CIBOS] Network stack: available                               │
  │  [CIBOS] GUI subsystem: available                               │
  │  [CIBOS] System ready.                                          │
  │                                                                  │
  │  CIBOS Balanced ─────────────────── 2025-01-01 00:00:00 UTC    │
  │  Containers: 0   Lanes: 0   Ready: 0   Stalled: 0              │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

**QEMU boot (same output, in your terminal)**

### 2.5 Verify the Running System

From the CIBOS system console (or serial output):

```bash
# Check system status
cibos-ctl status
# Output:
# Profile:    Balanced
# Uptime:     0d 0h 0m 12s
# Containers: 0
# Lanes:      0 active, 0 total
# Ready Pool: 0 containers
# Stalled:    0 containers
# Selector:   idle

# Check hardware info
cibos-ctl hardware
# Output:
# Physical cores: 4
# Logical cores:  4 (SMT disabled)
# RAM:            8192 MB
# Hardware RNG:   RDRAND
# Isolation:      Active

# Check profile
cibos-ctl profile
# Output:
# Profile: Balanced
# Features compiled:
#   anti-starvation       (threshold: 100ms)
#   cryptographic-ipc     (enabled)
#   handoff-cryptographic (enabled)
#   network-stack         (available)
#   gui-subsystem         (available)
```

**You now have a running CIBOS system.**

---

## Chapter 3: Your First Application

**Goal:** Write, build, and run "Hello Lane" — the minimal CIBOS application.

### 3.1 Create the Application

```bash
# On your build host (not the CIBOS system)
# Create a new application project
cargo new --bin hello-lane
cd hello-lane
```

**Edit `Cargo.toml`:**

```toml
[package]
name = "hello-lane"
version = "0.1.0"
edition = "2021"

[dependencies]
cibos = "0.1"        # CIBOS application SDK
log   = "0.4"        # Logging (routes to CIBOS kernel log)

[profile.release]
opt-level = "z"      # Size optimization for embedded
lto = true
codegen-units = 1
panic = "abort"
```

**Edit `src/main.rs`:**

```rust
#![no_std]
#![no_main]

extern crate alloc;

use cibos::{Lane, Timer};
use core::time::Duration;

/// Application entry point.
/// This function runs in your container's initial lane.
/// All application code runs through the HIP execution model:
/// lanes submit work, kernel dispatches via Catch and Release.
#[cibos::main]
async fn main() {
    log::info!("Hello Lane starting...");

    // Create a lane — a lightweight execution context
    // One lane = one parallel pathway in HIP
    let mut lane = Lane::create().expect("Lane creation failed");

    // Submit a future to the lane
    // The kernel will dispatch this when resources are available
    lane.submit(async {
        // This runs inside the HIP execution model
        // Fully isolated, interference-free
        let result = compute_greeting("CIBOS");
        log::info!("Computed: {}", result);

        // Timer::sleep demonstrates the async event model
        // .await here means: "stall this lane, resume when timer fires"
        // The kernel Catch and Release handles this automatically
        Timer::sleep(Duration::from_millis(100)).await;

        log::info!("Timer fired. Lane complete.");
    }).expect("Lane submit failed");

    // Wait for the lane to finish
    // In a real application, you would do other work here
    lane.join().await;

    log::info!("Hello Lane complete.");
}

/// Pure computation — no async, no I/O
fn compute_greeting(target: &str) -> alloc::string::String {
    alloc::format!("Hello from a lane, {}!", target)
}
```

### 3.2 Build the Application

```bash
# Build for your target architecture
cargo build --release --target x86_64-unknown-none

# Package for deployment to CIBOS
cibos-pack \
    --input target/x86_64-unknown-none/release/hello-lane \
    --output hello-lane.capp \
    --name "Hello Lane" \
    --version "0.1.0"

# .capp = CIBOS Application Package (signed container)
```

### 3.3 Deploy and Run

```bash
# Transfer to CIBOS system
cibos-deploy \
    --host cibos-system \          # IP or hostname of your CIBOS system
    --app hello-lane.capp

# On the CIBOS system, run it
cibos-ctl run hello-lane

# Expected output on CIBOS system:
# [hello-lane] Hello Lane starting...
# [hello-lane] Computed: Hello from a lane, CIBOS!
# [hello-lane] Timer fired. Lane complete.
# [hello-lane] Hello Lane complete.
# [cibos] Container hello-lane exited cleanly.
```

**What just happened:**

```
EXECUTION FLOW FOR HELLO LANE:

  Your Code                    CIBOS Kernel
  ─────────                    ────────────

  main() starts ──────────────► Container started
                               Initial lane created

  Lane::create() ─────────────► Lane registered
                               Added to container

  lane.submit(async{...}) ────► Future submitted to lane
                               Lane added to Ready Pool

  lane.join().await ──────────► Main lane stalls (waiting for lane)
                               Catch and Release: main → Stalled List

                               Selector dispatches submitted lane:
                               ┌───────────────────────────────────┐
                               │ Lane runs: compute_greeting()     │
                               │ log::info! → kernel log           │
                               └───────────────────────────────────┘

  Timer::sleep(100ms).await ──► Lane stalls on timer
                               Catch and Release: lane → Stalled List
                               Timer registered

                               100ms passes...
                               Timer fires → lane moved to Ready Pool
                               Selector dispatches lane again

                               Lane completes
                               Main lane moved to Ready Pool
                               Selector dispatches main

  lane.join() returns         ◄── Main resumes

  main() returns ─────────────► Container exits cleanly
```

Congratulations — you have written, built, and run your first CIBOS application.

---

## Chapter 4: Next Steps

### 4.1 Choosing a Profile

Your first run used Balanced profile. As your project takes shape, choose the profile that matches your use case:

```
PROFILE SELECTION GUIDE:

  USE MAXIMUM ISOLATION IF:
  ├─ Security is your primary requirement
  ├─ You are building for high-security environments
  ├─ Non-determinism is a security concern (must eliminate timing patterns)
  ├─ Cryptographic correctness is required for scheduling itself
  └─ You accept ~75K QTM in exchange for maximum security

  USE BALANCED IF:
  ├─ You are building a general-purpose application
  ├─ You want a good default with reasonable security
  ├─ You are still evaluating or learning CIBOS
  └─ ~85K QTM with solid security is the right trade-off

  USE PERFORMANCE IF:
  ├─ You are building a desktop or mobile application
  ├─ User-facing responsiveness matters
  ├─ Hardware is limited (embedded, mobile)
  ├─ SMT is available and you want to use it
  └─ ~50K QTM with excellent single-workload performance

  USE COMPUTE IF:
  ├─ You are doing scientific computation, ML, or data processing
  ├─ Throughput is the only metric that matters
  ├─ You have dedicated hardware (no other users)
  ├─ You want dynamic weight adjustment
  └─ 100K+ QTM at maximum hardware utilization
```

To switch profiles:

```bash
make profile=maximum-isolation
make verify profile=maximum-isolation
# Rebuild your boot media and redeploy
```

### 4.2 Adding Features

Features are compiled into the kernel via feature flags. Add them in your build configuration:

```bash
# Build Balanced with signal coalescence and audit logging
make profile=balanced \
     features="signal-coalescence,audit-logging"

# Available features by profile:
cibos-ctl features list --profile=balanced
# Output:
# Available for Balanced:
#   anti-starvation           [default: enabled, threshold: 100ms]
#   signal-coalescence        [default: disabled]
#   signal-coalescence-threshold [requires signal-coalescence]
#   cryptographic-ipc         [default: enabled]
#   rtro                      [optional]
#   user-authentication       [optional]
#   multi-user-isolation      [requires user-authentication]
#   audit-logging             [optional]
#   network-stack             [optional]
#   gui-subsystem             [optional]
#   cli-interface             [optional]
```

### 4.3 Where to Learn More

```
DOCUMENTATION MAP:

  You are here: Getting Started Guide

  NEXT READS (in order):

  1. Application Developer Guide
     ├─ Lane patterns (parallel, pipeline, event-driven)
     ├─ Channel communication between containers
     ├─ Async/await in HIP's event model
     └─ Profile-specific design patterns

  2. Application Examples Repository
     ├─ hello-lane             (you just did this!)
     ├─ channel-communication  (two containers talking)
     ├─ parallel-computation   (real parallel work)
     ├─ pipeline-processing    (staged data flow)
     ├─ compute-intensive      (dynamic weights)
     ├─ event-driven-ui        (state buffering)
     ├─ mobile-sensor          (camera/GPS/microphone)
     └─ profile-flexible       (works on all profiles)

  3. API Reference Guide
     └─ Complete Lane, Channel, Timer, Sensor, Container APIs

  FOR DEPLOYMENT:
  4. Administrator Guide
     └─ Production setup, configuration, monitoring, weight tuning

  FOR PERFORMANCE:
  5. Performance Tuning Guide
     └─ Measuring, optimizing, benchmarking per profile

  FOR PROBLEMS:
  6. Troubleshooting Guide
     └─ Boot issues, scheduling issues, memory, channels, errors

  FOR CONTRIBUTORS:
  7. Developer Guide          (kernel/firmware implementation)
  8. CIBOS Async Runtime Guide (custom async runtime internals)
  9. Contributor Guide        (PR process, coding standards)

  FOR UNDERSTANDING WHY:
  10. HIP README              (paradigm theory)
  11. Technical White Paper   (quantum-like property analysis)
  12. Architecture Decision Records (why each decision was made)
```
