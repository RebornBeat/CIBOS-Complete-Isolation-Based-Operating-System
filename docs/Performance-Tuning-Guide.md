# PERFORMANCE TUNING GUIDE

**CIBIOS/CIBOS/HIP — Performance Tuning**
**Version:** 1.0.0
**Audience:** Administrators and advanced developers optimizing production systems

---

## Overview

CIBOS performance tuning works differently from traditional OS tuning. The HIP architecture means many traditional bottlenecks simply do not exist:

```
WHAT DOESN'T EXIST IN CIBOS:
  ✗ Lock contention         (no global locks)
  ✗ Context switch overhead (lane-to-lane within container)
  ✗ False sharing           (lanes are isolated)
  ✗ Priority inversion      (weighted entropy, no priority queues)
  ✗ Thundering herd         (N≤C: all dispatch; N>C: entropy selects)

WHAT DOES NEED TUNING:
  ✓ Lane count vs core count
  ✓ Weight distribution across lanes
  ✓ Channel buffer sizes
  ✓ Signal coalescence thresholds
  ✓ Anti-starvation thresholds
  ✓ Memory allocation patterns
```

---

## Chapter 1: Measuring Performance

### 1.1 Built-in Profiling Tools

```bash
# Real-time system metrics
cibos-ctl metrics --live

# Output format:
# Metric                 Value        Unit
# ─────────────────────  ───────────  ────
# dispatch_rate          48,293       /sec
# ready_pool_depth       12           containers
# stall_rate             0.23         /container/sec
# lane_utilization       87.4         %
# selector_entropy_used  12.3         %
# throughput_containers  1,847        /sec
# memory_allocated       4,847        MB
# channel_messages       892,341      /sec

# Historical metrics (last 5 minutes, 10-second intervals)
cibos-ctl metrics --history 5m --interval 10s

# Per-container metrics
cibos-ctl metrics --container my-app

# Export metrics for external analysis
cibos-ctl metrics --export csv > metrics.csv
```

### 1.2 Throughput Measurement

**QTM (Quantum Throughput Multiplier)** is the primary CIBOS throughput metric:

```
QTM = (output_per_dollar) / (sequential_baseline_per_dollar)

Higher QTM = more work per hardware dollar.
Target QTM values by profile:
  Compute:           100,000+ QTM
  Balanced:          ~85,000 QTM
  Maximum Isolation: ~75,000 QTM
  Performance:       ~50,000 QTM (optimized for single-workload latency)
```

**Measure application-level throughput:**

```bash
# Start a throughput measurement
cibos-ctl benchmark throughput \
    --container my-processing-app \
    --duration 60s \
    --metric messages_per_second

# Output:
# Throughput Benchmark: my-processing-app
# Duration: 60s
# Messages processed: 5,423,891
# Throughput: 90,398 msg/sec
# P50 latency: 0.8ms
# P95 latency: 2.1ms
# P99 latency: 4.7ms
# CPU utilization: 89%
# QTM estimate: 98,200
```

### 1.3 Latency Measurement

```bash
# Measure end-to-end latency for a channel pipeline
cibos-ctl benchmark latency \
    --source-container input-container \
    --sink-container output-container \
    --samples 10000

# Output:
# Latency Benchmark: input → output
# Samples: 10,000
# P50:  1.2ms
# P95:  3.4ms
# P99:  8.1ms
# P999: 22.4ms
# Max:  47.8ms
```

### 1.4 Lane Utilization Tracking

```bash
# Per-lane utilization for a container
cibos-ctl lanes --container my-app --utilization

# Output:
# Lane ID  Weight  State    Util%  Stall/sec  Avg Stall Duration
# ───────  ──────  ───────  ─────  ─────────  ──────────────────
# lane-0   1       running  94%    12.3       0.8ms
# lane-1   1       running  91%    10.1       1.2ms
# lane-2   1       stalled  67%    45.2       3.1ms  ← high stall rate
# lane-3   5       running  98%    2.1        0.2ms
```

**Interpretation:**
- High utilization (>90%): lane is doing useful work. Good.
- High stall rate with high stall duration: lane is blocked on a resource (channel full/empty, timer). May indicate bottleneck.
- Low utilization + low stall rate: lane may have nothing to do. Consider reducing lane count.

### 1.5 Ready Pool Depth Monitoring

```bash
# Monitor Ready Pool depth over time
cibos-ctl metrics --metric ready_pool_depth --live --interval 1s

# Output:
# Time      Ready Pool Depth  Stalled Count  Cores  Dispatch Rate
# ────────  ────────────────  ─────────────  ─────  ─────────────
# 10:00:01  12                48             8      48,293
# 10:00:02  15                45             8      51,204
# 10:00:03  8                 52             8      45,100
# 10:00:04  23                37             8      58,431  ← spike
# 10:00:05  11                49             8      47,882
```

**Interpretation:**
- Ready Pool depth of 0: cores are idle, nothing to dispatch. Under-utilization.
- Ready Pool depth ≈ cores: optimal. Cores always have work.
- Ready Pool depth >> cores: many containers ready but waiting. High dispatch pressure.
- Stalled Count very high: many containers blocked on resources (may be correct for workload).

---

## Chapter 2: Throughput Optimization

### 2.1 Signal Coalescence Configuration

Signal coalescence reduces overhead by batching signals from multiple events into a single kernel wake. This is the single highest-impact tuning for throughput-heavy workloads.

```bash
# Check current coalescence configuration
cibos-ctl config coalescence

# Configure coalescence threshold
cibos-ctl config set signal-coalescence-threshold 4ms

# Monitor coalescence effectiveness
cibos-ctl metrics --metric coalescence_ratio --live

# coalescence_ratio = (signals coalesced) / (total signal events)
# Good ratio: 60-85%
# Too high (>90%): threshold may be too long — increasing latency
# Too low (<30%): threshold may be too short — not batching effectively
```

**Recommended thresholds by workload:**

```
WORKLOAD TYPE              THRESHOLD    REASON
─────────────────────────  ─────────    ──────────────────────────────────
Batch processing           8-16ms       High throughput, latency ok
Stream processing          2-4ms        Balance throughput + latency
Interactive applications   0.5-1ms      Latency-sensitive
Background computation     16-32ms      Throughput only, latency irrelevant
Mixed workload             4ms          Good general-purpose default
```

### 2.2 Lane Count Tuning

```
LANE COUNT vs THROUGHPUT:

  Too few lanes:
    Cores sit idle waiting for next work item
    Lane stalls (channel, timer) = core goes idle
    Solution: Add more lanes so cores always have work

  Too many lanes:
    Selector overhead increases (more candidates to evaluate)
    Memory pressure from idle lane state
    Marginal improvement after optimal count

  OPTIMAL LANE COUNT (rule of thumb):
    optimal_lanes = physical_cores × (1 / (1 - stall_fraction))

  Example: 8 cores, 40% of time lanes are stalled:
    optimal_lanes = 8 × (1 / (1 - 0.4)) = 8 × 1.67 = ~14 lanes

  Example: 8 cores, 80% of time lanes are stalled (I/O heavy):
    optimal_lanes = 8 × (1 / (1 - 0.8)) = 8 × 5 = ~40 lanes
```

```bash
# Check current lane stall fraction
cibos-ctl metrics --metric lane_stall_fraction --container my-app

# Output:
# Lane stall fraction: 0.42 (42% of time lanes are stalled)
# Recommended lane count for 8 cores: 14
# Current lane count: 8  ← under-provisioned for this stall rate
```

### 2.3 Weight Tuning for Throughput

On Compute profile with `per-lane-weights`:

```
WEIGHT STRATEGY FOR THROUGHPUT:

  Goal: maximum total output from all lanes

  Strategy: Equal weights for equal-priority lanes
  ─────────────────────────────────────────────────
  All lanes have equal dispatch probability.
  No lane is favored — maximum total parallelism.

  Strategy: Weighted for pipeline stages
  ────────────────────────────────────────
  If one pipeline stage is a bottleneck, give it higher weight.
  Example: Write stage is slower than Process stage:
    read_lane:    weight=1
    process_lane: weight=2
    write_lane:   weight=4   ← bottleneck gets priority
  This reduces buffering and back-pressure at the bottleneck.
```

### 2.4 Memory Allocation Patterns

CIBOS uses a per-container allocator. Allocation patterns affect throughput:

```
HIGH-THROUGHPUT ALLOCATION PATTERNS:

  GOOD: Pre-allocate pools
    // Allocate once, reuse
    let mut pool: Vec<Buffer> = (0..100)
        .map(|_| Buffer::with_capacity(4096))
        .collect();

  GOOD: Stack allocation for small, temporary data
    // No heap allocation at all
    let mut scratch = [0u8; 256];
    process_into(&mut scratch);

  AVOID: Frequent small allocations in hot paths
    // Allocates on every message — GC pressure
    while let Some(msg) = channel.receive().await {
        let processed = msg.to_string();  // Heap allocation per message
        output.send(processed).await?;
    }

  BETTER: Reuse allocation
    let mut buffer = String::with_capacity(256);
    while let Some(msg) = channel.receive().await {
        buffer.clear();
        write!(buffer, "{}", msg).unwrap();
        output.send(buffer.as_str()).await?;
    }
```

---

## Chapter 3: Latency Optimization

### 3.1 Weight Tuning for Responsiveness

For latency-sensitive lanes (UI, real-time processing):

```bash
# On Compute profile: give interactive lanes higher weights
cibos-ctl config lanes \
    --container ui-app \
    --lane ui-lane \
    --weight 5

cibos-ctl config lanes \
    --container ui-app \
    --lane background-sync \
    --weight 1

# Result: UI lane gets ~5x more dispatch chances than background sync
# Subjective responsiveness improves significantly
```

On Maximum Isolation and Balanced profiles: weights are fixed (1:1:1 for Maximum Isolation, system-managed for Balanced). Latency optimization must come from application design.

### 3.2 Anti-Starvation Thresholds

Anti-starvation prevents low-weight lanes from never executing. The threshold controls how long a lane can be deprived before getting forced dispatch.

```bash
# Check current anti-starvation threshold
cibos-ctl config get anti-starvation-threshold

# Adjust anti-starvation threshold
cibos-ctl config set anti-starvation-threshold 50ms

# Effect:
# Lower threshold (50ms): starvation is prevented more aggressively
#   Pro: lower maximum latency for low-weight lanes
#   Con: slightly disrupts high-weight lanes more often

# Higher threshold (200ms): starvation prevention is less aggressive
#   Pro: high-weight lanes run with less interruption
#   Con: low-weight lanes may wait longer

# PROFILE DEFAULTS:
# Maximum Isolation: anti-starvation NOT compiled (equal weights — no starvation possible)
# Balanced:          100ms
# Performance:       50ms
# Compute:           configurable (disabled is valid if all lanes have equal priority)
```

### 3.3 Priority Lane Patterns

Application design pattern for low-latency requirements:

```rust
// Pattern: Dedicated high-priority lane for time-sensitive work

// Separate UI updates from computation
let mut ui_lane = Lane::create_with_weight(5)?;    // High weight = more dispatch
let mut compute_lane = Lane::create_with_weight(1)?; // Low weight = background

// UI lane handles latency-sensitive work
ui_lane.submit(async move {
    loop {
        let event = select! {
            event = input.receive() => event,
            _ = Timer::sleep(Duration::from_millis(16)) => UIEvent::Tick,
        };
        handle_ui_event(event);
    }
})?;

// Compute lane handles throughput work
compute_lane.submit(async move {
    loop {
        let data = compute_input.receive().await?;
        let result = expensive_computation(data);
        compute_output.send(result).await?;
    }
})?;
```

---

## Chapter 4: Resource Efficiency

### 4.1 Memory Usage Patterns

```bash
# Monitor container memory usage
cibos-ctl metrics --container my-app --metric memory_allocated --live

# Check for memory growth (possible leak)
cibos-ctl metrics --container my-app \
    --metric memory_allocated \
    --history 1h \
    --check-growth

# Output:
# Memory trend over 1h: +2.3 MB/hour
# Status: GROWING — investigate for memory leak
```

**Common memory leak patterns in CIBOS:**

```rust
// LEAK: Collecting results without bound
let mut results: Vec<_> = Vec::new();
while let Some(msg) = channel.receive().await {
    results.push(process(msg));  // Vector grows unboundedly
    // results never drained — memory grows forever
}

// FIX: Process and drain
while let Some(msg) = channel.receive().await {
    let result = process(msg);
    output.send(result).await?;  // Immediately forward, don't accumulate
}
```

### 4.2 Channel Buffer Sizing

```
CHANNEL BUFFER SIZING GUIDE:

  TOO SMALL (1-2):
    Pro: Very low memory usage
    Con: Constant back-pressure — sender and receiver both stall frequently
    Use for: Tight coupling where you want back-pressure to be immediate

  APPROPRIATE (8-32):
    Pro: Absorbs short bursts; low stall rate
    Con: Moderate memory usage
    Use for: Most pipelines — good default

  LARGE (64-256):
    Pro: Absorbs large bursts; very low stall rate
    Con: Higher memory; large buffer = large latency spike on burst
    Use for: Rate-mismatched producers/consumers

  VERY LARGE (1000+):
    Pro: Almost never stalls sender
    Con: Very high memory; latency can spike to seconds on burst
    Use for: Batch collection before processing in phases

FORMULA: buffer_capacity = burst_size × safety_factor
  Where burst_size = max messages expected in one dispatch cycle
  And safety_factor = 2-4 (absorb spikes without constant back-pressure)
```

### 4.3 Lane Memory Footprint

Each lane has overhead:

```
LANE OVERHEAD (approximate):
  Base lane state:       ~2 KB (async stack, kernel tracking data)
  Per future submitted:  ~0.5-8 KB (depends on future complexity)

TOTAL ESTIMATE: budget 8-16 KB per lane for planning purposes

  Example: 100 lanes × 12 KB = ~1.2 MB lane overhead
  This is trivial on any modern hardware.
  Lane count limits are policy limits, not memory limits.
```

---

## Chapter 5: Profile-Specific Tuning

### 5.1 Maximum Isolation

**What cannot be tuned:**
- Weights (always 1:1:1 — equal across all lanes and containers)
- Anti-starvation (not compiled — equal weights prevent starvation)
- Timing side-channels (eliminated by design)

**What can be tuned:**
- Lane count (more lanes = more parallelism within equal-weight constraint)
- Channel buffer sizes (affects memory, not security)
- Memory limits per container

**Strategy:** Maximize lane count. Since weights are equal, maximizing lanes is the primary throughput lever. Equal weights mean maximum fairness automatically.

```bash
# Maximum Isolation: increase system-wide lane limit if throughput is needed
cibos-ctl config set max-lanes-per-container 512  # Default: 256
```

### 5.2 Balanced

**Goal:** Responsive + fair. Not maximum throughput, not minimum latency.

**Primary tunings:**
- Anti-starvation threshold: 50-150ms depending on workload mix
- Signal coalescence: 2-4ms for mixed workloads
- Lane count: moderate (don't over-provision)

```bash
# Balanced profile tuning for mixed workload
cibos-ctl config set anti-starvation-threshold 75ms
cibos-ctl config set signal-coalescence-threshold 3ms
```

### 5.3 Performance

**Goal:** Maximize single-workload performance on limited hardware.

**SMT handling:** Performance enables SMT. Understand cache effects:
- SMT pairs share L1/L2 cache — competing lanes on the same core can thrash cache
- Class affinity (`class-core-affinity` feature) helps keep related lanes on same physical core

```bash
# Performance profile: enable class affinity for cache-friendly scheduling
cibos-ctl config enable class-core-affinity

# Monitor cache miss rates (if hardware supports)
cibos-ctl hardware perf-counters \
    --counter l1_cache_misses \
    --counter l2_cache_misses \
    --live
```

### 5.4 Compute

**Goal:** Maximum throughput. All hardware fully utilized.

**Primary tunings:**
1. **Lane count:** Provision to match stall fraction (see Section 2.2)
2. **Dynamic weights:** Use for phased computations (load → compute → collect)
3. **Signal coalescence:** High threshold (8-16ms) — throughput over latency
4. **Anti-starvation:** Disable or set very high (500ms+) if all lanes equal priority

```bash
# Compute profile maximum throughput configuration
cibos-ctl config set signal-coalescence-threshold 12ms
cibos-ctl config set anti-starvation-threshold 0ms  # Disable
cibos-ctl config set max-lanes-per-container 1024

# Monitor QTM
cibos-ctl metrics --metric qtm --live
# Target: 100,000+ QTM
```

---

## Chapter 6: Benchmarking

### 6.1 Standard Benchmarks

```bash
# Run the full CIBOS standard benchmark suite
cibos-bench run --profile balanced --all

# Standard benchmarks:
# bench-lane-throughput        Lane dispatch rate
# bench-channel-throughput     Messages/sec through channels
# bench-parallel-sum           8-lane parallel sum
# bench-pipeline-3stage        Three-stage pipeline throughput
# bench-latency-round-trip     Container→channel→container round trip
# bench-memory-allocation      Allocation/deallocation throughput

# Output summary:
# Benchmark                  Result         Unit       QTM Estimate
# ─────────────────────────  ─────────────  ─────────  ────────────
# bench-lane-throughput      52,841         dispatches/sec
# bench-channel-throughput   1,293,441      messages/sec
# bench-parallel-sum         47.2           GB/sec
# bench-pipeline-3stage      892,341        records/sec
# bench-latency-round-trip   1.8            ms P50
# bench-memory-allocation    8.1            GB/sec
# Overall QTM estimate:      84,200         (Balanced profile — expected ~85,000)
```

### 6.2 Custom Workload Testing

```bash
# Benchmark your specific application
cibos-bench custom \
    --container my-processing-app \
    --workload benchmark-mode \
    --duration 120s \
    --warmup 30s \
    --output report.json

# Run with different configurations to compare
cibos-bench compare \
    --baseline config-a.toml \
    --variant config-b.toml \
    --workload my-workload \
    --metric throughput
```

### 6.3 Comparative Analysis

```bash
# Compare against theoretical maximum
cibos-bench theoretical-max --profile compute --cores 32

# Output:
# Theoretical maximum for Compute profile on 32 cores:
# Hardware throughput ceiling: ~11,000,000 dispatches/sec
# Current measured:            9,847,200 dispatches/sec
# Efficiency:                  89.5%
# Gap to close:                10.5% remaining
# Primary bottleneck:          Channel buffer pressure (see --detail)
```
