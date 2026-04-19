# CIBOS Application Developer Guide
**Programming Reference for Application Developers**

## Introduction

This guide covers everything you need to write applications for CIBOS. Because CIBOS supports multiple profiles with different feature flags, application design decisions can vary based on the deployment context. This guide covers both **profile-flexible design** (applications that work correctly across all profiles) and **profile-specific optimizations** (applications tuned for specific profiles).

For most applications, the goal is profile-flexible design: write the application to work correctly regardless of which features are compiled in. Where profile-specific optimizations are valuable, they are clearly identified with conditional compilation guards.

---

## Chapter 1: The CIBOS Programming Model

### Your Application Is a Container

Every application on CIBOS runs in a container — an isolated execution environment with dedicated memory, resource limits, and security boundaries. Your application cannot access memory belonging to other applications. Other applications cannot observe your application's behavior. This isolation is architectural and unconditional.

### Your Execution Unit Is a Lane

Within your container, you create lanes. Each lane is an isolated execution context with its own memory region and event queue. The kernel sees only the head event of each lane — it cannot see queue depth, future events, or relationships between lanes.

```
LANE INTERNAL VIEW vs KERNEL VIEW:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  WHAT YOU SEE (Application View):                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Lane Queue:                                                        │    │
│  │  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐                        │    │
│  │  │ HEAD  │  │  #2   │  │  #3   │  │  #4   │                        │    │
│  │  │ Event │  │ Event │  │ Event │  │ Event │  ← All yours, private  │    │
│  │  └───────┘  └───────┘  └───────┘  └───────┘                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                     │                                                       │
│                     │ Kernel sees ONLY the HEAD                             │
│                     ▼                                                       │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ KERNEL BOUNDARY ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─         │
│                                                                             │
│  WHAT KERNEL SEES (Ready Pool):                                             │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐                     │       │
│  │  │ Lane 1│  │ Lane 2│  │ Lane 3│  │ Lane N│                     │       │
│  │  │ HEAD  │  │ HEAD  │  │ HEAD  │  │ HEAD  │                     │       │
│  │  │ only  │  │ only  │  │ only  │  │ only  │                     │       │
│  │  └───────┘  └───────┘  └───────┘  └───────┘                     │       │
│  │  Kernel CANNOT see: queue depth, future events, internal order   │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                             │
│  WHY THIS MATTERS:                                                          │
│  - Kernel cannot leak information about your queue state                    │
│  - Other containers cannot observe your queue depth                         │
│  - Timing attacks cannot infer queue state                                  │
│  - Your internal ordering is completely private                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Async/Await and the Event Model

Lane work is submitted as async blocks. Each `.await` point is a potential stall point — if the awaited resource is unavailable, the event stalls transparently (Catch and Release). When the resource becomes available, the kernel resumes the event at exactly the `.await` point.

```
ASYNC/AWAIT TO EVENT MODEL MAPPING:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Each .await is a potential STALL point:                                    │
│                                                                             │
│  lane.submit(async {                                                        │
│                                                                             │
│      // Event starts — if resources available → Ready Pool                  │
│      //                if resources unavailable → Stalled List              │
│                                                                             │
│      let data = channel.receive().await;                                    │
│      //                            ▲                                        │
│      //               Potential stall point                                 │
│      //  Channel empty → Poll::Pending                                      │
│      //    → Kernel tracks ChannelData dependency                           │
│      //    → Event moves to Stalled List                                    │
│      //    → NO polling, NO retry, NO spin-wait                             │
│      //    → When data arrives → resource signal                            │
│      //    → Kernel qualifies ALL resources                                 │
│      //    → Event → Ready Pool → dispatched                                │
│      //    → wake() called → poll() again → Poll::Ready                     │
│      //    → Execution resumes HERE                                         │
│                                                                             │
│      process(data);  // Runs synchronously until next .await               │
│                                                                             │
│      Timer::sleep(Duration::from_millis(100)).await;                        │
│      //   Kernel timer event — no thread sleeping                           │
│      //   Timer fires → event moves to Ready Pool → resumes here            │
│                                                                             │
│      send(result).await;                                                    │
│      //   Buffer full → stalls until space available                        │
│      //   Transparent — no retry code needed                                │
│                                                                             │
│      // Event completes — next event in lane queue becomes HEAD             │
│  });                                                                        │
│                                                                             │
│  KEY:                                                                       │
│  async block = ExecutionEvent                                               │
│  .await      = potential stall point (resource check via kernel)            │
│  Poll::Ready = resource available, continue                                 │
│  Poll::Pending = resource unavailable, kernel tracks, event stalls          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Important:** CIBOS uses its own async runtime. Do NOT use `tokio::spawn()`, `tokio::sync::Mutex`, or any standard runtime primitives — these use global locks and are incompatible with HIP. Use CIBOS's lane and channel primitives.

### You Communicate Through Channels

When your application needs to exchange data with another application, you use channels. Channels require the other application's explicit agreement. Terms are proposed by the requester — the receiver accepts all or rejects entirely. No counter-proposal.

---

## Chapter 2: Working with Lanes

### Creating Lanes

```rust
// Standard lane creation — works on ALL profiles
let mut lane = Lane::create()?;

// Lane with explicit weight — ONLY when per-lane-weights compiled in (Compute)
#[cfg(feature = "per-lane-weights")]
let priority_lane = Lane::create_with_weight(5)?;

// Profile-flexible pattern: use explicit weight if available, fall back otherwise
fn create_priority_lane() -> Result<Lane, LaneError> {
    #[cfg(feature = "per-lane-weights")]
    return Lane::create_with_weight(5);
    #[cfg(not(feature = "per-lane-weights"))]
    return Lane::create();
}
```

### Submitting Work

```rust
// Submit an async block — FIFO within this lane
lane.submit(async move {
    let result = compute(input).await;
    channel.send(result).await?;
})?;

// Multiple submissions — execute in order within this lane
lane.submit(work_item_1)?;
lane.submit(work_item_2)?;  // Guaranteed to run AFTER work_item_1 in this lane
lane.submit(work_item_3)?;  // Guaranteed to run AFTER work_item_2 in this lane
```

### Lane Ordering

```
ORDERING GUARANTEES:

Within a lane: FIFO guaranteed
  Submit A, then B, then C → executes A, then B, then C

Across lanes: NO ordering guarantee
  Lane 1: [A, B]
  Lane 2: [X, Y]
  Possible orderings: A,X,B,Y or X,A,Y,B or A,X,Y,B or ...
  Selection is entropy-based — unpredictable

If cross-lane ordering is needed: use channels
  Lane 1: compute result, send to channel
  Lane 2: receive from channel, then proceed
  → Lane 2's work runs after Lane 1's work completes (explicit dependency)
```

### Dynamic Weights (Compute Profile Only)

```rust
// Update lane weight at runtime — Compute profile with dynamic-weights only
// Sends a message to selector — no locks, no waiting
#[cfg(feature = "dynamic-weights")]
lane.update_weight(5)?;  // Priority lane

// Profile-flexible: no-op on other profiles
fn set_priority(lane: &Lane, high: bool) {
    #[cfg(feature = "dynamic-weights")]
    {
        let weight = if high { 5 } else { 1 };
        let _ = lane.update_weight(weight);
    }
    // On other profiles: application continues working correctly
}
```

**Why dynamic weights are acceptable only in Compute:** Weight changes create observable timing patterns. In Maximum Isolation/Balanced (adversarial environment), this is information leakage. In Compute (air-gapped, single user, no adversary), predictability is acceptable and can be beneficial for workflow phase management.

---

## Chapter 3: Channel Communication

### Creating Channels

```rust
// Request a channel to another container
let request = ChannelRequest {
    target: other_container_id,
    terms: ChannelTerms {
        direction: Direction::Bidirectional,
        rate_limit: Some(RateLimit::MessagesPerSec(1000)),
        buffer_size: 256,
        lifetime: ChannelLifetime::Permanent,
    },
};

let channel = Channel::request(request).await?;  // Awaits acceptance

// Accept incoming request
let incoming = container.await_channel_request().await?;
let channel = incoming.accept()?;   // Accept ALL terms
// Or: incoming.reject(Some("Not available"));
```

### Terms Are Not Negotiable

Channel terms are proposed by the requester. The receiver accepts all or rejects. There is no counter-proposal mechanism. If different terms are needed, the requester sends a new request. This design prevents negotiation overhead and timing leakage from negotiation patterns.

### Sending and Receiving

```rust
// Send — may stall if buffer full (transparent, no retry code needed)
channel.send(message).await?;

// Receive — may stall if buffer empty (transparent)
let message = channel.receive().await?;

// Non-blocking receive
match channel.try_receive() {
    Some(message) => process(message),
    None => do_other_work(),   // No data yet — don't spin
}
```

### IPC Security by Profile

The security model of channel communication is determined at build time and is transparent to application code:

- **Cryptographic mode** (Maximum Isolation, Balanced): Every message is signed and verified by CIBOS. Application code is identical.
- **Lightweight handshake** (Compute): Channel identity verified once at creation. No per-message crypto. Application code is identical.

Write your channel code normally — the profile determines the security guarantees.

---

## Chapter 4: Resource Awareness

### Stalls Are Transparent

When resources are unavailable, operations stall transparently. No retry loops needed:

```rust
// WRONG — never do this:
while !resource_available() {
    std::thread::sleep(Duration::from_millis(10));  // Breaks the model
}

// RIGHT — let the kernel handle it:
let data = allocate(size).await?;
// If unavailable → stalls invisibly until available → resumes here
```

### Checking Resources Before Stalling

```rust
let limits = container.get_resource_limits();
let available = container.memory_available();

if size > available {
    // Choose a smaller operation or chunk the work
    process_in_chunks(data, CHUNK_SIZE).await?;
} else {
    let buffer = allocate(size).await?;
    process(buffer).await?;
}
```

### Timer-Based Operations

Time is available as an event source on all profiles:

```rust
// Sleep — available on ALL profiles
Timer::sleep(Duration::from_millis(100)).await;

// Timeout — available on ALL profiles
match with_timeout(Duration::from_secs(5), channel.receive()).await {
    Ok(Ok(message)) => process(message),
    Ok(Err(e))       => handle_channel_error(e),
    Err(Timeout)     => handle_timeout(),
}

// Periodic task
loop {
    do_periodic_work().await?;
    Timer::sleep(Duration::from_secs(60)).await;
}
```

**How timers work:** Timer fires → timer event enters Ready Pool → competes for dispatch → your code executes. Time GENERATES events. The kernel does NOT use time to coordinate dispatch decisions (Maximum Isolation, Balanced). For Performance and Compute, time-based mechanisms can influence scheduling (anti-starvation, full-fairness) but this is transparent to application code.

---

## Chapter 5: Quantum-Like Programming Patterns

CIBOS's lane architecture enables quantum-like parallel computation. All lane results are preserved — no collapse. One run is sufficient.

### Parallel Pathway Maintenance

```rust
async fn parallel_search(problem: Problem) -> Vec<Solution> {
    let (sender, receiver) = Channel::new_local();
    let lane_count = 8; // Or determine dynamically
    let mut lanes = Vec::new();

    for i in 0..lane_count {
        let mut lane = Lane::create()?;
        let approach = get_approach(i, &problem);
        let s = sender.clone();
        lane.submit(async move {
            let solution = approach.solve().await;
            s.send((i, solution)).await?;
        })?;
        lanes.push(lane);
    }

    // Collect ALL results — no collapse, all preserved
    let mut results = Vec::with_capacity(lane_count);
    for _ in 0..lane_count {
        results.push(receiver.receive().await?);
    }

    // Application controls resolution — all strategies:
    // Take first: results.into_iter().next()?
    // Take best:  results.into_iter().max_by_key(|r| r.quality_score())?
    // Combine:    combine_all(results)
    // Use all:    for result in results { analyze(result); }
    results
}
```

When no competition exists (8 lanes, 16 execution contexts), all 8 dispatch simultaneously — truly parallel, zero selection overhead, 100% results preserved.

### Pipeline Processing

```rust
async fn pipeline(input: InputChannel, output: OutputChannel) {
    let mut read_lane    = Lane::create()?;
    let mut process_lane = Lane::create()?;
    let mut write_lane   = Lane::create()?;

    let (raw_s, raw_r)   = Channel::new_local();
    let (proc_s, proc_r) = Channel::new_local();

    read_lane.submit(async move {
        while let Ok(data) = input.receive().await {
            raw_s.send(data).await?;
        }
    })?;

    process_lane.submit(async move {
        while let Ok(raw) = raw_r.receive().await {
            proc_s.send(transform(raw).await).await?;
        }
    })?;

    write_lane.submit(async move {
        while let Ok(processed) = proc_r.receive().await {
            output.send(processed).await?;
        }
    })?;

    // All three stages proceed simultaneously when contexts available
    // Reading, processing, writing overlap in time
}
```

### Data Parallelism

```rust
async fn parallel_process<T, R>(
    inputs: Vec<T>,
    compute_fn: impl Fn(T) -> R + Clone + Send + 'static,
) -> Vec<R> {
    let (sender, receiver) = Channel::new_local();
    let count = inputs.len();

    for (i, input) in inputs.into_iter().enumerate() {
        let mut lane = Lane::create()?;
        let s = sender.clone();
        let f = compute_fn.clone();

        // On Compute with per-lane-weights: optionally set weight
        #[cfg(feature = "per-lane-weights")]
        // All equal for peer parallel computation
        lane.set_weight(1)?;

        lane.submit(async move {
            let result = f(input);
            s.send((i, result)).await?;
        })?;
    }

    // Collect ALL results — no collapse
    let mut results = vec![None; count];
    for _ in 0..count {
        let (i, result) = receiver.receive().await?;
        results[i] = Some(result);
    }
    results.into_iter().flatten().collect()
}
```

---

## Chapter 6: Profile-Specific Application Design

### Maximum Isolation Applications

Equal weights (1:1:1). Anti-starvation NOT compiled. Very long waits are theoretically possible under extreme load.

**Design guidance:** Handle variable latency. Don't assume immediate dispatch. Use timeouts for time-sensitive operations. Design for correctness under any execution ordering. Anti-starvation guarantees are not available — design defensively.

### Balanced Applications

System class has higher probability (weight 3 vs 1). Anti-starvation ensures progress (100ms threshold).

**Design guidance:** UI applications can expect more responsive dispatch. Standard patterns work well. Anti-starvation provides a backstop.

### Performance Applications

Strong system class priority (weight 5). Anti-starvation (50ms). Full-fairness ensures proportional execution time. SMT enabled.

**Design guidance:** UI components get strong priority. All containers eventually execute (full-fairness guarantees). Time-based triggering is fully appropriate.

### Compute Applications

Pure parallel computation with minimal overhead. Maximum quantum-like properties.

```rust
// Compute-optimized: maximum lanes, minimal overhead
async fn compute_intensive(workload: Workload) -> Results {
    let parallelism = determine_optimal_lanes(); // Based on workload + available contexts
    let (sender, receiver) = Channel::new_local();

    for i in 0..parallelism {
        let mut lane = Lane::create()?;
        let work_unit = workload.chunk(i, parallelism);
        let s = sender.clone();

        // Use per-lane weights for phase-aware computation (Compute only)
        #[cfg(feature = "per-lane-weights")]
        lane.set_weight(1)?;  // All equal for peer computation

        lane.submit(async move {
            let result = compute(work_unit).await;
            s.send((i, result)).await?;
        })?;
    }

    let mut results = vec![None; parallelism];
    for _ in 0..parallelism {
        let (i, r) = receiver.receive().await?;
        results[i] = Some(r);
    }
    results.into_iter().flatten().collect()
}

// Dynamic weight phase management (Compute only)
#[cfg(feature = "dynamic-weights")]
async fn phased_computation(
    data_lane: &Lane,
    compute_lanes: &[Lane],
    result_lane: &Lane,
) {
    // Phase 1: Load data (prioritize data lane)
    data_lane.update_weight(5)?;
    for l in compute_lanes { l.update_weight(1)?; }
    result_lane.update_weight(1)?;
    data_lane.submit(load_data()).await?;

    // Phase 2: Parallel computation (all equal)
    data_lane.update_weight(1)?;
    for l in compute_lanes { l.update_weight(1)?; }
    // ... submit compute work ...

    // Phase 3: Collect results (prioritize result lane)
    result_lane.update_weight(5)?;
    // ... collect ...
}
```

---

## Chapter 7: Event-Driven UI Design

Traditional UI assumes guaranteed frame times. CIBOS's entropy-based dispatch does not guarantee fixed latency. Adapt with state buffering:

```
STATE BUFFER PATTERN:

Instead of:
  loop { render_frame(); sleep(16ms); }  // WRONG — doesn't work

Use:
  Lane collects input events → updates state buffer
  When lane is dispatched → renders current state
```

```rust
// State buffer accumulates changes between dispatches
struct UIState {
    elements: HashMap<ElementId, ElementState>,
    needs_render: bool,
}

let mut lane = Lane::create()?;
lane.submit(async move {
    loop {
        let event = input_or_timer.receive().await?;
        state.update(event);
        if state.needs_render {
            render(state.snapshot());
            state.needs_render = false;
        }
    }
})?;
```

**Benefits:** Multiple input events handled between renders. No stale renders. Memory bounded. Works on all profiles.

**What NOT to do:**

```rust
// WRONG — assumes fixed frame times
loop {
    render_frame();
    Timer::sleep(Duration::from_millis(16)).await;  // "60 FPS" — unreliable
}

// WRONG — polling for dispatch time
while !time_to_render() { /* spinning — breaks the model */ }

// WRONG — standard Tokio primitives
tokio::spawn(async { /* global task queue with locks */ });
```

**System class for UI responsiveness:** On Balanced and Performance profiles, UI containers are system class with higher weight — they receive more selection probability when competition exists. On Maximum Isolation (equal weights), design for variable latency.

---

## Chapter 8: Sensor Access for Mobile Applications (CIBOS-MOBILE)

CIBOS-MOBILE provides complete sensor isolation. Each sensor requires per-access authorization.

```rust
// Request camera access (user sees authorization prompt)
let camera = Sensor::request(SensorType::Camera).await?;
// If denied → error returned; if approved → isolated channel established

// Read frame (sensor data isolated to this container)
let frame = camera.read_frame().await?;
process_image(frame);

// Release when done
camera.release();
```

**Sensor properties:**
- Camera: Per-access authorization, single-container access, system indicator active
- Microphone: Per-access authorization, recording indicator system-wide, audio data isolated
- GPS: Per-access authorization, coarse or fine precision option, location data isolated
- All other sensors: Same pattern — per-access, isolated data

---

## Chapter 9: Error Handling

### Stalls Are Not Errors

A stall is a container waiting for a resource. It is NOT an error. No retry is needed. The container resumes automatically.

```rust
// This is CORRECT — .await stalls if empty, resumes when data arrives
let message = channel.receive().await?;
// The '?' propagates actual errors (channel closed, etc.)
// NOT stalls — stalls are transparent
```

### Application Crashes

If your application panics, the crash is isolated to your container. Other containers continue. Design for graceful degradation: handle errors explicitly, checkpoint state for long-running computations, check for and resume from checkpoints on restart.

---

## Chapter 10: Debugging

```rust
// Log at key points
log::debug!("Lane {} starting task", lane.id());

// Check resource state
let state = container.get_resource_state();
log::debug!("Memory: {} / {}", state.memory_used, state.memory_limit);

// Detect long waits
async fn detect_slow<F, T>(op: F) -> T where F: Future<Output = T> {
    let start = Instant::now();
    let result = op.await;
    let duration = start.elapsed();
    if duration > Duration::from_secs(1) {
        log::warn!("Long wait: {:?}", duration);
    }
    result
}

// Measure throughput
let start = Instant::now();
let count = process_batch().await?;
let throughput = count as f64 / start.elapsed().as_secs_f64();
log::info!("Throughput: {:.2} ops/sec", throughput);
```

---

## Chapter 11: Common Pitfalls

```rust
// PITFALL 1: Assuming cross-lane ordering
lane1.submit(task1)?;
lane2.submit(task2)?;
// task2 MAY execute before task1 — entropy-based dispatch

// SOLUTION: Channels for explicit dependencies
lane1.submit(compute_then_send_to(channel))?;
lane2.submit(wait_for_channel_then_compute(channel))?;

// PITFALL 2: Spin-waiting
while !resource_available() { }  // NEVER — breaks the model

// SOLUTION: Await the resource
wait_for_resource().await?;

// PITFALL 3: Using Tokio primitives
tokio::spawn(async { ... });     // NEVER — global locks
tokio::sync::Mutex::new(data);   // NEVER — global locks

// SOLUTION: Use CIBOS primitives
Lane::create()?.submit(async { ... })?;
// Use channels for communication, not shared state

// PITFALL 4: Holding resources while doing other work
let resource = acquire_exclusive().await?;
do_unrelated_work().await?;  // Resource held unnecessarily

// SOLUTION: Minimal resource hold time
let data = {
    let resource = acquire().await?;
    let d = read(resource);
    release(resource).await?;
    d
};
process(data).await?;  // Process without holding resource

// PITFALL 5: Assuming fixed dispatch timing
loop {
    render_frame();
    Timer::sleep(Duration::from_millis(16)).await;  // Unreliable
}

// SOLUTION: Event-driven rendering
state.update(event);
if state.changed() { render(state.snapshot()); }
```

---

## Appendix: Quick Reference

### Lane Operations

| Operation | Description | Profile Restriction |
|---|---|---|
| `Lane::create()` | Create lane with container class weight | All profiles |
| `Lane::create_with_weight(n)` | Create lane with explicit weight | per-lane-weights only |
| `lane.update_weight(n)` | Update weight at runtime via message | dynamic-weights only |
| `lane.submit(future)` | Submit async event (FIFO in this lane) | All profiles |
| `lane.destroy()` | Graceful destroy (waits for current event) | All profiles |
| `lane.destroy_immediate()` | Immediate destroy, cancel pending | All profiles |

### Channel Operations

| Operation | Description |
|---|---|
| `Channel::request(req).await` | Request channel (awaits acceptance) |
| `container.await_channel_request().await` | Wait for incoming request |
| `incoming.accept()` | Accept all proposed terms |
| `incoming.reject()` | Reject the request |
| `channel.send(data).await` | Send (stalls if buffer full) |
| `channel.receive().await` | Receive (stalls if buffer empty) |
| `channel.try_receive()` | Non-blocking receive |
| `channel.close()` | Close channel |

### Timer Operations

| Operation | Description |
|---|---|
| `Timer::sleep(duration).await` | Sleep for specified duration |
| `Timer::at(instant).await` | Sleep until specified instant |
| `with_timeout(duration, future).await` | Run future with timeout |

### Sensor Operations (CIBOS-MOBILE)

| Operation | Description |
|---|---|
| `Sensor::request(type).await` | Request sensor access (awaits authorization) |
| `sensor.read_frame().await` | Read camera frame |
| `sensor.read_samples().await` | Read microphone samples |
| `sensor.read_location().await` | Read GPS location |
| `sensor.release()` | Release sensor access |

---

*For system implementation details, see the Developer Guide. For deployment, see the Administrator Guide. For the async runtime internals, see the CIBOS Async Runtime Guide.*
