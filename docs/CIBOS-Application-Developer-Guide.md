# CIBOS Application Developer Guide
**Programming Reference for Application Developers**

## Introduction

This guide covers everything you need to write applications for CIBOS. It explains the execution model, lane architecture, channel communication, and how to structure your application to take advantage of CIBOS's isolation properties and quantum-like computational capabilities.

This guide does not cover system internals. For kernel implementation details, see the Developer Guide. For deployment, see the Administrator Guide.

---

## Chapter 1: The CIBOS Programming Model

### Your Application Is a Container

Every application running on CIBOS runs in its own container — an isolated execution environment with dedicated memory, resource limits, and security boundaries. Your application cannot access memory belonging to other applications. Other applications cannot observe your application's behavior.

This isolation is architectural and unconditional. There is no permission level at which one application can access another's memory. There is no debug mode that bypasses isolation. Isolation is always active.

### Your Execution Unit Is a Lane

Within your container, your application can create lanes. Each lane is an independent execution context with its own memory region and event queue. Your application controls what work each lane does.

The kernel sees only the head event of each lane — the next thing each lane needs to do. The kernel does not see your internal queue depth, your data structures, or your computation in progress.

### You Communicate Through Channels

When your application needs to exchange data with another application, you use channels. Channels require the other application's explicit agreement. Once established, channels carry messages in either or both directions.

Channels are your only authorized inter-application communication mechanism. There is no shared memory between applications, no signals, no shared files accessible to both.

### The Two-Layer Execution Model from the Application Perspective

**Layer 1 (Catch and Release):** When your lane has work and all required resources are available, your lane's head event enters the Ready Pool and is eligible for dispatch. If resources are unavailable, your lane stalls invisibly — no retry loops, no spinning.

**Layer 2 (Dispatch):** When your event is in the Ready Pool, the kernel dispatches it either immediately (if execution contexts are available and no competition exists) or after weighted entropy selection (if competition exists). You do not control or observe this process.

### What "Competition" Means for Your Application

Competition exists when more events are ready than execution contexts are available. In practice:
- On a lightly loaded system, all your ready lanes likely dispatch immediately without selection
- On a heavily loaded system, weighted entropy may delay some of your lanes
- Anti-starvation (when compiled) ensures no lane waits indefinitely in the Ready Pool

### The System Selects Events Probabilistically

When your lane has something ready to execute, the kernel selects your lane's event using weighted entropy selection. You are not guaranteed to be selected immediately. You might be selected very quickly; you might wait through several dispatch opportunities. The selection is probabilistic, determined by your container's weight class relative to other ready events.

This is by design. Deterministic selection order would create observable patterns that could be used for timing attacks. Probabilistic selection provides the non-determinism that enables quantum-like computational properties.

---

## Chapter 2: Working with Lanes

### What Lanes Provide

Lanes provide parallel execution without coordination overhead. When you create multiple lanes, each can execute independently. They do not share memory, do not need locks, and do not coordinate through any mechanism other than channels you explicitly create.

**Key properties:**
- Each lane has isolated memory
- Each lane has an independent event queue
- Lanes execute independently when selected
- No locks between lanes
- No shared mutable state

### Creating Lanes

```
LANE CREATION:

┌─────────────────────────────────────────────────────────────┐
│                    LANE CREATION                             │
│                                                             │
│  BASIC LANE:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Create a lane with default weight                │   │
│  │ // Weight is determined by container's class        │   │
│  │ let lane = Lane::create()?;                         │   │
│  │                                                     │   │
│  │ // Lane ID is assigned by the system                │   │
│  │ println!("Created lane: {}", lane.id());            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  LANE WITH EXPLICIT WEIGHT (Compute Profile Only):         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Create lane with specific weight                 │   │
│  │ // Only available when per-lane-weights compiled    │   │
│  │ let priority_lane = Lane::create_with_weight(5)?;   │   │
│  │ let normal_lane = Lane::create_with_weight(1)?;     │   │
│  │ let background_lane = Lane::create_with_weight(1)?; │   │
│  │                                                     │   │
│  │ // Higher weight = higher selection probability     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Lane Lifecycle

```
LANE LIFECYCLE:

┌─────────────────────────────────────────────────────────────┐
│                    LANE LIFECYCLE                            │
│                                                             │
│  1. Created → INACTIVE                                      │
│  2. Work submitted → Has head event                         │
│  3. Head event ready → May be selected                      │
│  4. Selected → EXECUTING                                    │
│  5. Complete or Stall                                       │
│  6. If complete and more work → New head event              │
│  7. If no more work → INACTIVE                              │
│  8. Destroyed when container ends                           │
│                                                             │
│  STATE TRANSITIONS:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ INACTIVE                                            │   │
│  │    ↓ (work submitted)                              │   │
│  │ READY (in Ready Pool)                              │   │
│  │    ↓ (selected)                                    │   │
│  │ EXECUTING                                           │   │
│  │    ├─→ (completes, more work) → READY              │   │
│  │    ├─→ (completes, no work) → INACTIVE            │   │
│  │    └─→ (resource unavailable) → STALLED           │   │
│  │                                                     │   │
│  │ STALLED                                             │   │
│  │    └─→ (resource available) → READY                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  DESTROYING LANES:                                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Graceful destroy (waits for current event)       │   │
│  │ lane.destroy()?;                                     │   │
│  │                                                     │   │
│  │ // Immediate destroy (cancels pending)              │   │
│  │ lane.destroy_immediate()?;                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Submitting Work to a Lane

```
SUBMITTING WORK:

┌─────────────────────────────────────────────────────────────┐
│                   WORK SUBMISSION                            │
│                                                             │
│  ASYNC WORK:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ lane.submit(async move {                            │   │
│  │     // This closure executes when lane is selected  │   │
│  │     let result = compute(input).await;              │   │
│  │     result                                          │   │
│  │ })?;                                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  WORK WITH ERROR HANDLING:                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ lane.submit(async move {                            │   │
│  │     match perform_work().await {                    │   │
│  │         Ok(result) => {                             │   │
│  │             // Work succeeded                       │   │
│  │             handle_result(result);                  │   │
│  │         }                                           │   │
│  │         Err(e) => {                                 │   │
│  │             // Work failed                          │   │
│  │             log::error!("Work failed: {}", e);      │   │
│  │         }                                           │   │
│  │     }                                               │   │
│  │ })?;                                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MULTIPLE WORK ITEMS:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Lanes process work in FIFO order                 │   │
│  │ // within the lane                                   │   │
│  │ lane.submit(work_item_1)?;                           │   │
│  │ lane.submit(work_item_2)?;                           │   │
│  │ lane.submit(work_item_3)?;                           │   │
│  │                                                     │   │
│  │ // Items execute: 1, then 2, then 3                 │   │
│  │ // Order within lane is guaranteed                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Lane FIFO Ordering

```
LANE FIFO ORDERING:

┌─────────────────────────────────────────────────────────────┐
│                    LANE ORDERING                             │
│                                                             │
│  WITHIN A LANE: FIFO (First-In-First-Out)                  │
│                                                             │
│  Lane Queue:                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ [Head Event A] → [Event B] → [Event C] → [Event D]  │   │
│  │        ↓                                            │   │
│  │   Executing                                          │   │
│  │                                                     │   │
│  │ When A completes, B becomes head                    │   │
│  │ When B completes, C becomes head                    │   │
│  │ When C completes, D becomes head                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ACROSS LANES: NO ORDERING GUARANTEE                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Lane 1: [Event A, Event B]                          │   │
│  │ Lane 2: [Event X, Event Y]                          │   │
│  │ Lane 3: [Event M, Event N]                          │   │
│  │                                                     │   │
│  │ Possible execution order:                           │   │
│  │   A, X, M, B, Y, N  (one possible order)           │   │
│  │   X, A, M, Y, B, N  (another possible order)       │   │
│  │   M, A, X, N, B, Y  (another possible order)       │   │
│  │                                                     │   │
│  │ Selection is by weighted entropy                    │   │
│  │ Order is non-deterministic                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  KEY INSIGHT:                                               │
│  If you need ordering across lanes, use channels           │
│  to coordinate between them.                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### When to Use Multiple Lanes

```
WHEN TO USE MULTIPLE LANES:

┌─────────────────────────────────────────────────────────────┐
│                    USE CASES                                 │
│                                                             │
│  USE MULTIPLE LANES WHEN:                                   │
│                                                             │
│  1. PARALLEL EXPLORATION                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Problem: Explore multiple solution approaches       │   │
│  │ Solution: One lane per approach                     │   │
│  │                                                     │   │
│  │ Lane 1: Approach A                                  │   │
│  │ Lane 2: Approach B                                  │   │
│  │ Lane 3: Approach C                                  │   │
│  │                                                     │   │
│  │ All execute in parallel, no coordination            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  2. PIPELINE PROCESSING                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Problem: Data flows through processing stages       │   │
│  │ Solution: One lane per stage                        │   │
│  │                                                     │   │
│  │ Lane 1: Read input                                  │   │
│  │ Lane 2: Process data                                │   │
│  │ Lane 3: Write output                                │   │
│  │                                                     │   │
│  │ Stages proceed independently                        │   │
│  │ Communication via channels                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  3. OVERLAPPING I/O AND COMPUTE                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Problem: Compute while waiting for I/O              │   │
│  │ Solution: Separate lanes for I/O and compute        │   │
│  │                                                     │   │
│  │ Lane 1: I/O operations (can stall)                  │   │
│  │ Lane 2: Computation (proceeds independently)        │   │
│  │                                                     │   │
│  │ Compute doesn't wait for I/O                        │   │
│  │ I/O doesn't block compute                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  4. INDEPENDENT TASKS                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Problem: Multiple independent tasks                 │   │
│  │ Solution: One lane per task                         │   │
│  │                                                     │   │
│  │ Lane 1: Task 1                                      │   │
│  │ Lane 2: Task 2                                      │   │
│  │ Lane 3: Task 3                                      │   │
│  │                                                     │   │
│  │ Tasks don't interfere with each other               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  DO NOT USE MULTIPLE LANES WHEN:                            │
│                                                             │
│  - Tasks are sequential (one task depends on previous)      │
│  - Single task, single thread is sufficient                │
│  - Tasks require extensive coordination                     │
│  - Memory overhead of multiple lanes is not justified      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 3: Channel Communication

### Channel Basics

```
CHANNEL BASICS:

┌─────────────────────────────────────────────────────────────┐
│                    CHANNEL OVERVIEW                          │
│                                                             │
│  WHAT A CHANNEL IS:                                         │
│  - Point-to-point communication link                       │
│  - Between exactly two containers                          │
│  - Created by mutual agreement                             │
│  - Isolated from other channels                            │
│                                                             │
│  WHAT A CHANNEL IS NOT:                                     │
│  - Not broadcast                                            │
│  - Not routable                                             │
│  - Not discoverable                                         │
│  - Not shared memory                                        │
│                                                             │
│  DIRECTIONALITY:                                            │
│  - One-way: A can send to B, B cannot send to A            │
│  - Bidirectional: Both can send                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Creating Channels

```
CREATING CHANNELS:

┌─────────────────────────────────────────────────────────────┐
│                  CHANNEL CREATION                            │
│                                                             │
│  REQUEST A CHANNEL:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let request = ChannelRequest {                      │   │
│  │     target: other_container_id,                     │   │
│  │     terms: ChannelTerms {                           │   │
│  │         direction: Direction::Bidirectional,        │   │
│  │         rate_limit: Some(RateLimit::MessagesPerSec(1000)),│
│  │         buffer_size: 256,                           │   │
│  │         lifetime: ChannelLifetime::Permanent,       │   │
│  │     },                                              │   │
│  │ };                                                   │   │
│  │                                                      │   │
│  │ let channel = Channel::request(request).await?;     │   │
│  │ // This awaits acceptance from the target           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ACCEPT INCOMING REQUEST:                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Wait for incoming channel request                │   │
│  │ let incoming = container.await_channel_request().await?;│
│  │                                                      │   │
│  │ // Accept with original terms                        │   │
│  │ let channel = incoming.accept()?;                   │   │
│  │                                                      │   │
│  │ // Or reject                                         │   │
│  │ incoming.reject(Some("Reason"));                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Channel Terms Are Not Negotiable

**Important:** B cannot modify terms and send a counter-proposal. The options are accept-all or reject. If different terms are needed:
1. B rejects
2. A sends a new request with modified terms
3. B accepts or rejects the new request

This is application-level logic, not kernel negotiation. Terms are defined by the proposing application's design and are not dynamically negotiable between applications.

### Sending and Receiving Messages

```
SENDING AND RECEIVING:

┌─────────────────────────────────────────────────────────────┐
│                 MESSAGE OPERATIONS                           │
│                                                             │
│  SEND MESSAGE:                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let message = Message::new()                        │   │
│  │     .data(my_data)                                   │   │
│  │     .priority(Priority::Normal);                    │   │
│  │                                                      │   │
│  │ channel.send(message).await?;                        │   │
│  │                                                      │   │
│  │ // If channel buffer is full:                        │   │
│  │ // - This operation stalls                          │   │
│  │ // - No retry loop needed                           │   │
│  │ // - Resumes when buffer space available            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  RECEIVE MESSAGE:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let message = channel.receive().await?;             │   │
│  │                                                      │   │
│  │ // If channel buffer is empty:                       │   │
│  │ // - This operation stalls                          │   │
│  │ // - No retry loop needed                           │   │
│  │ // - Resumes when message available                 │   │
│  │                                                      │   │
│  │ process(message.data());                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  NON-BLOCKING OPERATIONS:                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Try to receive without stalling                   │   │
│  │ match channel.try_receive() {                        │   │
│  │     Some(message) => process(message),              │   │
│  │     None => {                                       │   │
│  │         // No message available, do other work       │   │
│  │         do_other_work();                             │   │
│  │     }                                               │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Channel Rate Limits

```
RATE LIMITS:

┌─────────────────────────────────────────────────────────────┐
│                    RATE LIMITS                               │
│                                                             │
│  SETTING RATE LIMITS:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ChannelTerms {                                      │   │
│  │     rate_limit: Some(RateLimit::MessagesPerSec(1000)),│
│  │     // Or:                                          │   │
│  │     rate_limit: Some(RateLimit::BytesPerSec(1024*1024)),│
│  │     // Or:                                          │   │
│  │     rate_limit: None, // No limit                   │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  WHAT RATE LIMITS DO:                                       │
│  - Enforced by the kernel                                   │
│  - Sender cannot exceed limit                               │
│  - Sends above limit stall until rate window resets        │
│                                                             │
│  WHY USE RATE LIMITS:                                       │
│  - Protect receiver from being overwhelmed                 │
│  - Establish behavioral contract                            │
│  - Prevent one fast sender from starving others            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Channel Error Handling

```
CHANNEL ERRORS:

┌─────────────────────────────────────────────────────────────┐
│                  ERROR HANDLING                              │
│                                                             │
│  COMMON ERRORS:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ChannelError::Closed                                │   │
│  │   // Channel was closed                             │   │
│  │   // Cannot send or receive                         │   │
│  │                                                      │   │
│  │ ChannelError::RateLimited                           │   │
│  │   // Rate limit exceeded                            │   │
│  │   // Wait for rate window reset                     │   │
│  │                                                      │   │
│  │ ChannelError::Rejected                              │   │
│  │   // Channel request was rejected                   │   │
│  │   // Target refused the channel                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  HANDLING CLOSED CHANNEL:                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ match channel.receive().await {                     │   │
│  │     Ok(message) => process(message),                │   │
│  │     Err(ChannelError::Closed) => {                  │   │
│  │         // Channel closed by other end              │   │
│  │         cleanup();                                   │   │
│  │         maybe_reconnect();                           │   │
│  │     }                                               │   │
│  │     Err(e) => {                                      │   │
│  │         // Other error                               │   │
│  │         log::error!("Channel error: {}", e);        │   │
│  │     }                                               │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 4: Resource Awareness

### What Resources Can Cause Stalls

```
RESOURCES:

┌─────────────────────────────────────────────────────────────┐
│                  STALL CAUSES                                │
│                                                             │
│  MEMORY:                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Cause: Container memory limit exceeded              │   │
│  │ Effect: Allocation stalls                           │   │
│  │ Resolution: Free memory within container            │   │
│  │                                                     │   │
│  │ Example:                                            │   │
│  │   let data = vec![0u8; 1024*1024]; // 1 MB         │   │
│  │   // If limit exceeded, this stalls                │   │
│  │   // No OOM crash - system waits                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CHANNEL BUFFERS:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Cause: Send to full buffer                          │   │
│  │ Effect: Send operation stalls                       │   │
│  │ Resolution: Receiver reads from buffer               │   │
│  │                                                     │   │
│  │ Cause: Receive from empty buffer                    │   │
│  │ Effect: Receive operation stalls                    │   │
│  │ Resolution: Sender writes to buffer                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  I/O OPERATIONS:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Cause: Disk/network operation pending               │   │
│  │ Effect: Operation stalls until complete             │   │
│  │ Resolution: Hardware signals completion             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Stalls Are Transparent

When your application stalls, you do not need to detect or handle it. Your application's execution simply pauses at the stalling operation and resumes when the resource becomes available. There are no retry loops needed. The kernel handles everything.

```rust
// This is wrong — never do this
while !resource_available() {
    sleep(10ms);
}

// This is right — let the kernel handle it
let data = allocate(size).await?;
// If unavailable, stalls transparently until available
```

### Designing for Resource Constraints

```
DESIGN PRINCIPLES:

┌─────────────────────────────────────────────────────────────┐
│                 DESIGN GUIDELINES                            │
│                                                             │
│  1. KNOW YOUR LIMITS                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let limits = container.get_resource_limits();       │   │
│  │ println!("Memory limit: {} MB", limits.memory_mb);  │   │
│  │ println!("Channels: {}", limits.max_channels);      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  2. WORK WITHIN LIMITS                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Don't assume unlimited resources                 │   │
│  │ // Design for your limits                           │   │
│  │                                                     │   │
│  │ // Bad: Assume infinite memory                      │   │
│  │ let all_data = load_everything();                   │   │
│  │                                                     │   │
│  │ // Good: Work in chunks                             │   │
│  │ loop {                                              │   │
│  │     let chunk = load_chunk(CHUNK_SIZE)?;            │   │
│  │     if chunk.is_empty() { break; }                  │   │
│  │     process(chunk);                                 │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  3. RELEASE PROMPTLY                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Free resources when done                         │   │
│  │ let buffer = allocate(size)?;                        │   │
│  │ use(buffer);                                         │   │
│  │ deallocate(buffer)?; // Free for other lanes        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  4. DESIGN FOR LATENCY                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Execution may be delayed                          │   │
│  │ // Design to handle variable timing                  │   │
│  │                                                     │   │
│  │ async fn process() {                                │   │
│  │     // Work may be delayed - that's fine            │   │
│  │     // Kernel will schedule when ready              │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Handling Execution Latency

```
EXECUTION LATENCY:

┌─────────────────────────────────────────────────────────────┐
│                   LATENCY HANDLING                           │
│                                                             │
│  LATENCY SOURCES:                                           │
│  - Other containers competing for execution                 │
│  - Resource unavailability                                 │
│  - Weight class relative to other ready events             │
│                                                             │
│  DESIGN APPROACH:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Don't assume immediate execution                 │   │
│  │ // Don't retry - let the kernel handle it           │   │
│  │                                                     │   │
│  │ // Wrong:                                           │   │
│  │ while !try_execute() {                              │   │
│  │     sleep(100ms); // Don't do this                  │   │
│  │ }                                                    │   │
│  │                                                     │   │
│  │ // Right:                                           │   │
│  │ execute().await; // Kernel handles timing           │   │
│  │ // You'll execute when selected                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  IF YOU NEED A TIMEOUT:                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Application-level timeout                         │   │
│  │ match timeout(Duration::from_secs(30), operation()).await {│
│  │     Ok(result) => handle(result),                   │   │
│  │     Err(Timeout) => {                               │   │
│  │         // Operation didn't complete in time         │   │
│  │         // May still be pending or stalled          │   │
│  │         handle_timeout();                            │   │
│  │     }                                               │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Timer-Based Operations

```rust
// Sleep for 100 milliseconds
Timer::sleep(Duration::from_millis(100)).await;

// Set a timeout on an operation
let result = with_timeout(Duration::from_secs(5), async {
    channel.receive().await
}).await;

match result {
    Ok(Ok(message)) => process(message),
    Ok(Err(e)) => handle_channel_error(e),
    Err(TimeoutError) => handle_timeout(),
}
```

Timers work through the kernel's timer event mechanism. When you call `sleep`, the kernel registers a timer event. When the timer fires, the timer event enters the Ready Pool and your lane competes for dispatch. You do not hold CPU while sleeping.

---

## Chapter 5: Quantum-Like Programming Patterns

CIBOS's lane architecture enables quantum-like parallel computation. All lane results are preserved — there is no collapse. One run is sufficient.

### Parallel Pathway Maintenance

```
PARALLEL PATHWAYS:

┌─────────────────────────────────────────────────────────────┐
│               PARALLEL PATHWAY PATTERN                       │
│                                                             │
│  CONCEPT:                                                   │
│  Create multiple lanes for multiple approaches.            │
│  All execute in parallel.                                  │
│  Collect results when done.                                │
│  No collapse - all results preserved.                      │
│                                                             │
│  IMPLEMENTATION:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ async fn parallel_search(problem: Problem) -> Solution {│
│  │     // Create lanes for each approach                │   │
│  │     let lane1 = Lane::create()?;                     │   │
│  │     let lane2 = Lane::create()?;                     │   │
│  │     let lane3 = Lane::create()?;                     │   │
│  │                                                      │   │
│  │     // Result collection channel                     │   │
│  │     let (sender, receiver) = Channel::new_local();   │   │
│  │                                                      │   │
│  │     // Submit each approach                          │   │
│  │     let s1 = sender.clone();                         │   │
│  │     lane1.submit(async move {                        │   │
│  │         let solution = approach_a(&problem).await;   │   │
│  │         s1.send(solution).await                      │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     let s2 = sender.clone();                         │   │
│  │     lane2.submit(async move {                        │   │
│  │         let solution = approach_b(&problem).await;   │   │
│  │         s2.send(solution).await                      │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     let s3 = sender.clone();                         │   │
│  │     lane3.submit(async move {                        │   │
│  │         let solution = approach_c(&problem).await;   │   │
│  │         s3.send(solution).await                      │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     // Collect first result                          │   │
│  │     let first = receiver.receive().await?;           │   │
│  │                                                      │   │
│  │     // Or collect all results                        │   │
│  │     let results = vec![                              │   │
│  │         receiver.receive().await?,                   │   │
│  │         receiver.receive().await?,                   │   │
│  │         receiver.receive().await?,                   │   │
│  │     ];                                               │   │
│  │                                                      │   │
│  │     // Select best or combine                        │   │
│  │     best_solution(results)                           │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Data Parallelism

```
DATA PARALLELISM:

┌─────────────────────────────────────────────────────────────┐
│                  DATA PARALLEL PATTERN                       │
│                                                             │
│  CONCEPT:                                                   │
│  Split data into chunks.                                    │
│  Process each chunk in separate lane.                       │
│  Collect and combine results.                               │
│                                                             │
│  IMPLEMENTATION:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ async fn parallel_process(data: Vec<Data>) -> Vec<Result> {│
│  │     let num_lanes = 4;                               │   │
│  │     let chunk_size = data.len() / num_lanes;         │   │
│  │                                                      │   │
│  │     let (sender, receiver) = Channel::new_local();   │   │
│  │                                                      │   │
│  │     for i in 0..num_lanes {                          │   │
│  │         let lane = Lane::create()?;                  │   │
│  │         let chunk = data[i*chunk_size..(i+1)*chunk_size].to_vec();│
│  │         let s = sender.clone();                       │   │
│  │         lane.submit(async move {                     │   │
│  │             let result = process_chunk(chunk).await; │   │
│  │             s.send((i, result)).await                │   │
│  │         })?;                                         │   │
│  │     }                                                │   │
│  │                                                      │   │
│  │     // Collect all results                           │   │
│  │     let mut results = vec![None; num_lanes];         │   │
│  │     for _ in 0..num_lanes {                          │   │
│  │         let (index, result) = receiver.receive().await?;│
│  │         results[index] = Some(result);               │   │
│  │     }                                                │   │
│  │                                                      │   │
│  │     results.into_iter().flatten().collect()          │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Pipeline Processing

```
PIPELINE PATTERN:

┌─────────────────────────────────────────────────────────────┐
│                   PIPELINE PATTERN                           │
│                                                             │
│  CONCEPT:                                                   │
│  Each processing stage in separate lane.                    │
│  Stages proceed independently.                              │
│  Overlapped execution for throughput.                       │
│                                                             │
│  IMPLEMENTATION:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ async fn pipeline(input: InputChannel) -> OutputChannel {│
│  │     let read_lane = Lane::create()?;                 │   │
│  │     let process_lane = Lane::create()?;              │   │
│  │     let write_lane = Lane::create()?;                │   │
│  │                                                      │   │
│  │     // Channels between stages                       │   │
│  │     let (raw_sender, raw_receiver) = Channel::new(); │   │
│  │     let (proc_sender, proc_receiver) = Channel::new();│
│  │                                                      │   │
│  │     // Stage 1: Read                                 │   │
│  │     read_lane.submit(async move {                    │   │
│  │         while let Ok(data) = input.receive().await { │   │
│  │             raw_sender.send(data).await;             │   │
│  │         }                                            │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     // Stage 2: Process                              │   │
│  │     process_lane.submit(async move {                 │   │
│  │         while let Ok(raw) = raw_receiver.receive().await {│
│  │             let processed = transform(raw).await;    │   │
│  │             proc_sender.send(processed).await;       │   │
│  │         }                                            │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     // Stage 3: Write                                │   │
│  │     write_lane.submit(async move {                   │   │
│  │         while let Ok(processed) = proc_receiver.receive().await {│
│  │             output.send(processed).await;            │   │
│  │         }                                            │   │
│  │     })?;                                             │   │
│  │                                                      │   │
│  │     output                                            │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  BENEFIT:                                                   │
│  Reading, processing, writing all happen simultaneously.    │
│  When stage 2 is processing chunk N,                        │
│  stage 1 can read chunk N+1,                                │
│  stage 3 can write chunk N-1.                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Application-Controlled Resolution

```
RESOLUTION:

┌─────────────────────────────────────────────────────────────┐
│                 RESOLUTION CONTROL                           │
│                                                             │
│  QUANTUM COLLAPSE (Quantum Computing):                      │
│  - Physics-imposed                                         │
│  - Destroys unselected states                               │
│  - Requires repeated runs                                   │
│  - Information lost                                        │
│                                                             │
│  APPLICATION-CONTROLLED RESOLUTION (CIBOS):                 │
│  - Application decides when                                │
│  - Application decides how                                 │
│  - All results preserved                                    │
│  - One run sufficient                                      │
│                                                             │
│  EXAMPLE:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // All lanes running                                │   │
│  │ let lanes = create_lanes(4)?;                        │   │
│  │ let results = collect_all(lanes).await?;             │   │
│  │                                                      │   │
│  │ // Application decides how to resolve                │   │
│  │                                                      │   │
│  │ // Option 1: Take first result                       │   │
│  │ let first = results.into_iter().next()?;             │   │
│  │                                                      │   │
│  │ // Option 2: Take best result                        │   │
│  │ let best = results.into_iter()                       │   │
│  │     .max_by_key(|r| r.quality_score())?;             │   │
│  │                                                      │   │
│  │ // Option 3: Combine all results                     │   │
│  │ let combined = combine_all(results);                 │   │
│  │                                                      │   │
│  │ // Option 4: Use all results                         │   │
│  │ for result in results {                              │   │
│  │     analyze(result);                                 │   │
│  │ }                                                    │   │
│  │                                                      │   │
│  │ // No collapse - application controls resolution      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 6: Per-Lane Weights (Compute Profile)

### When Per-Lane Weights Are Available

Per-lane weights are only available when the `per-lane-weights` feature is compiled in (Compute Profile). In other profiles, all lanes use the container's weight class.

### Assigning Weights

```
PER-LANE WEIGHTS:

┌─────────────────────────────────────────────────────────────┐
│                  PER-LANE WEIGHTS                            │
│                                                             │
│  WHEN TO USE:                                               │
│  - Application has internal priority                        │
│  - Some computations more time-sensitive than others        │
│  - User-facing vs background work                           │
│                                                             │
│  HOW TO ASSIGN:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // High-priority main computation                    │   │
│  │ let primary = Lane::create_with_weight(5)?;          │   │
│  │                                                      │   │
│  │ // Secondary support computation                     │   │
│  │ let support = Lane::create_with_weight(2)?;          │   │
│  │                                                      │   │
│  │ // Background cleanup                                │   │
│  │ let cleanup = Lane::create_with_weight(1)?;          │   │
│  │                                                      │   │
│  │ // With weights 5:2:1,                               │   │
│  │ // Primary: 5/8 = 62.5% selection probability        │   │
│  │ // Support: 2/8 = 25% selection probability          │   │
│  │ // Cleanup: 1/8 = 12.5% selection probability        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  WHEN NOT TO USE:                                           │
│  - All lanes are peers                                      │
│  - No internal priority                                     │
│  - Equal weight is correct                                  │
│                                                             │
│  // All lanes equal - default                               │
│  let lane = Lane::create()?; // Weight = container class    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 7: Error Handling

### Stall Handling

```
STALL HANDLING:

┌─────────────────────────────────────────────────────────────┐
│                    STALL HANDLING                            │
│                                                             │
│  WHAT STALL MEANS:                                          │
│  - Operation cannot proceed                                 │
│  - Kernel is waiting for resource                           │
│  - NOT an error                                             │
│  - Will resume when resource available                      │
│                                                             │
│  APPLICATION BEHAVIOR:                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Don't detect or handle stalls                     │   │
│  │ // Let the kernel manage them                        │   │
│  │                                                      │   │
│  │ // Stalls are transparent                           │   │
│  │ async fn process() {                                 │   │
│  │     // This may stall if memory unavailable          │   │
│  │     let data = allocate(size).await?;                │   │
│  │                                                      │   │
│  │     // This may stall if channel full               │   │
│  │     channel.send(message).await?;                    │   │
│  │                                                      │   │
│  │ // No retry, no polling                             │   │
│  │ // Kernel will resume when resources available       │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Resource Exhaustion

```
RESOURCE EXHAUSTION:

┌─────────────────────────────────────────────────────────────┐
│                 RESOURCE EXHAUSTION                          │
│                                                             │
│  MEMORY EXHAUSTION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // If you need to detect before stall               │   │
│  │ let available = container.memory_available();       │   │
│  │                                                      │   │
│  │ if size > available {                                │   │
│  │     // Handle before attempting allocation          │   │
│  │     reduce_working_set();                            │   │
│  │ } else {                                             │   │
│  │     let data = allocate(size).await?;                │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CHANNEL EXHAUSTION:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Channel buffer full - send stalls                 │   │
│  │ // This is normal flow control                       │   │
│  │ channel.send(message).await?;                        │   │
│  │                                                      │   │
│  │ // If you need to avoid stall                        │   │
│  │ if channel.buffer_space() > 0 {                      │   │
│  │     channel.send(message).await?;                    │   │
│  │ } else {                                             │   │
│  │     // Buffer full, do other work                    │   │
│  │     handle_backpressure();                            │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Graceful Degradation

```
GRACEFUL DEGRADATION:

┌─────────────────────────────────────────────────────────────┐
│                GRACEFUL DEGRADATION                          │
│                                                             │
│  UNDER PRESSURE:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ async fn process_with_fallback() {                  │   │
│  │     let resources = container.resource_state();     │   │
│  │                                                      │   │
│  │     if resources.memory_available > threshold {      │   │
│  │         // Full quality processing                   │   │
│  │         full_quality_process().await                 │   │
│  │     } else {                                         │   │
│  │         // Reduced quality, less memory              │   │
│  │         degraded_process().await                     │   │
│  │     }                                                │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  WITH TIMEOUTS:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Application-level timeout                         │   │
│  │ match timeout(Duration::from_secs(30), operation()).await {│
│  │     Ok(result) => handle(result),                   │   │
│  │     Err(Timeout) => {                               │   │
│  │         // Operation timed out                       │   │
│  │         // May still be pending                      │   │
│  │         fallback_approach();                         │   │
│  │     }                                               │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Application Crashes

If your application crashes (panic, illegal memory access, unhandled error), the kernel isolates the crash to your container. Other applications continue running. Design for graceful degradation:
- Handle errors explicitly rather than panicking
- Log errors to your application's storage before they become fatal
- Implement restart logic that recovers from partial state

---

## Chapter 8: Debugging

### Observing Execution

```
DEBUGGING:

┌─────────────────────────────────────────────────────────────┐
│                    DEBUGGING                                 │
│                                                             │
│  ADD OBSERVABILITY:                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Add logging at key points                        │   │
│  │ log::debug!("Lane {} starting task", lane.id());    │   │
│  │                                                      │   │
│  │ // Check resource state                              │   │
│  │ let state = container.get_resource_state();         │   │
│  │ log::debug!("Memory: {} / {}",                       │   │
│  │     state.memory_used,                              │   │
│  │     state.memory_limit                              │   │
│  │ );                                                   │   │
│  │                                                      │   │
│  │ // Log channel state                                 │   │
│  │ log::debug!("Channel {} pending: {}",                │   │
│  │     channel.id(),                                   │   │
│  │     channel.pending_messages()                       │   │
│  │ );                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  DETECT STALLS:                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Add stall detection                              │   │
│  │ async fn detect_stall() {                            │   │
│  │     let start = Instant::now();                      │   │
│  │     let result = operation().await;                  │   │
│  │     let duration = start.elapsed();                  │   │
│  │                                                      │   │
│  │     if duration > Duration::from_secs(1) {           │   │
│  │         log::warn!("Long wait: {:?}", duration);    │   │
│  │     }                                                │   │
│  │                                                      │   │
│  │     result                                            │   │
│  │ }                                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Performance Analysis

```
PERFORMANCE:

┌─────────────────────────────────────────────────────────────┐
│                  PERFORMANCE ANALYSIS                        │
│                                                             │
│  MEASURE THROUGHPUT:                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let start = Instant::now();                          │   │
│  │ let count = process_batch().await?;                  │   │
│  │ let duration = start.elapsed();                       │   │
│  │ let throughput = count as f64 / duration.as_secs_f64();│
│  │ log::info!("Throughput: {:.2} ops/sec", throughput); │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  MEASURE LATENCY:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let start = Instant::now();                          │   │
│  │ let result = operation().await?;                      │   │
│  │ let latency = start.elapsed();                        │   │
│  │ log::info!("Latency: {:?}", latency);                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  TRACK RESOURCE USAGE:                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ let before = container.memory_used();                │   │
│  │ process().await?;                                    │   │
│  │ let after = container.memory_used();                 │   │
│  │ log::debug!("Memory delta: {} bytes", after - before);│
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Common Pitfalls

```
PITFALLS:

┌─────────────────────────────────────────────────────────────┐
│                    COMMON PITFALLS                           │
│                                                             │
│  1. ASSUMING ORDERING                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Wrong: Assume lanes execute in order              │   │
│  │ lane1.submit(task1)?;                                │   │
│  │ lane2.submit(task2)?;                                │   │
│  │ // task1 may execute after task2                     │   │
│  │                                                      │   │
│  │ // Right: Use channels for ordering                  │   │
│  │ lane1.submit(task1_then_send_to(channel))?;          │   │
│  │ lane2.submit(wait_for_channel_then_task2(channel))?; │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  2. SPIN-WAITING                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Wrong: Spin-wait                                  │   │
│  │ while !resource_available() {                        │   │
│  │     // Don't do this                                 │   │
│  │ }                                                    │   │
│  │                                                      │   │
│  │ // Right: Event-driven                              │   │
│  │ wait_for_resource().await?;                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  3. HOLDING RESOURCES                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ // Wrong: Hold resource for entire operation         │   │
│  │ let lock = acquire();                                │   │
│  │ do_everything();                                     │   │
│  │ release(lock);                                       │   │
│  │                                                      │   │
│  │ // Right: Release promptly                          │   │
│  │ let resource = acquire().await?;                     │   │
│  │ let data = read(resource);                           │   │
│  │ release(resource);                                   │   │
│  │ process(data);                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Chapter 9: Security Considerations for Application Developers

### What Isolation Provides

Your application's memory is private by architecture. Your application's execution timing is not observable by other applications. Your communication is through explicitly established channels that you control.

### What Applications Still Need to Handle

**Channel-borne data:** Messages received on channels come from the other application. Validate all input received through channels.

**File system data:** Data read from storage was written at some prior time. Validate stored data on read.

**External data:** Any data entering your application from outside must be treated as potentially malformed.

---

## Chapter 10: Compute Profile Specifics

### Lightweight Handshake Communication

Compute profile uses lightweight handshake IPC. Channel establishment verifies identity once. Subsequent messages flow without per-message cryptographic overhead. This is not a security compromise in an air-gapped, single-user environment.

Application code is identical regardless of IPC mode — the system configuration determines which mode is in use.

### No RTRO

Compute profile has no RTRO. System metrics (CPU usage, memory usage, event timing) are accurate. This is beneficial for performance analysis and workload monitoring.

### Maximum Computation Throughput

The combination of:
- Equal weights (or per-lane weights) maximizing selection fairness
- No RTRO overhead
- Lightweight handshake (no per-message cryptographic overhead)
- SMT enabled (maximum execution contexts)
- Anti-starvation optional (minimal or no overhead)

...makes Compute profile the highest-throughput configuration for parallel computation workloads.

---

## Chapter 11: Application State and Persistence

### Your Isolation Boundary

Your container's memory is private by architecture. No other application can read or write it. All shared state with other applications must go through channels.

### Persistent State

Applications can write persistent state to storage through the file system interface. Each application sees only its authorized file system region. Storage access goes through the kernel's I/O system and may cause stalls.

### State Across Application Restart

When your container restarts (crash or intentional restart), memory state is lost. Design for graceful restarts:
- Write checkpoints to storage periodically for long-running computations
- On startup, check for a checkpoint and resume from it if found
- Handle the case where no checkpoint exists (fresh start)

---

## Appendix: Quick Reference

### Lane Operations

| Operation | Description |
|---|---|
| `Lane::create()` | Create lane with container's weight class |
| `Lane::create_with_weight(n)` | Create lane with explicit weight (Compute profile) |
| `lane.submit(future)` | Submit async event to lane |
| `lane.destroy()` | Destroy lane after current event completes |
| `lane.destroy_immediate()` | Destroy lane immediately, cancel pending events |

### Channel Operations

| Operation | Description |
|---|---|
| `Channel::request(request)` | Request channel (awaits acceptance) |
| `container.await_channel_request()` | Wait for incoming request |
| `incoming.accept()` | Accept all proposed terms |
| `incoming.reject()` | Reject the request |
| `channel.send(data).await` | Send message (stalls if buffer full) |
| `channel.receive().await` | Receive message (stalls if buffer empty) |
| `channel.try_receive()` | Non-blocking receive |
| `channel.close()` | Close the channel |

### Timer Operations

| Operation | Description |
|---|---|
| `Timer::sleep(duration).await` | Sleep for specified duration |
| `Timer::at(instant).await` | Sleep until specified instant |
| `with_timeout(duration, future).await` | Run future with timeout |

### Resource Query

| Operation | Description |
|---|---|
| `container.memory_usage()` | Current memory usage |
| `container.memory_limit()` | Memory limit for this container |
| `container.channel_count()` | Number of active channels |

---

*This Application Developer Guide covers writing applications for CIBOS. For system implementation details, see the Developer Guide. For deployment configuration, see the Administrator Guide.*
