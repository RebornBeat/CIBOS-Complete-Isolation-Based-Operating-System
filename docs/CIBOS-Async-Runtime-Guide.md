# CIBOS Async Runtime Guide
**Implementation Reference: Building the HIP-Native Async Runtime**

## Introduction

CIBOS requires its own async runtime because standard runtimes (Tokio, async-std) use global task queues with locks — architecturally incompatible with HIP. This guide documents the design and implementation of the CIBOS async runtime that uses Rust's executor-agnostic `Future` trait to delegate all waiting to the kernel's Catch and Release mechanism.

---

## Chapter 1: Why a Custom Runtime Is Required

### The Fundamental Incompatibility

```
STANDARD RUNTIME (TOKIO) — INCOMPATIBLE:

┌─────────────────────────────────────────────────────────────────────────────┐
│  Global Task Queue (LOCKED)                                                 │
│  ┌──────────────────────────────────────────────┐                           │
│  │ Task 1, Task 2, Task 3, ... Task N           │ ← Mutex HERE              │
│  └──────────────────────────────────────────────┘                           │
│  Multiple threads steal tasks — COORDINATION REQUIRED                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                                     │
│  │Thread 1 │◄─│Thread 2 │◄─│Thread 3 │  ← MORE LOCKS (work stealing)       │
│  └─────────┘  └─────────┘  └─────────┘                                     │
│                                                                             │
│  This model REQUIRES locks.                                                  │
│  Cannot be "made lock-free" — design assumes shared mutable task queue.     │
└─────────────────────────────────────────────────────────────────────────────┘

CIBOS ASYNC RUNTIME — COMPATIBLE:

┌─────────────────────────────────────────────────────────────────────────────┐
│  Per-Lane Task Queues (NO LOCKS — each lane owns its queue)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                                  │
│  │ Lane 1 Q │  │ Lane 2 Q │  │ Lane N Q │  ← Each lane-local, single owner │
│  │ HEAD     │  │ HEAD     │  │ HEAD     │                                   │
│  │ only     │  │ only     │  │ only     │                                   │
│  │ visible  │  │ visible  │  │ visible  │                                   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                                  │
│       └─────────────┼─────────────┘                                         │
│                     │                                                       │
│                     ▼                                                       │
│            ┌─────────────────┐                                              │
│            │    SELECTOR     │ (single owner, no locks)                     │
│            │ Owns Ready Pool │                                              │
│            │ Owns Stalled List│                                             │
│            └─────────────────┘                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Rust Works

Rust's `Future` trait is executor-agnostic. The `.await` syntax describes dependencies, not coordination. A CIBOS-specific async runtime implements the same `Future` and `Waker` traits using Catch and Release instead of global task queues.

No new language is needed. No changes to the Rust language are needed. Only a different executor implementation.

---

## Chapter 2: Repository Location

```
async-runtime/
├── Cargo.toml
└── src/
    ├── lib.rs              # Public API, KernelInterface trait
    ├── executor.rs         # LaneExecutor, CibosWaker
    ├── timer.rs            # Timer/sleep futures
    ├── channel.rs          # HIP-native async channel futures
    ├── resource.rs         # Generic resource waiting future
    └── macros.rs           # #[cibos::main] macro
```

---

## Chapter 3: Core Abstractions

### KernelInterface Trait

```rust
/// Interface between async runtime and kernel
/// Implemented by the kernel, used by the async runtime
pub trait KernelInterface: Send + Sync {
    /// Register that a lane is waiting for a resource
    /// Called when a Future returns Poll::Pending
    fn register_wait(&self, lane_id: Uuid, resource: Resource);

    /// Signal that a lane has work ready (should be dispatched)
    /// Called by Waker::wake() when a resource becomes available
    fn signal_ready(&self, lane_id: Uuid);

    /// Get current time (for timer futures)
    fn now(&self) -> Instant;

    /// Set lane weight (per-lane-weights feature)
    #[cfg(feature = "per-lane-weights")]
    fn set_lane_weight(&self, lane_id: Uuid, weight: u32);

    /// Update lane weight at runtime (dynamic-weights feature)
    #[cfg(feature = "dynamic-weights")]
    fn update_lane_weight(&self, lane_id: Uuid, new_weight: u32)
        -> Result<(), WeightUpdateError>;
}

/// Resources that can be waited for
#[derive(Debug, Clone, Copy)]
pub enum Resource {
    ChannelData(Uuid),      // Channel has data to receive
    ChannelBuffer(Uuid),    // Channel has buffer space to send
    Memory(u64),            // Memory allocation of specified bytes
    DiskIO(Uuid),           // Disk I/O operation complete
    NetworkIO(Uuid),        // Network I/O operation complete
    Timer(Instant),         // Timer deadline reached
}
```

### LaneExecutor

```rust
/// The executor for a single lane
/// Lane-local — NO global state, NO locks
pub struct LaneExecutor {
    lane_id: Uuid,
    container_id: Uuid,
    /// Lane-local task queue — single owner, no locks needed
    tasks: VecDeque<LaneTask>,
    kernel: Arc<dyn KernelInterface>,
}

impl LaneExecutor {
    /// Submit a task to this lane's queue
    /// Called by Lane::submit()
    pub fn submit<F: Future<Output = ()> + Send + 'static>(&mut self, future: F) {
        let was_empty = self.tasks.is_empty();
        self.tasks.push_back(LaneTask { future: Box::pin(future) });

        // If this is now the only task, signal kernel that lane has work
        if was_empty {
            self.kernel.signal_ready(self.lane_id);
        }
    }

    /// Poll the head task — called by kernel when lane is dispatched
    pub fn poll_head(&mut self) -> Poll<()> {
        let task = match self.tasks.front_mut() {
            Some(t) => t,
            None => return Poll::Ready(()),
        };

        let waker = self.create_waker();
        let mut cx = Context::from_waker(&waker);

        match task.future.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {
                self.tasks.pop_front();
                // If more tasks, signal kernel
                if !self.tasks.is_empty() {
                    self.kernel.signal_ready(self.lane_id);
                }
                Poll::Ready(())
            }
            Poll::Pending => {
                // Waker was registered with kernel inside the poll() call
                // Kernel will call wake() when resource becomes available
                Poll::Pending
            }
        }
    }
}
```

### CibosWaker

```rust
/// Waker for CIBOS lanes
/// Signals the kernel via message — no global queue, no locks
struct CibosWakerData {
    lane_id: Uuid,
    container_id: Uuid,
    kernel: Arc<dyn KernelInterface>,
}

static CIBOS_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    cibos_waker_clone,
    cibos_waker_wake,
    cibos_waker_wake_by_ref,
    cibos_waker_drop,
);

unsafe fn cibos_waker_wake(data: *const ()) {
    let arc = Arc::from_raw(data as *const CibosWakerData);

    // Signal to kernel: this lane has work to do
    // Kernel decides WHEN to poll — based on Catch and Release
    // This is triggering, not coordination
    arc.kernel.signal_ready(arc.lane_id);

    // Arc dropped here
}
// wake() does NOT poll directly
// It signals the kernel; kernel manages scheduling
// No locks, no coordination, no global state
```

---

## Chapter 4: HIP-Native Async Primitives

### Timer Future

```rust
pub struct Sleep {
    deadline: Instant,
    kernel: Arc<dyn KernelInterface>,
    lane_id: Uuid,
    registered: bool,
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let now = self.kernel.now();

        if now >= self.deadline {
            return Poll::Ready(());
        }

        if !self.registered {
            // Register timer with kernel — no thread sleeping
            self.kernel.register_wait(
                self.lane_id,
                Resource::Timer(self.deadline),
            );
            self.registered = true;
        }

        Poll::Pending
        // Kernel will call wake() when timer fires
        // Timer fires → ResourceAvailable signal
        // Kernel qualifies ALL resources for this lane
        // Lane moves to Ready Pool → dispatched → resumes here
    }
}

/// Public API
pub fn sleep(duration: Duration) -> Sleep {
    // Sleep created with kernel reference and lane_id
    // (obtained from ambient context or passed explicitly)
}
```

### Async Channel Future

```rust
pub struct Receive<'a, T> {
    channel: &'a AsyncChannel<T>,
    registered: bool,
}

impl<'a, T> Future for Receive<'a, T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Try to receive (non-blocking)
        if let Some(value) = self.channel.try_receive() {
            return Poll::Ready(Some(value));
        }

        // Channel empty — register wait with kernel
        if !self.registered {
            self.channel.kernel.register_wait(
                self.channel.lane_id,
                Resource::ChannelData(self.channel.inner.id()),
            );
            self.registered = true;
        }

        Poll::Pending
        // Kernel will call wake() when data arrives
        // ChannelData resource available → qualify ALL lane resources
        // Lane → Ready Pool → dispatch → poll again → Poll::Ready(data)
    }
}

pub struct Send<'a, T> {
    channel: &'a AsyncChannel<T>,
    value: Option<T>,
    registered: bool,
}

impl<'a, T> Future for Send<'a, T> {
    type Output = Result<(), ChannelError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(value) = self.value.take() {
            match self.channel.try_send(value) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(v) => { self.value = Some(v); }
            }
        }

        // Buffer full — register wait with kernel
        if !self.registered {
            self.channel.kernel.register_wait(
                self.channel.lane_id,
                Resource::ChannelBuffer(self.channel.inner.id()),
            );
            self.registered = true;
        }

        Poll::Pending
        // Kernel will call wake() when buffer space available
    }
}
```

---

## Chapter 5: Kernel Side Integration

### KernelAsyncInterface

```rust
/// Kernel's implementation of KernelInterface
/// Bridges async runtime signals to kernel scheduling
pub struct KernelAsyncInterface {
    selector_sender: crossbeam_channel::Sender<SelectorMessage>,
}

impl KernelInterface for KernelAsyncInterface {
    fn register_wait(&self, lane_id: Uuid, resource: Resource) {
        // Convert to kernel resource type
        let kernel_resource = resource.into_kernel_resource();

        // Tell selector: this lane is waiting for this resource
        // Selector adds to Stalled List, tracks dependency
        let _ = self.selector_sender.send(SelectorMessage::RegisterWait {
            lane_id,
            resource: kernel_resource,
        });
        // Lane does not wait for acknowledgment — this is triggering, not coordination
    }

    fn signal_ready(&self, lane_id: Uuid) {
        // Tell selector: this lane has work and may be ready
        // Selector checks ALL resources, moves to Ready Pool if qualified
        let _ = self.selector_sender.send(SelectorMessage::SignalReady { lane_id });
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}
```

### Selector Processing of Async Signals

The selector processes signals from the async runtime in its main loop alongside resource signals:

```rust
// In selector main loop:

// Process async wake signals (from CibosWaker::wake())
while let Ok(msg) = state.async_signals.try_recv() {
    match msg {
        SelectorMessage::SignalReady { lane_id } => {
            // Check if lane has all required resources
            // If all available: move to Ready Pool
            // If any missing: keep in Stalled List with updated requirements
            state.process_ready_signal(lane_id);
        }
        SelectorMessage::RegisterWait { lane_id, resource } => {
            // Add resource requirement to lane's entry in Stalled List
            state.stalled_list.add_requirement(lane_id, resource);
        }
    }
}
```

---

## Chapter 6: What Can and Cannot Be Used

### CANNOT Use (Incompatible — Uses Global Locks)

```rust
// ALL of these are incompatible with HIP:

tokio::spawn(async { ... })           // Global task queue with locks
tokio::sync::Mutex::new(data)         // Direct lock
tokio::sync::RwLock::new(data)        // Direct lock
tokio::sync::Semaphore::new(n)        // Lock-based synchronization
tokio::sync::broadcast::channel()     // Multi-producer (coordination)
tokio::task::JoinSet::new()           // Internal coordination
async_std::task::spawn(async { ... }) // Global task queue with locks
std::sync::Mutex::new(data)          // Direct lock
std::sync::RwLock::new(data)         // Direct lock
```

### MUST Use (HIP-Compatible)

```rust
// CIBOS primitives — all lock-free:

Lane::create()?                        // Lane-local, no global state
lane.submit(async { ... })?            // Lane-local queue
cibos::channel::Channel::new()        // HIP-native, kernel-tracked
cibos::timer::sleep(duration).await   // Kernel timer, no sleeping thread
cibos::resource::wait_for(r).await    // Kernel tracks dependency
```

---

## Chapter 7: Testing the Async Runtime

```bash
# Verify no Tokio dependency anywhere
cargo run --package builder -- --verify-async-runtime

# Verify .await points correctly stall/resume via kernel
cibos-test --async-runtime --stall-resume

# Verify no global task queue exists
cibos-test --async-runtime --no-global-queue

# Thread sanitizer test (should detect zero data races)
RUSTFLAGS="-Z sanitizer=thread" cargo build
cibos-test --load high --async-intensive

# Performance comparison: lanes vs Tokio tasks
cibos-test --benchmark async-throughput
```

---

## Chapter 8: Error Types

```rust
pub enum AsyncRuntimeError {
    LaneCreationFailed,
    SubmissionFailed,
    WakerRegistrationFailed,
    KernelInterfaceError(String),
}

pub enum ChannelError {
    Closed,
    RateLimited,
    BufferFull,  // Only on try_send, not send().await
    BufferEmpty, // Only on try_receive, not receive().await
}

pub struct TimeoutError;
```

---

*This guide covers the CIBOS async runtime implementation. For deployment, see the Administrator Guide. For writing applications using the runtime, see the Application Developer Guide. For kernel internals, see the Developer Guide.*
