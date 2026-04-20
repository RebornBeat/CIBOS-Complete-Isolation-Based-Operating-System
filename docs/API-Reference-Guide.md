# API REFERENCE GUIDE

**CIBIOS/CIBOS/HIP — Complete API Reference**
**Version:** 1.0.0
**Audience:** Application developers (daily reference)

---

## Overview

This guide documents every public API available to CIBOS application developers. All APIs are in the `cibos` crate. Feature-gated APIs are clearly marked.

```
API SURFACE OVERVIEW:

  cibos::Lane         — Parallel execution pathway management
  cibos::Channel      — Inter-container and intra-container communication
  cibos::Timer        — Async time primitives
  cibos::sensor::*    — Sensor access (CIBOS mobile only)
  cibos::container    — Container self-inspection
  cibos::scheduling   — Scheduling hints (feature-gated)
  cibos::time         — Time utilities
  cibos::select!      — Multi-source async wait macro
```

---

## Chapter 1: Lane API

### `Lane::create()`

Creates a new execution lane in the current container.

```rust
pub fn create() -> Result<Lane, LaneError>
```

**Parameters:** None.

**Returns:** `Ok(Lane)` — a new lane handle.

**Errors:**
- `LaneError::ContainerAtCapacity` — container has reached its maximum lane count (default: 256; configurable per profile)
- `LaneError::SystemAtCapacity` — system-wide lane limit reached

**Guarantees:**
- The new lane is registered with the kernel immediately on return
- The lane is empty (no futures submitted) on return
- Lane ID is unique within this container for the lifetime of this lane

**Example:**
```rust
let mut lane = Lane::create()?;
// Lane exists, is empty, ready for submit()
```

**Profile availability:** All profiles.

---

### `Lane::create_with_weight()`

Creates a new lane with an explicit initial scheduling weight.

```rust
#[cfg(feature = "per-lane-weights")]
pub fn create_with_weight(weight: u32) -> Result<Lane, LaneError>
```

**Parameters:**
- `weight: u32` — Initial scheduling weight. Must be in range `1..=100`. Weight 0 is rejected.

**Returns:** `Ok(Lane)` — a new lane with the specified weight.

**Errors:**
- `LaneError::WeightOutOfRange` — weight is 0 or > 100
- `LaneError::ContainerAtCapacity` — same as `Lane::create()`
- `LaneError::SystemAtCapacity` — same as `Lane::create()`

**Weight semantics:**
- Weight controls the probability of dispatch relative to other lanes in this container
- Weight 5 vs weight 1 means the 5-weight lane is ~5× more likely to be dispatched per selection round
- Equal weights = equal probability (same as standard `Lane::create()`)
- Weights are per-lane within a container. Cross-container weights are not directly comparable.

**Example:**
```rust
#[cfg(feature = "per-lane-weights")]
{
    let mut high_priority = Lane::create_with_weight(5)?;
    let mut low_priority  = Lane::create_with_weight(1)?;
    // high_priority gets ~5x more dispatch chances
}
```

**Feature gate:** `per-lane-weights` (Compute profile only)

---

### `Lane::submit()`

Submits a future for execution on this lane.

```rust
pub fn submit(&mut self, future: impl Future<Output = ()> + 'static) -> Result<(), LaneError>
```

**Parameters:**
- `future` — The future to execute. Must be `'static` (no references to stack data outside the future). Must be `Send` (will execute on kernel-assigned cores).

**Returns:** `Ok(())` — future accepted, lane is now in Ready Pool.

**Errors:**
- `LaneError::AlreadyOccupied` — lane already has a submitted (running) future
- `LaneError::LaneDestroyed` — this lane handle has been destroyed

**Execution guarantees:**
- The future does NOT begin executing on `submit()` — it enters the Ready Pool
- The kernel dispatches it when: N ≤ C (immediately if cores available) or next dispatch cycle
- If multiple lanes are ready simultaneously, dispatch order is non-deterministic
- `submit()` is non-blocking: it returns immediately

**Ordering guarantees:**
- A single lane executes at most one future at a time
- Multiple calls to `submit()` on the same lane are ERRORS (use `join()` first)
- Ordering across different lanes is non-deterministic

**Example:**
```rust
let mut lane = Lane::create()?;
lane.submit(async {
    // This runs in HIP execution model
    let result = do_work();
    channel.send(result).await.unwrap();
})?;
// Future is now in Ready Pool. Lane is running.
// Calling submit() again here would return Err(LaneError::AlreadyOccupied)
```

**Profile availability:** All profiles.

---

### `Lane::join()`

Await the completion of the currently running future on this lane.

```rust
pub async fn join(&mut self)
```

**Parameters:** None.

**Returns:** Nothing. Returns when the submitted future completes.

**Behavior:**
- If lane has no submitted future: returns immediately
- If lane is running a future: stalls the calling lane until the submitted future finishes
- Uses the kernel Catch and Release mechanism — no busy-waiting
- After `join()` returns, the lane is empty and `submit()` can be called again

**Example:**
```rust
let mut lane = Lane::create()?;
lane.submit(async {
    do_slow_work();
})?;
// Do other things here while lane is running...
lane.join().await; // Stall until lane completes
// Lane is now empty — can submit again
lane.submit(async {
    do_more_work();
})?;
```

**Profile availability:** All profiles.

---

### `Lane::update_weight()`

Dynamically update the scheduling weight of a lane.

```rust
#[cfg(feature = "dynamic-weights")]
pub fn update_weight(&mut self, weight: u32) -> Result<(), LaneError>
```

**Parameters:**
- `weight: u32` — New weight. Must be in range `1..=100`.

**Returns:** `Ok(())` — weight updated.

**Errors:**
- `LaneError::WeightOutOfRange` — weight is 0 or > 100
- `LaneError::LaneDestroyed` — lane handle has been destroyed

**Timing:** The weight update takes effect on the next dispatch cycle. Updates sent via message (no locks) — ~45-110 cycles of overhead.

**Example:**
```rust
#[cfg(feature = "dynamic-weights")]
{
    let mut lane = Lane::create_with_weight(1)?;

    // Boost priority for important phase
    lane.update_weight(5)?;
    lane.submit(important_work())?;
    lane.join().await;

    // Return to normal priority
    lane.update_weight(1)?;
}
```

**Feature gate:** `dynamic-weights` (Compute profile with dynamic-weights feature only)

---

### `Lane::id()`

Returns the unique identifier of this lane within its container.

```rust
pub fn id(&self) -> LaneId
```

**Parameters:** None.

**Returns:** `LaneId` — an opaque identifier, unique within this container for this lane's lifetime.

**Use cases:** Logging, debugging, correlating log messages with lane activity.

**Example:**
```rust
let lane = Lane::create()?;
log::debug!("Created lane {}", lane.id());
```

---

### `Lane::destroy()`

Immediately destroy this lane.

```rust
pub fn destroy(self) -> Result<(), LaneError>
```

**Parameters:** None. Consumes the Lane handle.

**Returns:** `Ok(())` — lane destroyed successfully.

**Errors:**
- `LaneError::LaneRunning` — cannot destroy a lane with a running future (call `join()` first)

**Behavior:**
- Drops the lane handle and notifies the kernel
- If lane is empty (no running future): immediate destruction
- If lane has a running future: returns `Err(LaneError::LaneRunning)`
- Lanes are also destroyed automatically when the Lane handle is dropped

**Example:**
```rust
let mut lane = Lane::create()?;
lane.submit(some_work())?;
lane.join().await;
lane.destroy()?; // Explicit destruction
// Or: drop(lane); // Implicit destruction on drop
```

**Profile availability:** All profiles.

---

### `LaneError` enum

```rust
pub enum LaneError {
    ContainerAtCapacity,   // Container lane limit reached
    SystemAtCapacity,      // System-wide lane limit reached
    WeightOutOfRange,      // Weight was 0 or > 100
    AlreadyOccupied,       // Lane already has a running future
    LaneDestroyed,         // Lane handle has been invalidated
    LaneRunning,           // Operation requires lane to be empty
}
```

---

## Chapter 2: Channel API

### `Channel::request()`

Request a channel to another container.

```rust
pub async fn request(request: ChannelRequest) -> Result<Channel<T>, ChannelError>
```

**Parameters:**
- `request: ChannelRequest` — Channel request parameters:
  - `target: ContainerId` — the target container
  - `terms: ChannelTerms` — proposed channel terms

**`ChannelTerms` fields:**
- `purpose: &'static str` — Human-readable purpose string (max 64 bytes)
- `max_message_bytes: usize` — Maximum size of a single message in bytes
- `buffer_capacity: usize` — Maximum messages buffered in-kernel (1..=4096)

**Returns:** `Ok(Channel<T>)` — established channel, ready for send/receive.

**Errors:**
- `ChannelError::TargetNotFound` — target container does not exist
- `ChannelError::TargetRejected` — target container rejected the request
- `ChannelError::TargetTimeout` — target did not accept within timeout
- `ChannelError::TermsViolation` — requested terms exceed system policy
- `ChannelError::Unauthorized` — this container is not authorized to channel this target

**Await behavior:** Stalls the calling lane until the target accepts or the request fails. The target container is notified by the kernel and must call `container::await_channel_request()` to receive it.

**Example:**
```rust
let channel = Channel::<MyMessage>::request(ChannelRequest {
    target: ContainerId::from_static(0x1001),
    terms: ChannelTerms {
        purpose: "data-stream",
        max_message_bytes: 256,
        buffer_capacity: 16,
    },
}).await?;
```

**Profile availability:** All profiles. On Maximum Isolation and Balanced, uses cryptographic IPC. On Performance (with crypto-ipc feature), uses cryptographic IPC. On Compute with lightweight-handshake, uses lightweight IPC.

---

### `container::await_channel_request()`

Wait for an incoming channel request from another container.

```rust
pub async fn await_channel_request<T>() -> Result<IncomingRequest<T>, ChannelError>
```

**Parameters:** None.

**Returns:** `Ok(IncomingRequest<T>)` — an incoming request that must be accepted or dropped.

**Errors:**
- `ChannelError::ContainerExiting` — container is shutting down

**`IncomingRequest<T>` methods:**
- `sender_id() -> ContainerId` — ID of the requesting container
- `terms() -> &ChannelTerms` — proposed terms
- `accept() -> Result<Channel<T>, ChannelError>` — accept the request
- Dropping the `IncomingRequest` without calling `accept()` rejects it

**Example:**
```rust
let incoming = container::await_channel_request::<MyMessage>().await?;
log::info!("Request from {:?}: {}", incoming.sender_id(), incoming.terms().purpose);

if incoming.terms().purpose == "data-stream" {
    let channel = incoming.accept()?;
    // Use channel
} else {
    // Drop incoming → automatically rejected
}
```

---

### `Channel::new_local()`

Create a local (intra-container) channel.

```rust
pub fn new_local<T>(buffer_capacity: usize) -> Result<(Channel<T>, Channel<T>), ChannelError>
```

**Parameters:**
- `buffer_capacity: usize` — Maximum messages buffered (1..=65536)

**Returns:** `Ok((sender, receiver))` — a pair of channel ends.

**Notes:**
- Local channels do not cross container boundaries
- No cryptographic overhead — used for intra-lane communication
- Both ends are the same `Channel<T>` type (can send and receive on either end)
- In practice, name the pair `(sender, receiver)` by convention

**Example:**
```rust
let (sender, receiver) = Channel::<u64>::new_local(16)?;

lane.submit(async move {
    sender.send(42u64).await.unwrap();
    sender.close();
})?;

// In main lane:
while let Some(val) = receiver.receive().await {
    log::info!("Received: {}", val);
}
```

---

### `Channel::send()`

Send a message. Stalls if buffer is full.

```rust
pub async fn send(&self, message: T) -> Result<(), ChannelError>
```

**Parameters:**
- `message: T` — The message to send. Must be `Copy + Send` or serializable to bytes.

**Returns:** `Ok(())` — message delivered to kernel buffer.

**Errors:**
- `ChannelError::ChannelClosed` — receiver has closed the channel
- `ChannelError::MessageTooLarge` — message exceeds `max_message_bytes`

**Await behavior:**
- If buffer has space: delivers message and returns immediately
- If buffer is full: stalls the calling lane until space is available (back-pressure)

**Example:**
```rust
channel.send(Message::Data { id: 1, value: 42 }).await?;
```

---

### `Channel::receive()`

Receive a message. Stalls if no message is available.

```rust
pub async fn receive(&self) -> Option<T>
```

**Parameters:** None.

**Returns:**
- `Some(T)` — a message was available or just arrived
- `None` — channel is closed and no more messages will come

**Await behavior:**
- If a message is buffered: returns immediately
- If no message is available: stalls the calling lane until a message arrives or channel closes

**Example:**
```rust
while let Some(msg) = channel.receive().await {
    process(msg);
}
// channel closed — loop exits
```

---

### `Channel::try_send()`

Non-blocking send. Returns immediately regardless of buffer state.

```rust
pub fn try_send(&self, message: T) -> Result<(), TrySendError<T>>
```

**Parameters:**
- `message: T` — The message to send.

**Returns:**
- `Ok(())` — message sent
- `Err(TrySendError::Full(message))` — buffer full, message returned to caller
- `Err(TrySendError::Closed(message))` — channel closed

**Use cases:** When you cannot afford to stall the current lane. Must implement fallback logic for the `Full` case.

**Example:**
```rust
match channel.try_send(message) {
    Ok(()) => { /* sent */ }
    Err(TrySendError::Full(msg)) => {
        // Buffer full — handle back-pressure manually
        fallback_queue.push(msg);
    }
    Err(TrySendError::Closed(msg)) => {
        log::warn!("Channel closed, dropping message");
    }
}
```

---

### `Channel::try_receive()`

Non-blocking receive. Returns immediately regardless of buffer state.

```rust
pub fn try_receive(&self) -> Result<T, TryReceiveError>
```

**Returns:**
- `Ok(T)` — a message was available
- `Err(TryReceiveError::Empty)` — no message available
- `Err(TryReceiveError::Closed)` — channel closed and empty

**Use cases:** Polling a channel in a tick loop, draining a channel that may or may not have messages.

**Example:**
```rust
// Drain all currently available messages without stalling
loop {
    match channel.try_receive() {
        Ok(msg) => process(msg),
        Err(TryReceiveError::Empty) => break,     // Nothing more right now
        Err(TryReceiveError::Closed) => {
            done = true;
            break;
        }
    }
}
```

---

### `Channel::close()`

Close this end of the channel.

```rust
pub fn close(self)   // Consumes the channel handle
// or
pub fn close_ref(&self)  // Non-consuming close
```

**Behavior:**
- Marks this channel end as closed
- Other end's next `receive()` will eventually return `None` (after draining buffered messages)
- Other end's next `send()` will return `Err(ChannelError::ChannelClosed)`
- Buffered messages are NOT dropped — they remain available for the receiver

**Example:**
```rust
// Sender side:
for item in items {
    channel.send(item).await?;
}
channel.close(); // Signal end-of-stream

// Receiver side:
while let Some(item) = channel.receive().await {
    process(item); // Processes all buffered items
}
// Returns None when all buffered items are consumed AND sender closed
```

---

### `ChannelError` enum

```rust
pub enum ChannelError {
    TargetNotFound,      // Target container does not exist
    TargetRejected,      // Target explicitly rejected the request
    TargetTimeout,       // Target did not respond within timeout
    TermsViolation,      // Terms exceed system policy
    Unauthorized,        // Not authorized to channel this target
    ChannelClosed,       // Channel has been closed
    MessageTooLarge,     // Message exceeds max_message_bytes
    BufferCapacityInvalid, // buffer_capacity out of range
    ContainerExiting,    // Container is shutting down
}
```

---

## Chapter 3: Timer API

### `Timer::sleep()`

Stall the current lane for a duration.

```rust
pub async fn sleep(duration: Duration)
```

**Parameters:**
- `duration: Duration` — How long to stall. Zero duration returns immediately.

**Returns:** Nothing. Returns after at least `duration` has passed.

**Precision:** Timer precision is profile-dependent:
- All profiles: ~1ms precision (hardware timer resolution)
- Performance profile: hardware RTRO available if feature compiled

**Behavior:** The lane moves to the Stalled List. The kernel registers a timer event. When `duration` passes, the kernel moves the lane back to the Ready Pool. No busy-waiting.

**Example:**
```rust
log::info!("Starting sleep...");
Timer::sleep(Duration::from_millis(500)).await;
log::info!("Awake after 500ms");
```

---

### `Timer::at()`

Stall the current lane until a specific instant.

```rust
pub async fn at(instant: Instant)
```

**Parameters:**
- `instant: Instant` — The point in time to wake up. Must be in the future.

**Returns:** Nothing. Returns at or after `instant`. If `instant` is already in the past, returns immediately.

**Example:**
```rust
let deadline = cibos::time::now() + Duration::from_secs(10);
do_work();
Timer::at(deadline).await; // Stall until deadline, regardless of how long do_work() took
```

---

### `with_timeout()`

Run a future with a timeout. Returns early if timeout expires.

```rust
pub async fn with_timeout<T>(
    duration: Duration,
    future: impl Future<Output = T>,
) -> Result<T, TimeoutError>
```

**Parameters:**
- `duration: Duration` — Maximum time to wait for the future
- `future` — The future to run

**Returns:**
- `Ok(T)` — future completed within the timeout
- `Err(TimeoutError)` — timeout expired before future completed

**Example:**
```rust
match with_timeout(Duration::from_secs(5), channel.receive()).await {
    Ok(Some(msg)) => log::info!("Received: {:?}", msg),
    Ok(None)      => log::info!("Channel closed"),
    Err(TimeoutError) => log::warn!("Timed out waiting for message"),
}
```

---

### `cibos::time::now()`

Get the current monotonic time.

```rust
pub fn now() -> Instant
```

**Returns:** Current monotonic `Instant`. Monotonic means it never goes backwards. Not wall clock time.

**Example:**
```rust
let start = cibos::time::now();
do_work();
let elapsed = cibos::time::now() - start;
log::info!("Work took {:?}", elapsed);
```

---

## Chapter 4: Sensor API (CIBOS Mobile)

All sensor APIs require the `sensor-subsystem` feature and are only available on CIBOS mobile variant.

### `Sensor::request()`

Request access to a sensor. Returns a builder for configuration.

```rust
pub fn request(sensor_type: SensorType) -> SensorRequestBuilder
```

**Parameters:**
- `sensor_type: SensorType` — Which sensor to request:
  - `SensorType::Camera`
  - `SensorType::Microphone`
  - `SensorType::Gps`
  - `SensorType::Accelerometer`
  - `SensorType::Gyroscope`
  - `SensorType::Barometer`
  - `SensorType::ProximitySensor`

**Returns:** `SensorRequestBuilder` — builder for additional configuration. Call `.await` to complete.

**Builder methods:**
- `.precision(Precision)` — `Precision::Fine`, `Precision::Medium`, `Precision::Coarse`
- `.timeout(Duration)` — Maximum time to wait for sensor availability
- `.sample_rate(u32)` — Sample rate in Hz (Microphone, Accelerometer, Gyroscope)
- `.channels(u8)` — Channel count (Microphone only)

**Completes with:** `Result<SensorHandle, SensorError>`

**Errors:**
- `SensorError::NotAvailable` — Sensor not present on hardware
- `SensorError::Timeout` — Sensor not released within timeout
- `SensorError::PrecisionDenied` — Requested precision denied by system policy
- `SensorError::Unauthorized` — Container not authorized for this sensor

---

### `SensorHandle::read_frame()`

Capture one frame from the camera.

```rust
pub async fn read_frame(&self) -> Result<Frame, SensorError>
```

**Requires:** `SensorType::Camera`

**Returns:**
- `Ok(Frame)` — captured frame
  - `frame.data() -> &[u8]` — raw pixel data
  - `frame.width() -> u32`
  - `frame.height() -> u32`
  - `frame.format() -> PixelFormat` — `PixelFormat::Rgb24`, `PixelFormat::Yuv420`, etc.
  - `frame.timestamp() -> Instant`
- `Err(SensorError::CaptureFailure)` — hardware capture error

---

### `SensorHandle::read_samples()`

Capture audio samples from the microphone.

```rust
pub async fn read_samples(&self, count: usize) -> Result<AudioBuffer, SensorError>
```

**Requires:** `SensorType::Microphone`

**Parameters:**
- `count: usize` — Number of samples to capture

**Returns:**
- `Ok(AudioBuffer)` — captured audio
  - `buffer.data() -> &[i16]` — raw sample data (signed 16-bit PCM)
  - `buffer.sample_rate() -> u32`
  - `buffer.channels() -> u8`
- `Err(SensorError::CaptureFailure)`

---

### `SensorHandle::read_location()`

Read current GPS location.

```rust
pub async fn read_location(&self) -> Result<Location, SensorError>
```

**Requires:** `SensorType::Gps`

**Returns:**
- `Ok(Location)` — current location
  - `location.latitude() -> f64` — degrees, -90 to +90
  - `location.longitude() -> f64` — degrees, -180 to +180
  - `location.altitude_meters() -> Option<f64>` — meters above sea level
  - `location.accuracy_meters() -> f32` — horizontal accuracy radius
  - `location.timestamp() -> Instant`
- `Err(SensorError::NoFix)` — GPS has no satellite fix yet

---

### `SensorHandle::release()`

Release the sensor, making it available to other containers.

```rust
pub fn release(self)  // Consumes the handle
```

**Always call `release()` when done with a sensor.** The sensor remains exclusively held until `release()` is called or the container exits.

---

### `SensorError` enum

```rust
pub enum SensorError {
    NotAvailable,      // Sensor not present on this hardware
    Timeout,           // Sensor not released within timeout
    PrecisionDenied,   // Requested precision denied by policy
    Unauthorized,      // Container not authorized for this sensor
    CaptureFailure,    // Hardware capture error
    NoFix,             // GPS has no satellite fix
    InvalidConfig,     // Invalid sample rate or channel count
}
```

---

## Chapter 5: Container API

### `container::memory_usage()`

Returns the current memory usage of this container.

```rust
pub fn memory_usage() -> MemoryStats
```

**Returns:** `MemoryStats`:
- `.allocated_bytes: usize` — currently allocated bytes
- `.peak_bytes: usize` — peak allocation since container start
- `.limit_bytes: usize` — maximum allowed allocation

---

### `container::memory_limit()`

Returns the memory limit for this container.

```rust
pub fn memory_limit() -> usize
```

**Returns:** Maximum bytes this container can allocate. Determined at container launch time by the deployer.

---

### `container::channel_count()`

Returns the number of open channels for this container.

```rust
pub fn channel_count() -> ChannelCount
```

**Returns:** `ChannelCount`:
- `.inbound: usize` — channels where this container is the receiver
- `.outbound: usize` — channels where this container is the sender
- `.local: usize` — local (intra-container) channels

---

### `container::get_resource_limits()`

Returns all resource limits for this container.

```rust
pub fn get_resource_limits() -> ResourceLimits
```

**Returns:** `ResourceLimits`:
- `.memory_bytes: usize` — memory limit
- `.max_lanes: usize` — maximum lanes
- `.max_channels: usize` — maximum channels
- `.max_message_bytes: usize` — maximum message size per channel
- `.max_channel_buffer: usize` — maximum channel buffer capacity

---

### `container::id()`

Returns this container's ID.

```rust
pub fn id() -> ContainerId
```

**Use cases:** Telling other containers your ID so they can request channels to you.

---

## Chapter 6: Feature-Gated APIs

### Per-Lane Weights (feature: `per-lane-weights`)

Available on: **Compute profile** with `per-lane-weights` feature compiled.

```rust
// Lane creation with weight
Lane::create_with_weight(weight: u32) -> Result<Lane, LaneError>

// Weight range: 1..=100
// Default (without per-lane-weights): all lanes treated as weight 1
```

**Behavior:**
- Weight determines relative dispatch probability via weighted entropy selection
- Weight 5 vs weight 1: ~5× more likely to be dispatched per selection round
- Weights are normalized within the container

---

### Dynamic Weights (feature: `dynamic-weights`)

Available on: **Compute profile** with both `per-lane-weights` and `dynamic-weights` features compiled.

Requires `per-lane-weights`.

```rust
// Runtime weight update
Lane::update_weight(weight: u32) -> Result<(), LaneError>
```

**Overhead:** ~45-110 cycles per update. Effect takes place at next dispatch cycle.

**Why Compute profile only:** Dynamic weight changes create observable timing patterns. On profiles where an adversary might observe these patterns (Maximum Isolation, Balanced), this creates a timing side channel. On Compute profile, no adversary is present — the machine is dedicated to the computation workload.

---

### Class Core Affinity (feature: `class-core-affinity`)

Available on: **Performance profile** with `class-core-affinity` feature compiled.

```rust
pub fn set_class_affinity(&mut self, affinity: ClassAffinity) -> Result<(), LaneError>
```

**`ClassAffinity` variants:**
- `ClassAffinity::Interactive` — prefer cores recently used for UI work (cache warmth)
- `ClassAffinity::DataProcessing` — prefer cores with data pipeline state
- `ClassAffinity::Background` — prefer cores not in use by interactive work
- `ClassAffinity::None` — no affinity preference (default)

**Purpose:** Improves cache locality by keeping related lanes on the same physical core. Useful when lanes share data structures (immutably — no locks).
