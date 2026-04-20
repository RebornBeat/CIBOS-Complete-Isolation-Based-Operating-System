# MIGRATION GUIDE

**CIBIOS/CIBOS/HIP — Migrating From Other Systems**
**Version:** 1.0.0
**Audience:** Developers and administrators coming from other operating systems

---

## Overview

HIP is a fundamentally different paradigm from traditional operating systems. This guide bridges the conceptual gap for developers coming from Linux, other microkernels, or container systems.

**The most important shift in thinking:**

```
TRADITIONAL OS MENTAL MODEL → HIP MENTAL MODEL:

  Threads share memory     →  Lanes own their data
  Locks protect sharing    →  No sharing, no locks needed
  "Run this thread now"    →  "Submit this future, kernel decides when"
  Priority queues          →  Weighted entropy (probabilistic)
  Deterministic ordering   →  Non-deterministic is the default (and correct)
  One result wins          →  All results are preserved
```

---

## Chapter 1: From Linux

### 1.1 Process Model → Container/Lane Model

```
LINUX MAPPING:

  Linux Concept          CIBOS Equivalent        Key Difference
  ───────────────────    ────────────────────    ──────────────────────────────
  Process                Container               Container has strict memory
                                                 isolation — no ptrace,
                                                 no /proc/[pid]/mem access

  Thread                 Lane                    Lanes don't share memory
                                                 (threads in Linux do).
                                                 Lane = isolated future.

  pthread_create()       Lane::create()          No shared stack, no TLS.
                         + lane.submit()         Each lane owns its state.

  pthread_join()         lane.join().await       Non-blocking (async wait)

  mutex lock/unlock      No equivalent           Not needed — no sharing.
                                                 Use channels instead.

  pipe / socketpair      Channel::new_local()    No file descriptors.
                                                 Type-safe channel.

  Unix socket            Channel::request()      Kernel-mediated, typed.
                                                 Cryptographic on secure profiles.

  fork()                 No equivalent           CIBOS has no fork().
                                                 Launch separate containers.

  exec()                 cibos-ctl run <app>     Containers are launched
                                                 by administrator, not
                                                 by other containers.

  signal (SIGTERM, etc.) Container policy        No signals in CIBOS.
                                                 Use channels to communicate.

  /proc/[pid]/mem        Prohibited              Isolation boundary prevents
                                                 this by design.

  mmap(MAP_SHARED)       Prohibited              No shared memory between
                                                 containers.

  futex                  No equivalent           Not needed — no locks.
```

### 1.2 Threads → Lanes

```rust
// LINUX PATTERN (threads with shared memory):
let shared_data = Arc::new(Mutex::new(Vec::new()));
let data_clone = shared_data.clone();

let handle = std::thread::spawn(move || {
    let result = compute();
    let mut data = data_clone.lock().unwrap();  // LOCK
    data.push(result);
    // UNLOCK on drop
});

handle.join().unwrap();
let results = shared_data.lock().unwrap();  // LOCK again

// ─────────────────────────────────────────────────────────────────────

// CIBOS PATTERN (lanes with owned data, channels for results):
let (sender, receiver) = Channel::new_local(1)?;
let mut lane = Lane::create()?;

lane.submit(async move {
    let result = compute();
    sender.send(result).await.unwrap();  // No lock — channel is typed message passing
})?;

let result = receiver.receive().await.unwrap();
lane.join().await;
```

**Why this is better:**
- No lock contention — the computation lane runs freely
- No deadlock risk — no locks to order
- The result transfer is explicit and type-safe
- Non-determinism (if multiple lanes) is handled correctly by design

### 1.3 File System Differences

```
LINUX                          CIBOS
─────                          ─────
Hierarchical filesystem        No global filesystem (by default)
/proc, /sys                    No virtual filesystems
File descriptors               No file descriptors (channels instead)
open(), read(), write()        Channel::receive(), Channel::send()
inotify / epoll                channel.receive().await (async by design)

STORAGE ACCESS:
  CIBOS storage is accessed through typed channels to storage containers.
  A storage container owns the storage hardware (isolation boundary).
  Your container requests data through a channel:

    // Read a file through a storage channel
    let storage = Channel::request(ChannelRequest {
        target: STORAGE_CONTAINER_ID,
        terms: ChannelTerms { purpose: "read-file", ... },
    }).await?;

    storage.send(StorageRequest::Read { path: "/data/config.toml" }).await?;
    let response = storage.receive().await?;
    match response {
        StorageResponse::Data(bytes) => { /* use data */ }
        StorageResponse::NotFound => { /* handle */ }
    }
```

### 1.4 IPC Differences

```
LINUX IPC MECHANISM     CIBOS EQUIVALENT
────────────────────    ─────────────────────────────────────────────
Shared memory (shmem)   No equivalent. Use channels.
Message queues          Channel with buffer_capacity > 1
Unix domain sockets     Channel::request() / container::await_channel_request()
D-Bus                   No equivalent. Direct typed channels.
Signals                 No equivalent. Use channels with message types.
Semaphores              No equivalent. Not needed (no shared state).
Named pipes (FIFO)      No equivalent. Use channels.
```

---

## Chapter 2: From Other Microkernels

### 2.1 Capability Mapping

```
MICROKERNEL CONCEPT     CIBOS EQUIVALENT
───────────────────     ─────────────────────────────────────────────
Capability              Container authorization policy
Capability transfer     Not applicable (channels are typed, not caps)
Capability revocation   Container policy update via administrator

IPC endpoint            ContainerId (target of Channel::request())
IPC message             Channel::send() / Channel::receive()
IPC reply               Separate reply channel (request→reply pattern)

Page mapping            Not applicable (memory isolation is physical)
Shared page             Not applicable (no shared memory)

Thread                  Lane
Task                    Container
Address space           Container memory region (isolated by CIBIOS)
```

### 2.2 Porting IPC Patterns

```
SEL4-STYLE SYNCHRONOUS IPC → CIBOS ASYNC CHANNEL PATTERN:

// seL4-style (conceptual):
seL4_Call(endpoint, message_info, &reply_msg_info);
// Blocks sender until receiver processes and replies

// CIBOS equivalent:
let (request_channel, reply_channel) = (
    Channel::request(server_request_terms).await?,
    Channel::request(server_reply_terms).await?,
);
request_channel.send(RequestMessage { ... }).await?;
let reply = reply_channel.receive().await?;
// Request lane stalls waiting for reply — semantically equivalent
// but async: kernel can dispatch other lanes while waiting

// ─────────────────────────────────────────────────────────────────────

MACH-STYLE PORT RIGHTS → CIBOS CHANNEL PATTERN:

// Mach-style: send right, receive right, make-send right
// CIBOS: Channel is simply a typed pipe.
// No rights system — authorization is container policy.
// To give another container "send access" to you:
//   Authorize that container in your policy to channel you.
//   Then it can call Channel::request() targeting you.
```

### 2.3 Security Model Differences

```
TRADITIONAL MICROKERNEL SECURITY:
  - Capability-based access control
  - Capabilities are unforgeable tokens
  - Transfer capabilities to grant access

CIBOS SECURITY MODEL:
  - Policy-based container authorization
  - Isolation boundaries are physical (hardware-enforced)
  - No capability tokens to forge or steal
  - Access is granted by administrator policy, not by runtime capability transfer
  - On Maximum Isolation profile: scheduling itself is non-observable

KEY DIFFERENCE:
  In a capability microkernel, a compromised container with a capability
  can still exercise that capability.

  In CIBOS, a compromised container is constrained by isolation boundaries —
  it cannot access any container it's not authorized to channel,
  and cannot bypass the kernel's mediation of those channels.
```

---

## Chapter 3: From Container Systems (Docker, Kubernetes)

### 3.1 Container Concepts Mapping

```
DOCKER/KUBERNETES CONCEPT   CIBOS EQUIVALENT
────────────────────────    ────────────────────────────────────────────
Docker container            CIBOS container (similar isolation intent,
                            stronger isolation implementation)

Container image             .capp (CIBOS Application Package)
Docker registry             CIBOS package registry (administrator-managed)

Docker run                  cibos-ctl run <app-name>
Docker exec                 No equivalent (isolation boundary prevents it)
Docker logs                 cibos-ctl log --container <name>

Kubernetes Pod              Container group (related containers)
Kubernetes Service          Channel-based service (no DNS/IP needed)
Kubernetes ConfigMap        Configuration channel to config container
Kubernetes Secret           Secure channel with cryptographic IPC

Volume mount                Channel to storage container (no direct mount)
Network namespace           No equivalent (channels, not networking)
Port binding                Channel endpoint (no TCP ports needed)

Resource limits (CPU)       Lane weight + lane count
Resource limits (Memory)    Container memory limit
Resource limits (I/O)       Channel buffer + storage container policy

Health check                Container sends heartbeat via channel
Liveness probe              Administrator monitors container status
Readiness probe             Container signals ready via channel
```

### 3.2 Networking Differences

```
DOCKER NETWORKING:
  Containers communicate via TCP/UDP
  Port mapping, network namespaces, iptables
  DNS-based service discovery

CIBOS NETWORKING:
  Internal communication: typed channels (no networking overhead)
  External networking: through a dedicated network container

  For external access:
    Your container ←channel→ Network Container ←TCP/UDP→ Internet
    The network container owns the network hardware.
    Your container never touches network hardware directly.

  Benefits:
    - Network container is the only container with network access
    - Compromise of your container does not expose network
    - Traffic routing is policy, not iptables rules

  For internal microservice communication:
    Use channels directly — no TCP, no latency, no serialization overhead.
    Channel::request() replaces HTTP/gRPC for in-system communication.
```

### 3.3 Resource Limits Mapping

```
DOCKER/K8S RESOURCE LIMITS → CIBOS:

  CPU limits:
    Docker: --cpus=0.5 (half a core)
    CIBOS:  Lane weight + lane count (probabilistic, not hard)
            Lower weight = less dispatch priority
            Fewer lanes = less parallelism

  Memory limits:
    Docker: --memory=512m
    CIBOS:  cibos-ctl containers limit --memory 512MB (hard limit)
            Exceeding limit = container exits with MemoryLimitExceeded

  I/O limits:
    Docker: --device-read-bps, --device-write-bps
    CIBOS:  Storage container policy limits read/write rate
            Channel buffer size limits burst rate
            (no native per-container disk I/O limits in CIBOS)

  Network limits:
    Docker: (typically managed by CNI plugins)
    CIBOS:  Network container policy limits bandwidth per channel
            No native per-container bandwidth limits in base CIBOS
```
