//! Channel Communication — Sender Container
//!
//! This example demonstrates:
//!   - Requesting a channel to another container
//!   - Sending messages through a channel
//!   - Channel terms and negotiation
//!   - Graceful channel closure
//!
//! HIP concepts illustrated:
//!   I (Interference-Free): Containers cannot share memory.
//!     All communication is explicit, through channels.
//!     Channel::request() goes through the kernel — never direct access.
//!   The channel protocol enforces isolation: the kernel mediates
//!     every message, ensuring no bypass of isolation boundaries.

#![no_std]
#![no_main]

extern crate alloc;

use cibos::{Channel, ChannelRequest, ChannelTerms, ContainerId, Timer};
use core::time::Duration;

/// The receiver container's ID.
/// In a real application, this would come from a service registry
/// or be passed as a configuration parameter.
/// Here it's a placeholder — replace with your receiver's actual ID.
const RECEIVER_CONTAINER_ID: ContainerId = ContainerId::from_static(0x1001);

/// Message type for this channel.
/// Must implement: Copy + Send (no heap allocations crossing channels)
/// In practice, use fixed-size types or serialize to bytes.
#[derive(Debug, Clone, Copy)]
enum Message {
    Number(u64),
    Done,
}

#[cibos::main]
async fn main() {
    log::info!("=== Sender starting ===");

    // Channel::request() initiates a channel with another container.
    //
    // This is a kernel-mediated operation:
    //   1. Sender calls Channel::request()
    //   2. Kernel delivers the request to the receiver container
    //   3. Receiver calls accept() to accept (or drops it to reject)
    //   4. Kernel establishes the cryptographic channel (on crypto-ipc profiles)
    //   5. Both ends receive their channel handles
    //
    // .await here: sender stalls until receiver accepts or rejects.
    // If receiver never accepts, this will stall until timeout or close.
    log::info!("Requesting channel to receiver...");

    let channel = Channel::request(ChannelRequest {
        // Target container — the kernel routes this request
        target: RECEIVER_CONTAINER_ID,

        // Terms define what this channel is for and its constraints.
        // Both sides must agree on terms. Kernel enforces them.
        terms: ChannelTerms {
            // Human-readable purpose — helps receiver decide to accept
            purpose: "number-stream",

            // Maximum message size in bytes
            // Kernel enforces: larger messages are rejected
            max_message_bytes: 16,

            // Maximum messages that can be buffered in-kernel
            // If full, send() stalls until receiver consumes
            buffer_capacity: 8,
        },
    }).await.expect("Channel request failed or rejected");

    log::info!("Channel established. Sending numbers...");

    // Send 10 numbers with 100ms spacing
    for i in 0u64..10 {
        // Channel::send() is an async operation.
        //
        // If the channel buffer is not full:
        //   Kernel buffers the message. send() returns immediately.
        // If the channel buffer is full:
        //   This lane stalls (moves to Stalled List).
        //   When receiver consumes a message and buffer has space,
        //   kernel moves this lane back to Ready Pool.
        //
        // Backpressure is automatic — no polling, no spin loops.
        channel.send(Message::Number(i)).await
            .expect("Send failed — channel may be closed");

        log::info!("Sent number {}", i);

        // Pause between sends to demonstrate timing
        Timer::sleep(Duration::from_millis(100)).await;
    }

    // Send the Done message to signal end-of-stream
    channel.send(Message::Done).await
        .expect("Failed to send Done message");

    log::info!("Sent Done message");

    // Close the channel from the sender side.
    //
    // After close():
    //   - No more sends are possible
    //   - Receiver will see channel.receive() return None after
    //     consuming all buffered messages
    //   - Kernel cleans up channel resources
    channel.close();

    log::info!("=== Sender complete ===");
}
