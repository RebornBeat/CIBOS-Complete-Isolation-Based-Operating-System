//! Channel Communication — Receiver Container
//!
//! Deploy this as a separate container from sender.rs.
//! The kernel routes the channel request from sender to this container.

#![no_std]
#![no_main]

extern crate alloc;

use cibos::{container, Channel, ChannelTerms};

#[cibos::main]
async fn main() {
    log::info!("=== Receiver starting ===");
    log::info!("Waiting for incoming channel request...");

    // container::await_channel_request() stalls this lane until
    // another container sends a Channel::request() targeting us.
    //
    // Returns an IncomingRequest that we must accept or drop.
    // Dropping the IncomingRequest rejects the channel.
    //
    // In HIP terms: this lane is stalled (Stalled List) waiting
    // for a kernel event. No busy-waiting. No polling.
    let incoming = container::await_channel_request().await
        .expect("Error waiting for channel request");

    log::info!(
        "Channel request from container {:?}: purpose='{}'",
        incoming.sender_id(),
        incoming.terms().purpose
    );

    // Inspect the terms and decide whether to accept
    let terms = incoming.terms();
    if terms.purpose != "number-stream" {
        log::warn!("Unknown channel purpose '{}' — rejecting", terms.purpose);
        // Dropping `incoming` without calling accept() rejects it
        return;
    }

    // Accept the channel
    // After accept(), both sender and receiver have channel handles
    let channel = incoming.accept()
        .expect("Failed to accept channel");

    log::info!("Channel accepted. Receiving messages...");

    // Receive messages until the channel is closed or Done is received
    //
    // channel.receive() returns:
    //   Some(msg) — a message was available or just arrived
    //   None      — the channel was closed and no more messages
    //
    // If no message is currently available, this lane stalls.
    // When the sender sends, the kernel moves this lane to Ready Pool.
    loop {
        match channel.receive().await {
            Some(Message::Number(n)) => {
                log::info!("Received number: {}", n);
                // Process the number (in real app: do something useful)
                let _ = process_number(n);
            }
            Some(Message::Done) => {
                log::info!("Received Done — stream complete");
                break;
            }
            None => {
                // Channel closed without Done message
                log::warn!("Channel closed unexpectedly");
                break;
            }
        }
    }

    log::info!("=== Receiver complete ===");
}

fn process_number(n: u64) -> u64 {
    // Example processing: square the number
    n * n
}

/// Must match sender's Message type
#[derive(Debug, Clone, Copy)]
enum Message {
    Number(u64),
    Done,
}
