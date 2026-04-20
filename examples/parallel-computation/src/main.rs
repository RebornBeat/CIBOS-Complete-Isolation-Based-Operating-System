//! Parallel Computation — Multiple Lanes, All Results Collected
//!
//! This example demonstrates:
//!   - Spawning multiple lanes simultaneously
//!   - Collecting all results (HIP's A property — no collapse)
//!   - Local channels for result collection
//!   - The parallel sum pattern
//!
//! HIP concepts illustrated:
//!   P (Parallel Pathways): All 8 lanes exist simultaneously.
//!     The kernel maintains all of them. None is discarded.
//!   I (Interference-Free): Each lane works on its own data chunk.
//!     No shared mutable state. Results come back through channels.
//!   N (Non-Deterministic): The order in which lanes complete is
//!     non-deterministic. This is CORRECT. We collect all results
//!     regardless of completion order.
//!   A (Application Control): We collect ALL 8 results.
//!     No result is discarded. The application assembles the final
//!     answer from all partial results.
//!
//! KEY INSIGHT: Traditional parallel programming worries about which
//! result "wins." In HIP, ALL results are preserved. The application
//! decides what to do with them. Here we sum them — but we could
//! take the minimum, maximum, concatenate, or use all 8 independently.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use cibos::{Channel, Lane, Timer};
use core::time::Duration;

/// Number of parallel computation lanes.
/// In real applications, tune this to hardware core count.
const LANE_COUNT: usize = 8;

/// Large dataset to sum in parallel.
/// In real applications, this would come from a channel or storage.
const DATASET_SIZE: usize = 8_000_000; // 8 million u64 values

#[cibos::main]
async fn main() {
    log::info!("=== Parallel Computation starting ===");
    log::info!("Computing sum of {} numbers using {} parallel lanes",
               DATASET_SIZE, LANE_COUNT);

    // Generate test data (in real app: read from channel or storage)
    let numbers: Vec<u64> = (0..DATASET_SIZE as u64).collect();
    let expected_sum = (DATASET_SIZE as u64 - 1) * DATASET_SIZE as u64 / 2;

    log::info!("Dataset ready. Expected sum: {}", expected_sum);

    // Compute the parallel sum and verify
    let start = cibos::time::now();
    let result = parallel_sum(&numbers).await;
    let elapsed = cibos::time::now() - start;

    log::info!("Parallel sum result: {}", result);
    log::info!("Elapsed: {:?}", elapsed);

    if result == expected_sum {
        log::info!("Result CORRECT");
    } else {
        log::error!("Result INCORRECT: expected {}, got {}", expected_sum, result);
    }

    log::info!("=== Parallel Computation complete ===");
}

/// Compute the sum of `numbers` using LANE_COUNT parallel lanes.
///
/// HIP pattern: Fan-out → Parallel Work → Fan-in
///
///   Main lane
///     │
///     ├──► Lane 0: sum(chunk 0) ──► channel
///     ├──► Lane 1: sum(chunk 1) ──► channel
///     ├──► Lane 2: sum(chunk 2) ──► channel
///     │   ...
///     └──► Lane 7: sum(chunk 7) ──► channel
///
///     Main lane stalls until all lanes send their partial sums
///     Then assembles final result
///
/// All 8 lanes run simultaneously. Order of completion is
/// non-deterministic. All 8 results are collected.
async fn parallel_sum(numbers: &[u64]) -> u64 {
    // Local channel for collecting partial sums.
    // Channel::new_local() creates a channel within this container —
    // no cross-container IPC, no cryptographic overhead.
    // Buffer capacity = LANE_COUNT so all lanes can send without stalling.
    let (sender, receiver) = Channel::new_local(LANE_COUNT)
        .expect("Failed to create result channel");

    let chunk_size = numbers.len() / LANE_COUNT;

    // Spawn LANE_COUNT lanes simultaneously.
    // All lanes are created and submitted before any of them runs.
    // The kernel sees LANE_COUNT items in the Ready Pool.
    let mut lanes = Vec::with_capacity(LANE_COUNT);

    for i in 0..LANE_COUNT {
        let mut lane = Lane::create().expect("Failed to create lane");

        // Each lane gets its own chunk of the data.
        // Clone the chunk — each lane owns its data, no sharing.
        //
        // In production: use Arc for large datasets, or
        // pass chunk indices and read from immutable shared storage.
        let chunk: Vec<u64> = numbers[i * chunk_size..(i + 1) * chunk_size].to_vec();
        let s = sender.clone();
        let lane_index = i;

        lane.submit(async move {
            log::debug!("Lane {} computing sum of {} numbers", lane_index, chunk.len());

            // Pure computation — no I/O, no shared state
            let partial_sum: u64 = chunk.iter().sum();

            log::debug!("Lane {} partial sum: {}", lane_index, partial_sum);

            // Send the result back through the channel.
            // Include the lane index for logging/debugging.
            s.send((lane_index, partial_sum)).await
                .expect("Failed to send partial sum");

        }).expect("Failed to submit to lane");

        lanes.push(lane);
    }

    log::info!("All {} lanes spawned and ready", LANE_COUNT);

    // Collect all LANE_COUNT results.
    // We receive exactly LANE_COUNT results — one per lane.
    // Order is non-deterministic (depends on kernel scheduling).
    // We store in a pre-allocated array indexed by lane.
    let mut partial_sums = [0u64; LANE_COUNT];

    for received in 0..LANE_COUNT {
        let (lane_index, partial_sum) = receiver.receive().await
            .expect("Unexpected channel close");

        log::debug!("Received result from lane {}: {}", lane_index, partial_sum);

        // Store by lane index — order-independent
        partial_sums[lane_index] = partial_sum;

        log::info!("Progress: {}/{} results collected", received + 1, LANE_COUNT);
    }

    log::info!("All results collected. Assembling final sum...");

    // Assemble the final result from all partial results.
    // This is the A (Application Control) property:
    // the application decides what to do with all preserved results.
    let total: u64 = partial_sums.iter().sum();

    // Clean up: join all lanes
    for lane in lanes {
        lane.join().await;
    }

    total
}
