//! Compute-Intensive — Scientific Computation with Dynamic Weights
//!
//! This example demonstrates:
//!   - Dynamic weight adjustment during phased computation
//!   - Maximum parallelism for compute workloads
//!   - Weight-based priority for I/O-bound vs compute-bound phases
//!   - Profile awareness (#[cfg(feature = "dynamic-weights")])
//!
//! REQUIRES: Compute profile with per-lane-weights + dynamic-weights features
//!
//! HIP concepts illustrated:
//!   P: 16 compute lanes run simultaneously in Phase 2.
//!   I: Each compute lane works on independent data partitions.
//!   N: Compute lanes complete in non-deterministic order.
//!   A: All 16 partial results are collected and merged.
//!
//! DYNAMIC WEIGHTS IN COMPUTE PROFILE:
//!   Phase 1 (Load):    data_lane weight=5, compute weight=1
//!     → Load lane gets ~71% of dispatch chances (5/(5+1×16))
//!     → Compute lanes get ~4% each — they're idle anyway
//!   Phase 2 (Compute): All weights equal
//!     → Equal dispatch probability for all 16 compute lanes
//!     → Maximum throughput through hardware cores
//!   Phase 3 (Collect): result_lane weight=5, others=1
//!     → Result collection gets priority as compute lanes finish
//!
//! WHY DYNAMIC WEIGHTS ARE SAFE ON COMPUTE PROFILE:
//!   Compute profile has no adversary — it's dedicated hardware.
//!   Weight patterns are not observable by an attacker.
//!   The performance benefit (phased priority) outweighs
//!   the theoretical timing information they reveal.
//!   On Maximum Isolation or Balanced, dynamic-weights is prohibited
//!   because observable weight patterns = timing side channel.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use cibos::{Channel, Lane};

/// Number of parallel compute lanes.
/// Tune to: (physical_cores × logical_per_physical) - overhead_lanes
/// On a 16-core machine with SMT: ~28 compute lanes (leaving 4 for OS)
const COMPUTE_LANE_COUNT: usize = 16;

/// Dataset partitions — must equal COMPUTE_LANE_COUNT
const PARTITION_COUNT: usize = COMPUTE_LANE_COUNT;

/// Simulated large dataset
const DATA_SIZE: usize = 16_000_000; // 16 million f64 values

#[cibos::main]
async fn main() {
    log::info!("=== Compute-Intensive starting ===");

    // Verify we're on the right profile
    // (In real apps, check at build time via #[cfg(feature = "...")]
    //  and provide a fallback for other profiles)
    #[cfg(not(feature = "per-lane-weights"))]
    {
        log::warn!("per-lane-weights not compiled — running without weight control");
        log::warn!("For full example, use Compute profile with per-lane-weights feature");
    }

    // Generate simulated dataset
    // In real app: receive via channel from data source
    log::info!("Generating dataset ({} values)...", DATA_SIZE);
    let data: Vec<f64> = (0..DATA_SIZE).map(|i| i as f64 * 0.001).collect();

    // Run phased computation
    let result = phased_scientific_computation(data).await;

    log::info!("Final result: {:.6}", result);
    log::info!("=== Compute-Intensive complete ===");
}

/// Phased scientific computation with dynamic weight adjustment.
///
/// Phase 1: Load and distribute data (I/O bound)
///   - Data lane has high weight → gets more dispatch
///   - Compute lanes have low weight → they're not ready anyway
///
/// Phase 2: Parallel compute (CPU bound)
///   - All lanes have equal weight → maximum parallelism
///   - All 16 compute lanes run simultaneously
///
/// Phase 3: Collect and aggregate results
///   - Result lane has high weight → prioritize collection
///   - Compute lanes finishing → they need to send results
async fn phased_scientific_computation(data: Vec<f64>) -> f64 {

    // Create the data distribution lane
    #[cfg(feature = "per-lane-weights")]
    let mut data_lane = Lane::create_with_weight(1).expect("Failed to create data lane");
    #[cfg(not(feature = "per-lane-weights"))]
    let mut data_lane = Lane::create().expect("Failed to create data lane");

    // Create 16 compute lanes, all starting with weight 1
    let mut compute_lanes: Vec<Lane> = (0..COMPUTE_LANE_COUNT)
        .map(|_| {
            #[cfg(feature = "per-lane-weights")]
            { Lane::create_with_weight(1).expect("Failed to create compute lane") }
            #[cfg(not(feature = "per-lane-weights"))]
            { Lane::create().expect("Failed to create compute lane") }
        })
        .collect();

    // Create the result collection lane
    #[cfg(feature = "per-lane-weights")]
    let mut result_lane = Lane::create_with_weight(1).expect("Failed to create result lane");
    #[cfg(not(feature = "per-lane-weights"))]
    let mut result_lane = Lane::create().expect("Failed to create result lane");

    // Result channel: collect partial results from all compute lanes
    let (result_sender, result_receiver) = Channel::new_local(COMPUTE_LANE_COUNT)
        .expect("Failed to create result channel");

    // Partition channel: distribute data partitions to compute lanes
    // We'll use separate channels per compute lane for clean distribution
    let mut partition_channels: Vec<(Channel<Vec<f64>>, Channel<Vec<f64>>)> = (0..COMPUTE_LANE_COUNT)
        .map(|_| Channel::new_local(1).expect("Failed to create partition channel"))
        .collect();

    // ─────────────────────────────────────────────────────────────────
    // PHASE 1: DATA LOADING
    // Prioritize the data lane — it's doing the I/O work
    // ─────────────────────────────────────────────────────────────────

    log::info!("Phase 1: Loading and distributing data...");

    #[cfg(feature = "dynamic-weights")]
    {
        // Raise data lane weight to 5 — it gets priority dispatch
        data_lane.update_weight(5).expect("Failed to update data lane weight");
        log::debug!("Data lane weight set to 5 (Phase 1)");
    }

    // Extract partition senders before moving lanes
    let mut partition_senders: Vec<_> = partition_channels
        .iter_mut()
        .map(|(s, _)| s.clone())
        .collect();

    // Data lane: partition the dataset and distribute to compute lanes
    data_lane.submit(async move {
        let partition_size = data.len() / PARTITION_COUNT;

        for (i, sender) in partition_senders.iter().enumerate() {
            let partition: Vec<f64> = data[i * partition_size..(i + 1) * partition_size].to_vec();
            log::debug!("Distributing partition {} ({} values)", i, partition.len());
            sender.send(partition).await
                .expect("Partition channel closed");
        }

        log::info!("Phase 1 complete — {} partitions distributed", PARTITION_COUNT);
    }).expect("Failed to submit data lane");

    // ─────────────────────────────────────────────────────────────────
    // PHASE 2: PARALLEL COMPUTATION
    // Equal weights — maximum hardware utilization
    // ─────────────────────────────────────────────────────────────────

    log::info!("Phase 2: Parallel computation ({} lanes)...", COMPUTE_LANE_COUNT);

    #[cfg(feature = "dynamic-weights")]
    {
        // Reset data lane to equal weight — Phase 1 is submitting, not running
        data_lane.update_weight(1).expect("Failed to reset data lane weight");

        // All compute lanes at equal weight — equal dispatch probability
        for lane in compute_lanes.iter_mut() {
            lane.update_weight(1).expect("Failed to set compute lane weight");
        }

        log::debug!("All weights equalized for Phase 2");
    }

    // Launch all compute lanes simultaneously
    for (i, (mut lane, (_, receiver))) in compute_lanes.iter_mut()
        .zip(partition_channels.iter_mut())
        .enumerate()
    {
        let rs = result_sender.clone();
        let receiver = receiver.clone();
        let lane_index = i;

        lane.submit(async move {
            // Receive this lane's partition
            let partition = receiver.receive().await
                .expect("Partition not received");

            log::debug!("Compute lane {} received {} values", lane_index, partition.len());

            // Scientific computation: sum of squares (simulating real work)
            // In real app: FFT, matrix multiply, Monte Carlo simulation, etc.
            let partial_result: f64 = partition.iter()
                .map(|&x| x * x)
                .sum();

            log::debug!("Compute lane {} partial result: {:.6}", lane_index, partial_result);

            // Send result back
            rs.send((lane_index, partial_result)).await
                .expect("Result channel closed");

        }).expect("Failed to submit compute lane");
    }

    // ─────────────────────────────────────────────────────────────────
    // PHASE 3: RESULT COLLECTION
    // Prioritize result lane — it's assembling the final answer
    // ─────────────────────────────────────────────────────────────────

    log::info!("Phase 3: Collecting results...");

    #[cfg(feature = "dynamic-weights")]
    {
        result_lane.update_weight(5).expect("Failed to set result lane weight");
        log::debug!("Result lane weight set to 5 (Phase 3)");
    }

    let final_result_receiver = result_receiver;

    result_lane.submit(async move {
        let mut partial_results = [0f64; COMPUTE_LANE_COUNT];

        for received in 0..COMPUTE_LANE_COUNT {
            let (lane_index, partial) = final_result_receiver.receive().await
                .expect("Result channel closed early");

            partial_results[lane_index] = partial;
            log::debug!("Collected result from lane {}: {:.6}", lane_index, partial);
            log::info!("Phase 3 progress: {}/{}", received + 1, COMPUTE_LANE_COUNT);
        }

        let total: f64 = partial_results.iter().sum();
        log::info!("Phase 3 complete — final result: {:.6}", total);

        // In real app: send final result through output channel
        // Here we just log it

    }).expect("Failed to submit result lane");

    // Wait for all phases to complete
    data_lane.join().await;
    log::info!("Phase 1 (data) joined");

    for lane in compute_lanes.iter_mut() {
        lane.join().await;
    }
    log::info!("Phase 2 (compute) joined");

    result_lane.join().await;
    log::info!("Phase 3 (result) joined");

    // Return placeholder — in real app, return via channel
    0.0
}
