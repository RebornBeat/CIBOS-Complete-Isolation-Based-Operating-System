//! Profile-Flexible Application
//!
//! This example demonstrates:
//!   - Writing code that compiles and runs correctly on ALL profiles
//!   - Using #[cfg(feature = "...")] for profile-specific behavior
//!   - Graceful degradation when advanced features are not available
//!   - The correct way to check for optional features at runtime
//!
//! This application runs on:
//!   ✓ Maximum Isolation (no per-lane-weights, no dynamic-weights)
//!   ✓ Balanced         (no per-lane-weights, no dynamic-weights)
//!   ✓ Performance      (no per-lane-weights, no dynamic-weights)
//!   ✓ Compute          (with per-lane-weights and dynamic-weights)
//!
//! The core functionality is IDENTICAL on all profiles.
//! Optional features ENHANCE behavior on Compute but are never required.
//!
//! DESIGN PRINCIPLE: Write for correctness first, optimize for Compute second.
//!   1. Make the core algorithm correct without any optional features
//!   2. Use #[cfg(feature = "...")] to enhance on profiles that support it
//!   3. Never make the core algorithm depend on optional features

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use cibos::{Channel, Lane};

#[cibos::main]
async fn main() {
    log::info!("=== Profile-Flexible Application starting ===");

    // Print which optional features are available
    log::info!("Profile capabilities:");
    #[cfg(feature = "per-lane-weights")]
    log::info!("  per-lane-weights: YES (Compute profile)");
    #[cfg(not(feature = "per-lane-weights"))]
    log::info!("  per-lane-weights: NO (Maximum Isolation, Balanced, or Performance)");

    #[cfg(feature = "dynamic-weights")]
    log::info!("  dynamic-weights: YES (Compute profile with dynamic-weights)");
    #[cfg(not(feature = "dynamic-weights"))]
    log::info!("  dynamic-weights: NO");

    #[cfg(feature = "signal-coalescence")]
    log::info!("  signal-coalescence: YES");
    #[cfg(not(feature = "signal-coalescence"))]
    log::info!("  signal-coalescence: NO");

    // Run the profile-flexible computation
    let result = flexible_computation(1000).await;
    log::info!("Result: {}", result);

    log::info!("=== Profile-Flexible Application complete ===");
}

/// A computation that works correctly on all profiles.
///
/// Core behavior: Sum numbers 0..n using parallel lanes.
/// Enhancement on Compute: Dynamic weight adjustment for phases.
async fn flexible_computation(n: u64) -> u64 {

    // Lane creation — works on all profiles
    // Per-lane-weights is purely an enhancement, never required for correctness
    let mut lane = create_lane_with_optional_weight(1);

    // Prepare data
    let numbers: Vec<u64> = (0..n).collect();
    let (result_sender, result_receiver) = Channel::new_local(1)
        .expect("Failed to create result channel");

    // Submit computation — identical regardless of profile
    lane.submit(async move {
        let sum: u64 = numbers.iter().sum();
        result_sender.send(sum).await.expect("Result channel closed");
    }).expect("Failed to submit computation");

    // Optionally adjust weight after submission (Compute only)
    // This is an enhancement — on other profiles, this is a no-op at compile time
    #[cfg(feature = "dynamic-weights")]
    {
        // On Compute: lower this lane's weight since it's doing background work
        let _ = lane.update_weight(1); // ignore error if not supported
        log::debug!("Dynamic weight adjustment applied");
    }

    // Collect result — identical regardless of profile
    let sum = result_receiver.receive().await.expect("No result received");

    lane.join().await;

    sum
}

/// Create a lane, optionally with an initial weight.
///
/// On profiles with per-lane-weights: creates lane with specified weight.
/// On profiles without per-lane-weights: creates lane with default weight.
///
/// The returned lane behaves identically in both cases —
/// the weight is just a scheduling hint.
fn create_lane_with_optional_weight(weight: u32) -> Lane {
    #[cfg(feature = "per-lane-weights")]
    {
        // Compute profile: create with explicit weight
        Lane::create_with_weight(weight)
            .unwrap_or_else(|_| Lane::create().expect("Failed to create lane"))
    }
    #[cfg(not(feature = "per-lane-weights"))]
    {
        // Other profiles: weight parameter is ignored
        let _ = weight; // suppress unused warning
        Lane::create().expect("Failed to create lane")
    }
}

/// Profile-aware data processing.
///
/// Demonstrates how to write data processing that:
/// - Uses basic channels on all profiles
/// - Takes advantage of class affinity on Performance profile
/// - Uses lightweight channels on Compute profile
async fn profile_aware_processing(data: Vec<u64>) -> Vec<u64> {

    // Basic processing: works on all profiles
    let mut lane = create_lane_with_optional_weight(2);
    let (out_sender, out_receiver) = Channel::new_local(data.len())
        .expect("Failed to create output channel");

    // On Performance profile with class-core-affinity:
    // The kernel will prefer to schedule this lane on the same core
    // as related lanes, improving cache locality.
    // On other profiles: no effect.
    #[cfg(feature = "class-core-affinity")]
    {
        lane.set_class_affinity(cibos::scheduling::ClassAffinity::DataProcessing)
            .unwrap_or(()); // ignore if not supported
        log::debug!("Class affinity set for data processing");
    }

    lane.submit(async move {
        for value in data {
            // Simple transformation: double the value
            let processed = value * 2;
            out_sender.send(processed).await.expect("Output channel closed");
        }
        out_sender.close();
    }).expect("Failed to submit processing lane");

    // Collect results
    let mut results = Vec::new();
    while let Some(value) = out_receiver.receive().await {
        results.push(value);
    }

    lane.join().await;

    results
}
