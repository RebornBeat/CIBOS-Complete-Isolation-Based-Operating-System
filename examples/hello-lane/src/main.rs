//! Hello Lane — Minimal CIBOS Application
//!
//! This example demonstrates:
//!   - The minimal structure of a CIBOS application
//!   - Creating and submitting to a lane
//!   - The Timer async primitive (stall and resume)
//!   - The #[cibos::main] entry point macro
//!
//! HIP concepts illustrated:
//!   P (Parallel Pathways): The submitted future runs in its own lane,
//!     separate from the main lane. Both exist simultaneously.
//!   I (Interference-Free): No shared state between lanes.
//!     compute_greeting() takes no shared references.
//!   N (Non-Deterministic): If multiple lanes were ready simultaneously,
//!     the kernel would select one non-deterministically. With one lane
//!     active at a time here, this is trivially deterministic.
//!   A (Application Control): All results are preserved.
//!     The main lane collects the result via lane.join().

#![no_std]
#![no_main]

extern crate alloc;

use cibos::{Lane, LaneError, Timer};
use core::time::Duration;

/// Entry point. Runs as the initial lane in your container.
///
/// The #[cibos::main] macro:
///   1. Sets up no_std panic handler
///   2. Initializes the container's allocator
///   3. Calls your async fn as the initial lane's future
///   4. Exits the container cleanly when this fn returns
#[cibos::main]
async fn main() {
    log::info!("=== Hello Lane starting ===");

    // Lane::create() registers a new execution lane with the kernel.
    //
    // In HIP terms: this creates a new parallel pathway.
    // The lane starts empty — no futures submitted yet.
    // Creating a lane does NOT immediately execute anything.
    //
    // Returns: Ok(Lane) or Err(LaneError)
    // Errors:  LaneError::ContainerAtCapacity if at lane limit
    //          LaneError::SystemAtCapacity if system-wide limit reached
    let mut lane = Lane::create().expect("Failed to create lane");

    log::info!("Lane {} created", lane.id());

    // lane.submit() gives the kernel a future to execute on this lane.
    //
    // In HIP terms: this places a container in the Ready Pool.
    // The kernel Catch and Release will dispatch it when resources allow.
    //
    // Important: submit() does NOT block. The future begins executing
    // when the kernel dispatches it, not when you call submit().
    lane.submit(async {
        log::info!("Inside the lane — running in HIP execution model");

        // Pure computation: no I/O, no shared state, no locks.
        // This is the ideal form of lane work: isolated computation.
        let result = compute_greeting("CIBOS");

        log::info!("Computed result: {}", result);

        // Timer::sleep() is an async primitive that stalls this lane.
        //
        // In HIP terms: this lane moves from Ready Pool to Stalled List.
        // The timer is registered with the kernel event system.
        // When 100ms passes, the kernel moves this lane back to Ready Pool.
        // The selector then dispatches it again for the code after .await.
        //
        // No busy-waiting. No polling. Pure event-driven.
        Timer::sleep(Duration::from_millis(100)).await;

        log::info!("Timer fired — lane resumed after 100ms");
        log::info!("Lane work complete.");

    }).expect("Failed to submit to lane");

    log::info!("Future submitted — lane is now in Ready Pool");

    // lane.join() stalls the current (main) lane until the submitted
    // future completes. This is itself an async operation:
    // the main lane moves to Stalled List, the submitted lane runs,
    // when it finishes the main lane moves back to Ready Pool.
    //
    // In real applications you would do other work here instead of
    // immediately joining. This is just the simplest demonstration.
    lane.join().await;

    log::info!("=== Hello Lane complete ===");
}

/// Pure computation — takes no shared references, returns owned value.
///
/// This is the correct pattern for lane work:
/// - All inputs are passed by value (or reference within the lane's scope)
/// - The result is returned by value
/// - No global state accessed
/// - No locks needed
fn compute_greeting(target: &str) -> alloc::string::String {
    alloc::format!("Hello from a lane, {}!", target)
}
