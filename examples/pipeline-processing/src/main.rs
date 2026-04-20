//! Pipeline Processing — Read → Process → Write
//!
//! This example demonstrates:
//!   - Dedicated lanes for pipeline stages
//!   - Back-pressure through channel buffering
//!   - Pipeline composition pattern
//!   - Graceful pipeline shutdown
//!
//! HIP concepts illustrated:
//!   P (Parallel Pathways): Three lanes run simultaneously:
//!     Read lane, Process lane, Write lane.
//!     All three are active at the same time when data is flowing.
//!   I (Interference-Free): Stages communicate only through channels.
//!     No shared mutable state between pipeline stages.
//!   The pipeline demonstrates HIP's natural fit for streaming:
//!     each stage is a self-contained lane, communication is
//!     explicit through typed channels, back-pressure is automatic.
//!
//! PIPELINE STRUCTURE:
//!
//!   [Input Channel]  →  [Read Lane]  →  [raw_channel]
//!                                           │
//!                                    [Process Lane]  →  [proc_channel]
//!                                                           │
//!                                                    [Write Lane]  →  [Output Channel]

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use cibos::{Channel, Lane};

/// Data types for this pipeline
#[derive(Debug, Clone)]
struct RawRecord {
    id: u64,
    data: [u8; 64],
}

#[derive(Debug, Clone)]
struct ProcessedRecord {
    id: u64,
    checksum: u32,
    transformed: [u8; 32],
}

#[cibos::main]
async fn main() {
    log::info!("=== Pipeline Processing starting ===");

    // In a real application, input comes from a channel to another container
    // and output goes to another container. Here we simulate both.
    let (input_sender, input_receiver) = Channel::new_local(16)
        .expect("Failed to create input channel");
    let (output_sender, output_receiver) = Channel::new_local(16)
        .expect("Failed to create output channel");

    // Spawn a producer to feed the pipeline
    let mut producer = Lane::create().expect("Failed to create producer lane");
    producer.submit(async move {
        for i in 0u64..100 {
            let record = RawRecord {
                id: i,
                data: [i as u8; 64],
            };
            input_sender.send(record).await
                .expect("Input channel closed unexpectedly");
            log::debug!("Produced record {}", i);
        }
        // Close input — signals end of stream
        input_sender.close();
        log::info!("Producer complete — 100 records produced");
    }).expect("Failed to submit producer");

    // Spawn a consumer to drain the pipeline output
    let mut consumer = Lane::create().expect("Failed to create consumer lane");
    consumer.submit(async move {
        let mut count = 0u64;
        while let Some(record) = output_receiver.receive().await {
            log::debug!("Consumed processed record {} (checksum: {})",
                        record.id, record.checksum);
            count += 1;
        }
        log::info!("Consumer complete — {} records consumed", count);
    }).expect("Failed to submit consumer");

    // Build and run the pipeline
    run_pipeline(input_receiver, output_sender).await;

    // Wait for consumer to finish
    consumer.join().await;
    producer.join().await;

    log::info!("=== Pipeline Processing complete ===");
}

/// Run a three-stage pipeline:
///   Stage 1 (Read):    Receive raw records from input
///   Stage 2 (Process): Transform each record
///   Stage 3 (Write):   Send processed records to output
///
/// Each stage runs in its own dedicated lane.
/// Stages communicate through local channels.
/// Back-pressure flows naturally: if Process is slow, Read stalls (buffer full).
async fn run_pipeline(
    input: Channel<RawRecord>,
    output: Channel<ProcessedRecord>,
) {
    // Inter-stage channels
    // Buffer size = 8: Process can get 8 records ahead of Write
    let (raw_sender, raw_receiver) = Channel::new_local(8)
        .expect("Failed to create raw channel");
    let (proc_sender, proc_receiver) = Channel::new_local(8)
        .expect("Failed to create processed channel");

    // Stage 1: Read Lane
    // Reads from input channel, forwards to processing stage
    let mut read_lane = Lane::create().expect("Failed to create read lane");
    read_lane.submit(async move {
        log::info!("Read stage started");
        let mut count = 0u64;

        while let Some(record) = input.receive().await {
            log::debug!("Read stage: forwarding record {}", record.id);
            raw_sender.send(record).await
                .expect("Raw channel closed — process stage may have crashed");
            count += 1;
        }

        // Input closed — close the raw channel to signal process stage
        raw_sender.close();
        log::info!("Read stage complete — {} records forwarded", count);
    }).expect("Failed to submit read stage");

    // Stage 2: Process Lane
    // Transforms raw records into processed records
    let mut process_lane = Lane::create().expect("Failed to create process lane");
    process_lane.submit(async move {
        log::info!("Process stage started");
        let mut count = 0u64;

        while let Some(raw) = raw_receiver.receive().await {
            log::debug!("Process stage: transforming record {}", raw.id);

            // Transform the record
            let processed = transform_record(raw);

            proc_sender.send(processed).await
                .expect("Processed channel closed — write stage may have crashed");
            count += 1;
        }

        // Raw channel closed — close processed channel to signal write stage
        proc_sender.close();
        log::info!("Process stage complete — {} records transformed", count);
    }).expect("Failed to submit process stage");

    // Stage 3: Write Lane
    // Takes processed records and sends to output
    let mut write_lane = Lane::create().expect("Failed to create write lane");
    write_lane.submit(async move {
        log::info!("Write stage started");
        let mut count = 0u64;

        while let Some(processed) = proc_receiver.receive().await {
            log::debug!("Write stage: outputting record {}", processed.id);
            output.send(processed).await
                .expect("Output channel closed unexpectedly");
            count += 1;
        }

        // Processed channel closed — close output to signal consumer
        output.close();
        log::info!("Write stage complete — {} records written", count);
    }).expect("Failed to submit write stage");

    // Wait for all stages to complete
    // They complete in order: Read → Process → Write (via channel closure signals)
    read_lane.join().await;
    log::info!("Read stage joined");

    process_lane.join().await;
    log::info!("Process stage joined");

    write_lane.join().await;
    log::info!("Write stage joined");

    log::info!("Pipeline complete.");
}

/// Transform a raw record into a processed record.
/// Pure function — no I/O, no shared state.
fn transform_record(raw: RawRecord) -> ProcessedRecord {
    // Compute a simple checksum
    let checksum: u32 = raw.data.iter().map(|&b| b as u32).sum();

    // Transform the data (downsample 64 bytes → 32 bytes)
    let mut transformed = [0u8; 32];
    for i in 0..32 {
        transformed[i] = raw.data[i * 2].wrapping_add(raw.data[i * 2 + 1]);
    }

    ProcessedRecord {
        id: raw.id,
        checksum,
        transformed,
    }
}
