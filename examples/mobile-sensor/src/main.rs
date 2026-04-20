//! Mobile Sensor Access — Camera, Microphone, GPS
//!
//! This example demonstrates:
//!   - Requesting sensor access (kernel-mediated)
//!   - Reading frames from camera
//!   - Reading samples from microphone
//!   - Reading location from GPS
//!   - Releasing sensors when done
//!   - Running multiple sensors concurrently (different lanes)
//!
//! REQUIRES: CIBOS mobile variant with sensor-subsystem feature
//!
//! HIP concepts illustrated:
//!   Sensor access is mediated by the kernel isolation boundary.
//!   Sensor::request() asks the kernel for exclusive access.
//!   If another container holds the sensor, this stalls until
//!   the other container releases it.
//!   No container can bypass this — sensor access is physical isolation.
//!
//! ISOLATION MODEL FOR SENSORS:
//!
//!   ┌─────────────────────────────────────────────────────┐
//!   │                    Your Container                    │
//!   │                                                     │
//!   │  Sensor::request(Camera) ──────────────────────────►│──► Kernel
//!   │                                                     │      │
//!   │  (stall until available)                            │    Sensor
//!   │                                                     │   Isolation
//!   │  ◄── SensorHandle returned ──────────────────────── │   Boundary
//!   │                                                     │      │
//!   │  handle.read_frame() ──────────────────────────────►│──► Hardware
//!   │  ◄── frame data ────────────────────────────────────│      │
//!   │                                                     │      │
//!   │  handle.release() ─────────────────────────────────►│──► Released
//!   └─────────────────────────────────────────────────────┘
//!
//!   Another container cannot access the sensor while you hold it.
//!   The kernel enforces this at the hardware level.

#![no_std]
#![no_main]

extern crate alloc;

use cibos::{Lane, Timer};
use cibos::sensor::{Precision, Sensor, SensorError, SensorType};
use core::time::Duration;

#[cibos::main]
async fn main() {
    log::info!("=== Mobile Sensor Access starting ===");

    // Run camera and GPS demonstrations concurrently
    // Each in its own lane — they don't interfere with each other
    let mut camera_lane = Lane::create().expect("Failed to create camera lane");
    let mut gps_lane = Lane::create().expect("Failed to create GPS lane");
    let mut microphone_lane = Lane::create().expect("Failed to create microphone lane");

    camera_lane.submit(camera_demo()).expect("Failed to submit camera demo");
    gps_lane.submit(gps_demo()).expect("Failed to submit GPS demo");
    microphone_lane.submit(microphone_demo()).expect("Failed to submit microphone demo");

    // Wait for all demos to complete
    camera_lane.join().await;
    gps_lane.join().await;
    microphone_lane.join().await;

    log::info!("=== Mobile Sensor Access complete ===");
}

/// Camera demonstration: request access, capture frames, release
async fn camera_demo() {
    log::info!("Camera: requesting access...");

    // Sensor::request() is an async operation:
    // - If camera is available: returns immediately with SensorHandle
    // - If camera is held by another container: stalls until released
    // - If camera does not exist: returns Err(SensorError::NotAvailable)
    //
    // Precision::Fine = full resolution frames (highest CPU/memory cost)
    // Precision::Medium = medium resolution (balanced)
    // Precision::Coarse = low resolution (lowest cost)
    let camera = match Sensor::request(SensorType::Camera)
        .precision(Precision::Fine)
        .timeout(Duration::from_secs(5))  // Don't wait forever
        .await
    {
        Ok(handle) => {
            log::info!("Camera: access granted");
            handle
        }
        Err(SensorError::NotAvailable) => {
            log::warn!("Camera: not available on this hardware");
            return;
        }
        Err(SensorError::Timeout) => {
            log::warn!("Camera: timed out waiting for access");
            return;
        }
        Err(e) => {
            log::error!("Camera: request failed: {:?}", e);
            return;
        }
    };

    log::info!("Camera: resolution {}x{}", camera.width(), camera.height());

    // Capture 5 frames
    for frame_num in 0..5 {
        // read_frame() is an async operation:
        // - Camera captures frame and delivers it to this container
        // - Lane stalls while camera is capturing
        // - Returns when frame is ready
        match camera.read_frame().await {
            Ok(frame) => {
                log::info!(
                    "Camera: frame {} captured ({} bytes, format: {:?})",
                    frame_num,
                    frame.data().len(),
                    frame.format()
                );

                // Process the frame in isolation — no sharing with other lanes
                let brightness = compute_average_brightness(frame.data());
                log::info!("Camera: frame {} average brightness: {:.2}", frame_num, brightness);
            }
            Err(e) => {
                log::error!("Camera: frame {} capture failed: {:?}", frame_num, e);
                break;
            }
        }

        // Small delay between frames
        Timer::sleep(Duration::from_millis(33)).await; // ~30fps
    }

    // ALWAYS release the sensor when done.
    // release() is synchronous — kernel immediately marks sensor available.
    // If you don't call release(), the sensor stays held until your
    // container exits (which may be a long time).
    camera.release();
    log::info!("Camera: released");
}

/// GPS demonstration: request coarse location, read, release
async fn gps_demo() {
    log::info!("GPS: requesting access...");

    // Precision::Coarse for GPS = city-level accuracy
    // This is appropriate for most applications (lower battery usage)
    // Precision::Fine = GPS satellite precision (higher battery usage)
    //
    // The kernel may restrict Precision::Fine based on system policy
    // (e.g., Maximum Isolation profile may enforce Coarse only)
    let gps = match Sensor::request(SensorType::Gps)
        .precision(Precision::Coarse)
        .timeout(Duration::from_secs(30)) // GPS may need warmup time
        .await
    {
        Ok(handle) => {
            log::info!("GPS: access granted");
            handle
        }
        Err(SensorError::NotAvailable) => {
            log::warn!("GPS: not available on this hardware");
            return;
        }
        Err(e) => {
            log::error!("GPS: request failed: {:?}", e);
            return;
        }
    };

    // Read 3 location samples
    for sample_num in 0..3 {
        match gps.read_location().await {
            Ok(location) => {
                log::info!(
                    "GPS: sample {} — lat: {:.4}, lon: {:.4}, accuracy: {:.0}m",
                    sample_num,
                    location.latitude(),
                    location.longitude(),
                    location.accuracy_meters()
                );
            }
            Err(e) => {
                log::error!("GPS: location read {} failed: {:?}", sample_num, e);
                break;
            }
        }

        Timer::sleep(Duration::from_secs(1)).await;
    }

    gps.release();
    log::info!("GPS: released");
}

/// Microphone demonstration: request access, capture audio samples, release
async fn microphone_demo() {
    log::info!("Microphone: requesting access...");

    let microphone = match Sensor::request(SensorType::Microphone)
        .precision(Precision::Medium)
        .sample_rate(44100)   // 44.1kHz
        .channels(1)          // Mono
        .timeout(Duration::from_secs(5))
        .await
    {
        Ok(handle) => {
            log::info!("Microphone: access granted ({}Hz, {} channels)",
                       handle.sample_rate(), handle.channels());
            handle
        }
        Err(SensorError::NotAvailable) => {
            log::warn!("Microphone: not available on this hardware");
            return;
        }
        Err(e) => {
            log::error!("Microphone: request failed: {:?}", e);
            return;
        }
    };

    // Capture audio for 1 second (44100 samples at 44.1kHz)
    log::info!("Microphone: capturing 1 second of audio...");

    // read_samples() returns a buffer of audio samples
    // sample_count = how many samples to capture (blocks until complete)
    match microphone.read_samples(44100).await {
        Ok(samples) => {
            log::info!("Microphone: captured {} samples", samples.len());

            // Compute RMS amplitude
            let rms = compute_audio_rms(samples.data());
            log::info!("Microphone: RMS amplitude: {:.4}", rms);
        }
        Err(e) => {
            log::error!("Microphone: capture failed: {:?}", e);
        }
    }

    microphone.release();
    log::info!("Microphone: released");
}

/// Compute average brightness of a frame (grayscale)
fn compute_average_brightness(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let sum: u64 = data.iter().map(|&b| b as u64).sum();
    sum as f32 / data.len() as f32
}

/// Compute RMS (root mean square) amplitude of audio samples
fn compute_audio_rms(samples: &[i16]) -> f32 {
    if samples.is_empty() { return 0.0; }
    let sum_sq: f64 = samples.iter().map(|&s| (s as f64) * (s as f64)).sum();
    (sum_sq / samples.len() as f64).sqrt() as f32
}
