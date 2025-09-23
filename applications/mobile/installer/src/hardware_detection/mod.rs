// =============================================================================
// MOBILE INSTALLER HARDWARE DETECTION MODULE - cibos/applications/mobile/installer/src/hardware_detection/mod.rs
// =============================================================================

//! Mobile hardware detection for installation compatibility verification
//! 
//! This module provides comprehensive mobile device hardware detection
//! and compatibility verification to ensure successful CIBIOS/CIBOS-MOBILE
//! installation across diverse mobile hardware platforms.

// External hardware detection dependencies
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;

// Mobile hardware detection component exports
pub use self::detector::{MobileHardwareDetector, MobileDeviceScanner, MobileCapabilityDetector};
pub use self::compatibility::{MobileCompatibilityChecker, MobileArchitectureCompatibility, MobilePlatformCompatibility};
pub use self::platform::{MobilePlatformDetector, MobileOSDetector, MobileBootloaderDetector};
pub use self::connection::{MobileConnectionDetector, MobileInterfaceScanner, MobileProtocolDetector};

// Mobile installer imports
use crate::{MobileDeviceInfo, MobileConnectionType, MobileFlashInterface, MobileSecurityFeatures};

// Shared imports
use shared::types::hardware::{
    ProcessorArchitecture, MobileHardwareConfiguration, TouchCapabilities, SensorCapabilities
};
use shared::types::error::{MobileHardwareError, MobileDetectionError};

// Hardware detection module declarations
pub mod detector;
pub mod compatibility;
pub mod platform;
pub mod connection;

/// Main mobile hardware detector coordinating device discovery and analysis
#[derive(Debug)]
pub struct MobileHardwareDetector {
    device_scanner: Arc<MobileDeviceScanner>,
    capability_detector: Arc<MobileCapabilityDetector>,
    compatibility_checker: Arc<MobileCompatibilityChecker>,
    connection_detector: Arc<MobileConnectionDetector>,
}

impl MobileHardwareDetector {
    /// Initialize mobile hardware detector
    pub async fn initialize() -> AnyhowResult<Self> {
        info!("Initializing mobile hardware detector");

        // Initialize mobile device scanner
        let device_scanner = Arc::new(MobileDeviceScanner::initialize().await
            .context("Mobile device scanner initialization failed")?);

        // Initialize mobile capability detector
        let capability_detector = Arc::new(MobileCapabilityDetector::initialize().await
            .context("Mobile capability detector initialization failed")?);

        // Initialize mobile compatibility checker
        let compatibility_checker = Arc::new(MobileCompatibilityChecker::initialize().await
            .context("Mobile compatibility checker initialization failed")?);

        // Initialize mobile connection detector
        let connection_detector = Arc::new(MobileConnectionDetector::initialize().await
            .context("Mobile connection detector initialization failed")?);

        Ok(Self {
            device_scanner,
            capability_detector,
            compatibility_checker,
            connection_detector,
        })
    }

    /// Scan for connected mobile devices available for installation
    pub async fn scan_for_mobile_devices(&self) -> AnyhowResult<Vec<ConnectedMobileDevice>> {
        info!("Scanning for connected mobile devices");

        let connected_devices = self.device_scanner.scan_connected_devices().await
            .context("Mobile device scan failed")?;

        info!("Found {} mobile devices connected", connected_devices.len());
        Ok(connected_devices)
    }

    /// Detect comprehensive hardware specifications for mobile device
    pub async fn detect_device_specifications(&self) -> AnyhowResult<MobileDeviceInfo> {
        info!("Detecting mobile device hardware specifications");

        // Detect basic device information
        let device_info = self.device_scanner.detect_device_info().await
            .context("Mobile device info detection failed")?;

        // Detect hardware capabilities
        let capabilities = self.capability_detector.detect_hardware_capabilities(&device_info).await
            .context("Mobile hardware capability detection failed")?;

        // Combine information into complete device specification
        let complete_device_info = MobileDeviceInfo {
            device_model: device_info.device_model,
            manufacturer: device_info.manufacturer,
            processor_architecture: capabilities.processor_architecture,
            memory_size: capabilities.memory_size,
            storage_size: capabilities.storage_size,
            flash_interface: capabilities.flash_interface,
            security_features: capabilities.security_features,
        };

        info!("Mobile device specifications detected: {} {}", 
               complete_device_info.manufacturer, complete_device_info.device_model);

        Ok(complete_device_info)
    }

    /// Check mobile device compatibility with CIBIOS/CIBOS-MOBILE
    pub async fn check_mobile_compatibility(&self, device_info: &MobileDeviceInfo) -> AnyhowResult<MobileCompatibilityResult> {
        info!("Checking mobile device compatibility with CIBIOS/CIBOS-MOBILE");

        let compatibility_result = self.compatibility_checker.check_device_compatibility(device_info).await
            .context("Mobile device compatibility check failed")?;

        if compatibility_result.compatible {
            info!("Mobile device is compatible with CIBIOS/CIBOS-MOBILE");
        } else {
            warn!("Mobile device compatibility issues: {}", compatibility_result.reason);
        }

        Ok(compatibility_result)
    }
}

/// Connected mobile device information
#[derive(Debug, Clone)]
pub struct ConnectedMobileDevice {
    pub device_name: String,
    pub connection_type: MobileConnectionType,
    pub device_id: String,
}

/// Mobile device compatibility result
#[derive(Debug, Clone)]
pub struct MobileCompatibilityResult {
    pub compatible: bool,
    pub reason: String,
    pub supported_features: Vec<String>,
    pub missing_requirements: Vec<String>,
}

/// Mobile hardware capabilities detected during scanning
#[derive(Debug, Clone)]
pub struct MobileHardwareCapabilities {
    pub processor_architecture: ProcessorArchitecture,
    pub memory_size: u64,
    pub storage_size: u64,
    pub flash_interface: MobileFlashInterface,
    pub security_features: MobileSecurityFeatures,
}

/// Basic mobile device information
#[derive(Debug, Clone)]
pub struct BasicMobileDeviceInfo {
    pub device_model: String,
    pub manufacturer: String,
    pub device_id: String,
}
