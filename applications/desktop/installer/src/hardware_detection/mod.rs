// =============================================================================
// HARDWARE DETECTION MODULE - cibos/applications/desktop/installer/src/hardware_detection/mod.rs
// Hardware Detection and Compatibility Verification
// =============================================================================

//! Hardware detection and compatibility checking
//! 
//! This module provides comprehensive hardware detection, capability assessment,
//! and compatibility verification for CIBIOS/CIBOS installation across different
//! processor architectures and platform types.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{fs, process::Command, time::Duration};
use uuid::Uuid;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// Hardware detection component exports
pub use self::detector::{HardwareDetector, DetectionEngine, HardwareProbe};
pub use self::compatibility::{CompatibilityChecker, CompatibilityResult, CompatibilityReport};
pub use self::platform::{PlatformDetector, PlatformIdentifier, PlatformCapabilities};
pub use self::processor::{ProcessorDetector, ProcessorInfo, ArchitectureCapabilities};

// Shared imports for hardware operations
use shared::types::hardware::{
    HardwarePlatform, ProcessorArchitecture, SecurityCapabilities,
    DisplayCapabilities, InputCapabilities, AudioCapabilities,
    NetworkCapabilities, StorageCapabilities
};
use shared::types::error::{HardwareError, DetectionError, CompatibilityError};

// Module declarations for hardware detection
pub mod detector;
pub mod compatibility;
pub mod platform;
pub mod processor;

/// Main hardware detector coordinating all detection operations
#[derive(Debug)]
pub struct HardwareDetector {
    pub detection_engine: DetectionEngine,
    pub compatibility_checker: CompatibilityChecker,
    pub platform_detector: PlatformDetector,
    pub processor_detector: ProcessorDetector,
}

/// Complete hardware detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareDetectionResult {
    pub detection_successful: bool,
    pub platform: HardwarePlatform,
    pub architecture: ProcessorArchitecture,
    pub processor_info: ProcessorInformation,
    pub security_capabilities: SecurityCapabilities,
    pub storage_devices: Vec<crate::StorageDevice>,
    pub memory_size: u64,
    pub detection_timestamp: DateTime<Utc>,
}

/// Processor information detected from hardware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorInformation {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub base_frequency: u64,
    pub cache_sizes: CacheSizes,
    pub instruction_sets: Vec<String>,
}

/// CPU cache size information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSizes {
    pub l1_instruction: u32,
    pub l1_data: u32,
    pub l2: u32,
    pub l3: Option<u32>,
}

/// Hardware compatibility check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityResult {
    pub compatible: bool,
    pub reason: String,
    pub requirements_met: Vec<String>,
    pub requirements_failed: Vec<String>,
    pub warnings: Vec<String>,
}

impl HardwareDetector {
    /// Initialize hardware detector with detection engines
    pub async fn initialize() -> AnyhowResult<Self> {
        info!("Initializing hardware detector");

        let detection_engine = DetectionEngine::initialize().await
            .context("Detection engine initialization failed")?;

        let compatibility_checker = CompatibilityChecker::initialize().await
            .context("Compatibility checker initialization failed")?;

        let platform_detector = PlatformDetector::initialize().await
            .context("Platform detector initialization failed")?;

        let processor_detector = ProcessorDetector::initialize().await
            .context("Processor detector initialization failed")?;

        info!("Hardware detector initialization completed");

        Ok(Self {
            detection_engine,
            compatibility_checker,
            platform_detector,
            processor_detector,
        })
    }

    /// Detect complete hardware configuration
    pub async fn detect_hardware(&self) -> AnyhowResult<crate::HardwareConfiguration> {
        info!("Starting comprehensive hardware detection");

        // Detect processor architecture and capabilities
        let processor_info = self.processor_detector.detect_processor().await
            .context("Processor detection failed")?;

        // Detect platform type (desktop, mobile, server, etc.)
        let platform = self.platform_detector.detect_platform().await
            .context("Platform detection failed")?;

        // Detect security capabilities
        let security_caps = self.detect_security_capabilities(&processor_info).await
            .context("Security capability detection failed")?;

        // Detect storage devices
        let storage_devices = self.detection_engine.detect_storage_devices().await
            .context("Storage device detection failed")?;

        // Detect memory configuration
        let memory_size = self.detection_engine.detect_memory_size().await
            .context("Memory detection failed")?;

        // Create hardware capabilities summary
        let capabilities = crate::HardwareCapabilities {
            virtualization_support: security_caps.hardware_virtualization,
            secure_boot_support: security_caps.secure_boot_support,
            encryption_acceleration: security_caps.hardware_encryption,
            trusted_platform_module: security_caps.trusted_platform_module,
        };

        let hardware_config = crate::HardwareConfiguration {
            platform,
            architecture: processor_info.architecture,
            memory_size,
            storage_devices,
            capabilities,
        };

        info!("Hardware detection completed: {:?} on {:?}", 
              hardware_config.architecture, hardware_config.platform);

        Ok(hardware_config)
    }

    /// Check hardware compatibility with CIBIOS/CIBOS requirements
    pub async fn check_compatibility(&self, hardware: &crate::HardwareConfiguration) -> AnyhowResult<CompatibilityResult> {
        info!("Checking hardware compatibility for {:?}", hardware.platform);

        let compatibility = self.compatibility_checker.check_cibos_compatibility(hardware).await
            .context("Compatibility check failed")?;

        if compatibility.compatible {
            info!("Hardware compatibility verified");
        } else {
            warn!("Hardware compatibility issues found: {}", compatibility.reason);
        }

        Ok(compatibility)
    }

    /// Detect security capabilities available on hardware
    async fn detect_security_capabilities(&self, processor: &ProcessorInformation) -> AnyhowResult<SecurityCapabilities> {
        info!("Detecting security capabilities");

        // Detect hardware virtualization support
        let hardware_virtualization = self.detect_virtualization_support(processor).await?;

        // Detect hardware encryption capabilities
        let hardware_encryption = self.detect_encryption_acceleration(processor).await?;

        // Detect TPM presence
        let trusted_platform_module = self.detect_tpm_presence().await?;

        // Detect secure boot support
        let secure_boot_support = self.detect_secure_boot_support().await?;

        // Detect memory encryption support
        let memory_encryption = self.detect_memory_encryption(processor).await?;

        Ok(SecurityCapabilities {
            hardware_virtualization,
            hardware_encryption,
            trusted_platform_module,
            secure_boot_support,
            memory_encryption,
        })
    }

    async fn detect_virtualization_support(&self, processor: &ProcessorInformation) -> AnyhowResult<bool> {
        // Check for Intel VT-x, AMD-V, ARM Virtualization Extensions, etc.
        let virt_support = match processor.vendor.as_str() {
            "Intel" => processor.instruction_sets.contains(&"vmx".to_string()),
            "AMD" => processor.instruction_sets.contains(&"svm".to_string()),
            "ARM" => processor.instruction_sets.contains(&"virt".to_string()),
            _ => false,
        };

        info!("Virtualization support detected: {}", virt_support);
        Ok(virt_support)
    }

    async fn detect_encryption_acceleration(&self, processor: &ProcessorInformation) -> AnyhowResult<bool> {
        // Check for AES-NI, SHA extensions, ARM Crypto extensions, etc.
        let crypto_accel = processor.instruction_sets.iter().any(|inst| {
            inst.contains("aes") || inst.contains("sha") || inst.contains("crypto")
        });

        info!("Hardware encryption acceleration detected: {}", crypto_accel);
        Ok(crypto_accel)
    }

    async fn detect_tpm_presence(&self) -> AnyhowResult<bool> {
        // Check for TPM 2.0 presence
        // This would involve checking /sys/class/tpm or similar
        info!("TPM presence detection");
        Ok(false) // Placeholder
    }

    async fn detect_secure_boot_support(&self) -> AnyhowResult<bool> {
        // Check for UEFI Secure Boot capability
        info!("Secure boot support detection");
        Ok(false) // Placeholder
    }

    async fn detect_memory_encryption(&self, processor: &ProcessorInformation) -> AnyhowResult<bool> {
        // Check for Intel TME, AMD SME/SEV, ARM Pointer Authentication, etc.
        let mem_encryption = processor.instruction_sets.iter().any(|inst| {
            inst.contains("tme") || inst.contains("sme") || inst.contains("sev")
        });

        info!("Memory encryption support detected: {}", mem_encryption);
        Ok(mem_encryption)
    }
}
