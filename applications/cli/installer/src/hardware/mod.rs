// HARDWARE MODULE - cibos/applications/cli/installer/src/hardware/mod.rs  
pub mod hardware {
    //! Hardware detection and compatibility verification
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use std::collections::HashMap;

    // Hardware component exports
    pub use self::detector::{HardwareDetector, SystemDetector, ComponentDetector};
    pub use self::compatibility::{CompatibilityChecker, PlatformAnalyzer, SupportChecker};
    pub use self::profile::{HardwareProfile, SystemProfile, ComponentProfile};
    pub use self::support::{SupportedPlatforms, PlatformSupport, ArchitectureSupport};

    // Hardware module declarations
    pub mod detector;
    pub mod compatibility;
    pub mod profile;
    pub mod support;

    /// Comprehensive hardware profile for installation targeting
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HardwareProfile {
        pub profile_id: uuid::Uuid,
        pub platform: shared::types::hardware::HardwarePlatform,
        pub architecture: shared::types::hardware::ProcessorArchitecture,
        pub processor: ProcessorInfo,
        pub memory: MemoryInfo,
        pub storage_devices: Vec<StorageDeviceInfo>,
        pub network_interfaces: Vec<NetworkInterfaceInfo>,
        pub capabilities: shared::types::hardware::SecurityCapabilities,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcessorInfo {
        pub manufacturer: String,
        pub model: String,
        pub cores: u32,
        pub threads: u32,
        pub base_frequency: u64,
        pub virtualization_support: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemoryInfo {
        pub total_memory: u64,
        pub available_memory: u64,
        pub memory_type: MemoryType,
        pub ecc_support: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum MemoryType {
        DDR3,
        DDR4,
        DDR5,
        LPDDR4,
        LPDDR5,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StorageDeviceInfo {
        pub device_name: String,
        pub device_type: shared::types::hardware::StorageType,
        pub total_capacity: u64,
        pub available_space: u64,
        pub interface: StorageInterface,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum StorageInterface {
        SATA,
        NVME,
        USB,
        SD,
        EMMC,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkInterfaceInfo {
        pub interface_name: String,
        pub interface_type: NetworkInterfaceType,
        pub mac_address: String,
        pub current_status: NetworkStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum NetworkInterfaceType {
        Ethernet,
        WiFi,
        Cellular,
        Bluetooth,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum NetworkStatus {
        Connected,
        Disconnected,
        Disabled,
    }

    /// Hardware compatibility report for installation validation
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompatibilityReport {
        pub compatible: bool,
        pub compatibility_score: f32,
        pub incompatibility_reason: String,
        pub supported_features: Vec<String>,
        pub unsupported_features: Vec<String>,
        pub recommendations: Vec<String>,
    }
}

