// =============================================================================
// SHARED/SRC/TYPES/HARDWARE.RS - Hardware Abstraction Types
// =============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Hardware platform identification for universal compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwarePlatform {
    Desktop,
    Laptop,
    Server,
    Mobile,
    Tablet,
    Embedded,
    SingleBoard,
}

/// Processor architecture for compilation and runtime targeting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorArchitecture {
    X86_64,
    AArch64,
    X86,
    RiscV64,
}

/// Security capabilities available on hardware platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCapabilities {
    pub hardware_virtualization: bool,
    pub hardware_encryption: bool,
    pub trusted_platform_module: bool,
    pub secure_boot_support: bool,
    pub memory_encryption: bool,
}

/// Display capabilities for GUI platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayCapabilities {
    pub resolution_width: u32,
    pub resolution_height: u32,
    pub color_depth: u8,
    pub refresh_rate: u32,
    pub multi_monitor_support: bool,
}

/// Input capabilities for user interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputCapabilities {
    pub keyboard_present: bool,
    pub mouse_present: bool,
    pub touchscreen_present: bool,
    pub touchscreen_multitouch: bool,
    pub usb_ports: Vec<USBPortType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum USBPortType {
    USB_A,
    USB_C,
    MicroUSB,
    Lightning,
}

/// Audio capabilities for multimedia platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioCapabilities {
    pub speakers_present: bool,
    pub microphone_present: bool,
    pub headphone_jack: bool,
    pub bluetooth_audio: bool,
}

/// Network capabilities for connectivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCapabilities {
    pub ethernet_present: bool,
    pub wifi_present: bool,
    pub cellular_present: bool,
    pub bluetooth_present: bool,
}

/// Storage capabilities for data management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapabilities {
    pub internal_storage_size: u64,
    pub external_storage_support: bool,
    pub storage_type: StorageType,
    pub encryption_support: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    HDD,
    SSD,
    EMMC,
    NVME,
    SD_CARD,
}

/// Sensor capabilities for mobile platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorCapabilities {
    pub accelerometer: bool,
    pub gyroscope: bool,
    pub magnetometer: bool,
    pub gps: bool,
    pub ambient_light: bool,
    pub proximity: bool,
}
