// CIBOS KERNEL DRIVERS MODULE ORGANIZATION - cibos/kernel/src/drivers/mod.rs
pub mod kernel_drivers {
    //! Isolated device driver framework for CIBOS kernel
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use async_trait::async_trait;
    use uuid::Uuid;
    use std::sync::Arc;
    use std::collections::HashMap;
    
    // Driver framework component exports
    pub use self::storage::{StorageDriverFramework, IsolatedStorageDriver, StorageInterface};
    pub use self::network::{NetworkDriverFramework, IsolatedNetworkDriver, NetworkInterface};
    pub use self::input::{InputDriverFramework, IsolatedInputDriver, InputInterface};
    pub use self::display::{DisplayDriverFramework, IsolatedDisplayDriver, DisplayInterface};
    pub use self::usb::{USBDriverFramework, IsolatedUSBDriver, USBInterface};
    
    // Driver module declarations
    pub mod storage;
    pub mod network;
    pub mod input;
    pub mod display;
    pub mod usb;
    
    /// Main driver manager coordinating isolated device access
    #[derive(Debug)]
    pub struct DriverManager {
        pub storage_drivers: Arc<StorageDriverFramework>,
        pub network_drivers: Arc<NetworkDriverFramework>,
        pub input_drivers: Arc<InputDriverFramework>,
        pub display_drivers: Arc<DisplayDriverFramework>,
        pub usb_drivers: Arc<USBDriverFramework>,
        pub driver_registry: DriverRegistry,
    }
    
    #[derive(Debug)]
    pub struct DriverRegistry {
        pub registered_drivers: HashMap<String, DriverMetadata>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriverMetadata {
        pub driver_name: String,
        pub driver_version: String,
        pub supported_devices: Vec<DeviceId>,
        pub isolation_boundary: Uuid,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeviceId {
        pub vendor_id: u16,
        pub device_id: u16,
        pub class_code: u8,
    }
}
