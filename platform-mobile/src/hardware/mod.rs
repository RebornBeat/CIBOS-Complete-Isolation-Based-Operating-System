// Mobile Hardware Module Organization - cibos/platform-mobile/src/hardware/mod.rs
pub mod mobile_hardware {
    //! Mobile hardware abstraction and management
    //! 
    //! This module provides hardware abstraction for mobile-specific components
    //! including display, battery, sensors, modem, and charging systems. The
    //! platform manages hardware access for applications through controlled APIs.
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use async_trait::async_trait;
    use uuid::Uuid;
    use std::sync::Arc;
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};
    
    // Hardware component exports
    pub use self::display::{DisplayManager, DisplayConfiguration, ScreenProperties};
    pub use self::battery::{BatteryMonitor, BatteryConfiguration, BatteryMetrics};
    pub use self::sensors::{SensorInterface, SensorConfiguration, SensorReading};
    pub use self::modem::{ModemInterface, ModemConfiguration, ModemStatus};
    pub use self::charging::{ChargingManager, ChargingConfiguration, ChargingStatus};
    
    // Module declarations for hardware components
    pub mod display;
    pub mod battery;
    pub mod sensors;
    pub mod modem;
    pub mod charging;
    
    /// Display management for mobile platform
    #[derive(Debug)]
    pub struct DisplayManager {
        pub screen_properties: ScreenProperties,
        pub brightness_controller: BrightnessController,
        pub orientation_manager: OrientationManager,
    }
    
    #[derive(Debug, Clone)]
    pub struct ScreenProperties {
        pub width: u32,
        pub height: u32,
        pub pixel_density: f32,
        pub color_depth: u8,
        pub refresh_rate: u32,
    }
    
    #[derive(Debug)]
    pub struct BrightnessController {
        pub current_brightness: f32,
        pub auto_brightness_enabled: bool,
        pub ambient_light_sensor: Option<AmbientLightSensor>,
    }
    
    #[derive(Debug)]
    pub struct OrientationManager {
        pub current_orientation: ScreenOrientation,
        pub auto_rotation_enabled: bool,
        pub supported_orientations: Vec<ScreenOrientation>,
    }
    
    #[derive(Debug, Clone)]
    pub enum ScreenOrientation {
        Portrait,
        PortraitUpsideDown,
        LandscapeLeft,
        LandscapeRight,
    }
    
    #[derive(Debug)]
    pub struct AmbientLightSensor {
        pub current_reading: f32,
        pub calibration_data: Vec<CalibrationPoint>,
    }
    
    #[derive(Debug, Clone)]
    pub struct CalibrationPoint {
        pub ambient_light: f32,
        pub screen_brightness: f32,
    }
}
