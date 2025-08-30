// Mobile Platform Module Organization - cibos/platform-mobile/src/touch/mod.rs
pub mod touch {
    //! Touch input management for mobile platform
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use winit::event::{Touch, TouchPhase};
    use std::sync::Arc;
    use std::collections::HashMap;
    use uuid::Uuid;
    
    // Touch management component exports
    pub use self::input::{TouchInputManager, TouchEvent, TouchConfiguration};
    pub use self::gestures::{GestureRecognizer, GestureType, GestureEvent};
    pub use self::isolation::{TouchIsolation, TouchBoundary, TouchPermissions};
    pub use self::calibration::{TouchCalibration, CalibrationData, CalibrationResult};
    
    // Touch module declarations
    pub mod input;
    pub mod gestures;
    pub mod isolation;
    pub mod calibration;
    
    /// Main touch input manager coordinating mobile input
    #[derive(Debug)]
    pub struct TouchInputManager {
        pub gesture_recognizer: GestureRecognizer,
        pub touch_isolation: TouchIsolation,
        pub calibration: TouchCalibration,
    }
    
    /// Touch configuration for mobile devices
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TouchConfiguration {
        pub sensitivity: f32,
        pub multi_touch_enabled: bool,
        pub gesture_recognition: bool,
        pub calibration_required: bool,
    }
}
