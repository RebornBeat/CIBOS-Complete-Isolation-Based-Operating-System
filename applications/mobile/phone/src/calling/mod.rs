// Mobile Phone Application Module Organization - cibos/applications/mobile/phone/src/calling/mod.rs
pub mod phone_calling {
    //! Voice calling functionality for mobile phone application
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    use std::sync::Arc;
    use std::collections::HashMap;
    
    // Calling component exports
    pub use self::manager::{CallManager, CallConfiguration, CallError};
    pub use self::engine::{VoiceCallEngine, CallAudio, AudioConfiguration};
    pub use self::history::{CallHistory, CallRecord, HistoryManager};
    pub use self::isolation::{CallIsolation, CallBoundary, CallPermissions};
    
    // Calling module declarations
    pub mod manager;
    pub mod engine;
    pub mod history;
    pub mod isolation;
    
    /// Main call manager coordinating voice communication
    #[derive(Debug)]
    pub struct CallManager {
        pub active_calls: HashMap<Uuid, ActiveCall>,
        pub call_history: CallHistory,
        pub voice_engine: VoiceCallEngine,
        pub isolation: CallIsolation,
    }
    
    /// Active call information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ActiveCall {
        pub call_id: Uuid,
        pub phone_number: String,
        pub call_state: CallState,
        pub start_time: DateTime<Utc>,
        pub isolation_boundary: Uuid,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum CallState {
        Dialing,
        Ringing,
        Connected,
        OnHold,
        Ending,
    }
}
