// Desktop Installer Module Organization - cibos/applications/desktop/installer/src/ui/mod.rs
pub mod installer_ui {
    //! User interface components for the installer application
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use uuid::Uuid;
    use std::sync::Arc;
    
    // UI component exports
    pub use self::wizard::{InstallationWizard, WizardStep, WizardConfiguration};
    pub use self::progress::{ProgressDisplay, ProgressBar, ProgressConfiguration};
    pub use self::dialogs::{ConfirmationDialog, ErrorDialog, InfoDialog};
    pub use self::interface::{InstallerInterface, UIEvent, UIConfiguration};
    
    // UI module declarations
    pub mod wizard;
    pub mod progress;
    pub mod dialogs;
    pub mod interface;
    
    /// Main installer interface coordinating user interaction
    #[derive(Debug)]
    pub struct InstallerInterface {
        pub wizard: InstallationWizard,
        pub progress_display: ProgressDisplay,
        pub dialog_manager: DialogManager,
    }
    
    #[derive(Debug)]
    pub struct DialogManager {
        pub active_dialogs: Vec<DialogHandle>,
    }
    
    #[derive(Debug)]
    pub struct DialogHandle {
        pub dialog_id: Uuid,
        pub dialog_type: DialogType,
    }
    
    #[derive(Debug)]
    pub enum DialogType {
        Confirmation,
        Error,
        Info,
        Progress,
    }
}
