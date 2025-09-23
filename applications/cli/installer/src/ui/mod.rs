// UI MODULE - cibos/applications/cli/installer/src/ui/mod.rs
pub mod ui {
    //! Command-line user interface for installer operations
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::io::{AsyncWriteExt, stdout};
    use std::sync::Arc;

    // UI component exports  
    pub use self::interface::{CLIInterface, UserInterface, InteractiveInterface};
    pub use self::display::{InstallationDisplay, ProgressDisplay, StatusDisplay};
    pub use self::progress::{ProgressIndicator, ProgressBar, ProgressTracker};
    pub use self::prompts::{InteractivePrompts, UserPrompts, ConfirmationPrompts};

    // UI module declarations
    pub mod interface;
    pub mod display;
    pub mod progress;
    pub mod prompts;

    /// Main CLI interface coordinating user interaction
    #[derive(Debug)]
    pub struct CLIInterface {
        pub display: InstallationDisplay,
        pub progress: ProgressIndicator,
        pub prompts: InteractivePrompts,
        pub config: CLIUIConfiguration,
    }

    /// CLI UI configuration for interface behavior
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CLIUIConfiguration {
        pub verbose_output: bool,
        pub show_progress_bars: bool,
        pub interactive_prompts: bool,
        pub log_to_file: bool,
        pub colored_output: bool,
    }

    /// Progress tracker for installation operations
    #[derive(Debug)]
    pub struct ProgressTracker {
        pub operation_name: String,
        pub total_steps: u32,
        pub completed_steps: u32,
        pub start_time: chrono::DateTime<chrono::Utc>,
    }

    impl CLIInterface {
        pub async fn display_installation_header(&self, config: &super::CLIInstallerConfiguration) -> AnyhowResult<()> {
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║                 CIBOS CLI Installer v{}                 ║", env!("CARGO_PKG_VERSION"));
            println!("║          Complete Isolation System Deployment               ║");
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            if config.ui_config.verbose_output {
                println!("Configuration Summary:");
                println!("  Target Platform: {:?}", config.installation_config.target_platform);
                println!("  Verification Enabled: {}", config.verification_config.verify_signatures);
                println!("  Backup Enabled: {}", config.backup_config.create_backup);
                println!();
            }

            Ok(())
        }

        pub async fn display_hardware_profile(&self, profile: &super::hardware::HardwareProfile) -> AnyhowResult<()> {
            println!("Hardware Detection Results:");
            println!("  Platform: {:?}", profile.platform);
            println!("  Architecture: {:?}", profile.architecture);
            println!("  Processor: {} - {} cores", profile.processor.model, profile.processor.cores);
            println!("  Memory: {:.2} GB", profile.memory.total_memory as f64 / (1024.0 * 1024.0 * 1024.0));
            println!("  Storage Devices: {}", profile.storage_devices.len());
            println!();
            Ok(())
        }

        pub async fn display_installation_summary(&self, result: &super::InstallationResult) -> AnyhowResult<()> {
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║                    Installation Summary                      ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            
            println!("Installation ID: {}", result.installation_id);
            println!("Completion Time: {}", result.installation_timestamp);
            
            let status = if result.firmware_installed && result.os_installed && result.verification_passed {
                "✓ SUCCESS"
            } else {
                "✗ FAILED"
            };
            println!("Status: {}", status);
            println!();

            Ok(())
        }

        pub async fn create_progress_tracker(&self, operation_name: &str) -> AnyhowResult<Arc<ProgressTracker>> {
            Ok(Arc::new(ProgressTracker {
                operation_name: operation_name.to_string(),
                total_steps: 100, // Will be updated during operation
                completed_steps: 0,
                start_time: chrono::Utc::now(),
            }))
        }
    }
}

