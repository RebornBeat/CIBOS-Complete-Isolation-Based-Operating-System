// CONFIG MODULE - cibos/applications/cli/installer/src/config/mod.rs
pub mod config {
    //! Configuration management for CLI installer operations
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::fs;
    use std::path::{Path, PathBuf};

    // Configuration component exports
    pub use self::manager::{ConfigurationManager, ConfigurationLoader, ConfigurationSaver};
    pub use self::validator::{ConfigurationValidator, ValidationRules, ValidationResult};
    pub use self::types::{InstallationConfig, DeploymentConfig, PlatformConfig};

    // Configuration module declarations
    pub mod manager;
    pub mod validator;
    pub mod types;

    /// Configuration manager for installer settings and parameters
    #[derive(Debug)]
    pub struct ConfigurationManager {
        pub loader: ConfigurationLoader,
        pub validator: ConfigurationValidator,
        pub saver: ConfigurationSaver,
    }

    impl ConfigurationManager {
        pub async fn load_from_file(path: &Path) -> AnyhowResult<super::CLIInstallerConfiguration> {
            info!("Loading configuration from file: {:?}", path);
            
            let config_data = fs::read_to_string(path).await
                .context("Failed to read configuration file")?;
            
            let config: super::CLIInstallerConfiguration = toml::from_str(&config_data)
                .context("Failed to parse configuration file")?;
            
            info!("Configuration loaded successfully from file");
            Ok(config)
        }

        pub async fn validate_configuration(
            &self, 
            config: &super::CLIInstallerConfiguration
        ) -> AnyhowResult<()> {
            // Validate configuration parameters
            self.validator.validate_installation_config(&config.installation_config)?;
            self.validator.validate_verification_config(&config.verification_config)?;
            self.validator.validate_hardware_config(&config.hardware_config)?;
            self.validator.validate_backup_config(&config.backup_config)?;
            
            info!("Configuration validation completed successfully");
            Ok(())
        }
    }
}


