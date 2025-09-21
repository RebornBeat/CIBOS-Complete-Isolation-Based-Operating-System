// =============================================================================
// CLI PLATFORM CONFIGURATION MODULE - cibos/platform-cli/src/config/mod.rs
// Platform Configuration Management
// =============================================================================

//! CLI Platform Configuration Management
//! 
//! This module manages configuration for all CLI platform components including
//! shell settings, service configurations, tool permissions, and security
//! policies. Configuration maintains isolation requirements while enabling
//! flexible platform customization.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::collections::HashMap;
use std::time::Duration;

// Shared type imports for configuration validation
use shared::types::isolation::{IsolationLevel, IsolationConfiguration};
use shared::types::authentication::{AuthenticationMethod, CLIAuthenticationMethod};
use shared::types::profiles::{CLIProfile, CLIProfileConfiguration};
use shared::types::error::{ConfigurationError, ValidationError};

// Configuration component exports
pub use self::platform::{CLIPlatformConfiguration, PlatformSettings, PlatformDefaults};
pub use self::shell::{ShellConfiguration, ShellSettings, PromptConfiguration};
pub use self::services::{ServiceConfiguration, SSHConfiguration, FileServerConfiguration};
pub use self::tools::{ToolConfiguration, ToolPermissions, ToolRegistry};
pub use self::commands::{CommandConfiguration, CommandPermissions, CommandDefaults};

// Configuration module declarations
pub mod platform;
pub mod shell;
pub mod services;
pub mod tools;
pub mod commands;

/// Main CLI platform configuration encompassing all subsystems
/// 
/// This configuration structure defines behavior for shell interaction,
/// background services, system tools, and security policies while
/// maintaining strict isolation boundary requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLIPlatformConfiguration {
    /// Overall platform settings and behavior
    pub platform_settings: PlatformSettings,
    
    /// Shell configuration and user interface
    pub shell_config: ShellConfiguration,
    
    /// Background service configuration
    pub service_config: ServiceConfiguration,
    
    /// System tool configuration and permissions
    pub tool_config: ToolConfiguration,
    
    /// Command configuration and routing
    pub command_config: CommandConfiguration,
    
    /// Authentication configuration for CLI access
    pub auth_config: CLIAuthenticationConfiguration,
    
    /// Isolation configuration for platform components
    pub isolation_config: CLIIsolationConfiguration,
}

/// Authentication configuration for CLI platform access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLIAuthenticationConfiguration {
    /// Required authentication method for CLI access
    pub authentication_method: CLIAuthenticationMethod,
    
    /// USB key device requirements
    pub usb_key_required: bool,
    
    /// Authentication timeout duration
    pub auth_timeout: Duration,
    
    /// Session timeout for idle users
    pub session_timeout: Duration,
    
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
}

/// Isolation configuration for CLI platform components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLIIsolationConfiguration {
    /// Base isolation level for all CLI components
    pub base_isolation_level: IsolationLevel,
    
    /// Shell isolation configuration
    pub shell_isolation: ShellIsolationConfig,
    
    /// Service isolation configuration
    pub service_isolation: ServiceIsolationConfig,
    
    /// Tool isolation configuration
    pub tool_isolation: ToolIsolationConfig,
    
    /// Command isolation configuration
    pub command_isolation: CommandIsolationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellIsolationConfig {
    pub enforce_working_directory_isolation: bool,
    pub environment_variable_isolation: bool,
    pub process_isolation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIsolationConfig {
    pub require_service_isolation: bool,
    pub network_isolation_per_service: bool,
    pub storage_isolation_per_service: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIsolationConfig {
    pub require_tool_isolation: bool,
    pub temporary_isolation_boundaries: bool,
    pub tool_permission_validation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandIsolationConfig {
    pub builtin_command_isolation: bool,
    pub system_command_isolation: bool,
    pub application_command_isolation: bool,
}

impl CLIPlatformConfiguration {
    /// Load default CLI platform configuration
    /// 
    /// Creates a secure default configuration suitable for server and
    /// embedded system deployment with maximum isolation enforcement
    /// and conservative security settings.
    pub async fn load_default() -> AnyhowResult<Self> {
        info!("Loading default CLI platform configuration");

        let config = Self {
            platform_settings: PlatformSettings::secure_defaults(),
            shell_config: ShellConfiguration::secure_defaults(),
            service_config: ServiceConfiguration::secure_defaults(),
            tool_config: ToolConfiguration::secure_defaults(),
            command_config: CommandConfiguration::secure_defaults(),
            auth_config: CLIAuthenticationConfiguration::secure_defaults(),
            isolation_config: CLIIsolationConfiguration::maximum_isolation(),
        };

        // Validate configuration consistency
        config.validate().await
            .context("Default configuration validation failed")?;

        info!("Default CLI platform configuration loaded successfully");
        Ok(config)
    }

    /// Validate configuration consistency and security requirements
    /// 
    /// Ensures all configuration components are compatible with each
    /// other and meet minimum security requirements for isolated
    /// platform operation.
    pub async fn validate(&self) -> AnyhowResult<()> {
        info!("Validating CLI platform configuration");

        // Validate authentication configuration
        self.validate_authentication_config()
            .context("Authentication configuration validation failed")?;

        // Validate isolation configuration
        self.validate_isolation_config()
            .context("Isolation configuration validation failed")?;

        // Validate service configuration
        self.validate_service_config()
            .context("Service configuration validation failed")?;

        // Validate tool configuration
        self.validate_tool_config()
            .context("Tool configuration validation failed")?;

        // Validate shell configuration
        self.validate_shell_config()
            .context("Shell configuration validation failed")?;

        info!("CLI platform configuration validation completed successfully");
        Ok(())
    }

    /// Validate authentication configuration requirements
    fn validate_authentication_config(&self) -> AnyhowResult<()> {
        // Ensure authentication method is specified
        match self.auth_config.authentication_method {
            CLIAuthenticationMethod::USBKey => {
                if !self.auth_config.usb_key_required {
                    return Err(anyhow::anyhow!("USB key authentication requires usb_key_required = true"));
                }
            }
            CLIAuthenticationMethod::Password => {
                // Password authentication configuration validation would go here
            }
        }

        // Validate timeout values
        if self.auth_config.auth_timeout.as_secs() < 10 {
            return Err(anyhow::anyhow!("Authentication timeout must be at least 10 seconds"));
        }

        if self.auth_config.session_timeout.as_secs() < 300 {
            return Err(anyhow::anyhow!("Session timeout must be at least 5 minutes"));
        }

        Ok(())
    }

    /// Validate isolation configuration requirements
    fn validate_isolation_config(&self) -> AnyhowResult<()> {
        // Ensure base isolation level is Complete (only supported level)
        if self.isolation_config.base_isolation_level != IsolationLevel::Complete {
            return Err(anyhow::anyhow!("Base isolation level must be Complete"));
        }

        // Validate service isolation requirements
        if !self.isolation_config.service_isolation.require_service_isolation {
            return Err(anyhow::anyhow!("Service isolation is mandatory for security"));
        }

        // Validate tool isolation requirements
        if !self.isolation_config.tool_isolation.require_tool_isolation {
            return Err(anyhow::anyhow!("Tool isolation is mandatory for security"));
        }

        Ok(())
    }

    /// Validate service configuration
    fn validate_service_config(&self) -> AnyhowResult<()> {
        // SSH service validation
        if self.service_config.ssh_enabled {
            if self.service_config.ssh_config.port < 1024 && self.service_config.ssh_config.port != 22 {
                return Err(anyhow::anyhow!("SSH port must be 22 or above 1024"));
            }
        }

        // File server validation
        if self.service_config.file_server_enabled {
            if self.service_config.file_server_config.port < 1024 {
                return Err(anyhow::anyhow!("File server port must be above 1024"));
            }
        }

        Ok(())
    }

    /// Validate tool configuration
    fn validate_tool_config(&self) -> AnyhowResult<()> {
        // Ensure diagnostic tools are always available
        if !self.tool_config.diagnostics_enabled {
            return Err(anyhow::anyhow!("Diagnostic tools must be enabled for system maintenance"));
        }

        Ok(())
    }

    /// Validate shell configuration
    fn validate_shell_config(&self) -> AnyhowResult<()> {
        // Validate history settings
        if self.shell_config.history_size == 0 {
            return Err(anyhow::anyhow!("Shell history size must be greater than 0"));
        }

        // Validate timeout settings
        if self.shell_config.command_timeout.as_secs() == 0 {
            return Err(anyhow::anyhow!("Command timeout must be greater than 0"));
        }

        Ok(())
    }
}

impl CLIAuthenticationConfiguration {
    /// Create secure default authentication configuration
    fn secure_defaults() -> Self {
        Self {
            authentication_method: CLIAuthenticationMethod::USBKey,
            usb_key_required: true,
            auth_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600), // 1 hour
            max_concurrent_sessions: 5,
        }
    }
}

impl CLIIsolationConfiguration {
    /// Create maximum isolation configuration
    fn maximum_isolation() -> Self {
        Self {
            base_isolation_level: IsolationLevel::Complete,
            shell_isolation: ShellIsolationConfig {
                enforce_working_directory_isolation: true,
                environment_variable_isolation: true,
                process_isolation_required: true,
            },
            service_isolation: ServiceIsolationConfig {
                require_service_isolation: true,
                network_isolation_per_service: true,
                storage_isolation_per_service: true,
            },
            tool_isolation: ToolIsolationConfig {
                require_tool_isolation: true,
                temporary_isolation_boundaries: true,
                tool_permission_validation: true,
            },
            command_isolation: CommandIsolationConfig {
                builtin_command_isolation: true,
                system_command_isolation: true,
                application_command_isolation: true,
            },
        }
    }
}
