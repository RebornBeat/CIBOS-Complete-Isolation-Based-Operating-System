// =============================================================================
// CIBOS CLI PLATFORM - cibos/platform-cli/src/lib.rs
// Command Line Interface Platform for Servers and Embedded Systems
// =============================================================================

// External CLI platform dependencies
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, sync::{Mutex, RwLock}};
use async_trait::async_trait;
use clap::{Arg, Command, ArgMatches, Parser};
use rustyline::{Editor, Helper, Context as ReadlineContext};
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent},
    terminal::{enable_raw_mode, disable_raw_mode}
};

// CIBOS kernel integration
use cibos_kernel::{KernelRuntime, ProcessManager, IsolationManager};
use cibos_kernel::core::ipc::{SecureChannels, KernelCommunication};
use cibos_kernel::security::profiles::{ProfileManager, UserProfileData};
use cibos_kernel::security::authentication::{AuthenticationSystem, CLIAuthenticator};

// CLI platform specific imports
use crate::shell::{CommandShell, ShellEnvironment, CommandExecutor, ShellHistory};
use crate::services::{
    CLIService, SSHService, FileServerService, MonitoringService, PackageManagerService
};
use crate::tools::{
    CLIInstaller, ConfigurationManager, DiagnosticsTools, BackupTools
};

// Command processing imports
use crate::commands::{
    BuiltinCommands, SystemCommands, ApplicationCommands,
    CommandParser, CommandResult, CommandError
};

// Configuration imports
use crate::config::{
    CLIPlatformConfiguration, ShellConfiguration, ServiceConfiguration
};

// Shared imports
use shared::types::hardware::{CLIHardwareCapabilities, ServerCapabilities, EmbeddedCapabilities};
use shared::types::isolation::{CLIIsolationLevel, CommandIsolation, ServiceBoundary};
use shared::types::authentication::{CLIAuthenticationMethod, ServerCredentials};
use shared::types::profiles::{CLIProfile, CLIProfileConfiguration};
use shared::types::error::{CLIError, ShellError, ServiceError};
use shared::ipc::{CLIChannel, CommandProtocol, ServiceProtocol};

/// Main CLI platform runtime coordinating command interface and services
#[derive(Debug)]
pub struct CLIPlatformRuntime {
    shell: Arc<CommandShell>,
    services: Arc<ServiceManager>,
    authentication: Arc<AuthenticationSystem>,
    isolation: Arc<IsolationManager>,
    config: CLIPlatformConfiguration,
}

/// Command shell providing isolated command execution
#[derive(Debug)]
pub struct CommandShell {
    environment: ShellEnvironment,
    executor: CommandExecutor,
    history: ShellHistory,
    command_parser: CommandParser,
}

/// Service manager coordinating platform services
#[derive(Debug)]
pub struct ServiceManager {
    ssh_service: Option<Arc<SSHService>>,
    file_server: Option<Arc<FileServerService>>,
    monitoring: Arc<MonitoringService>,
    package_manager: Arc<PackageManagerService>,
}

impl CLIPlatformRuntime {
    /// Initialize CLI platform from kernel runtime
    pub async fn initialize(kernel: Arc<KernelRuntime>) -> AnyhowResult<Self> {
        info!("Initializing CIBOS-CLI platform");

        // Load CLI platform configuration
        let config = CLIPlatformConfiguration::load_default().await
            .context("CLI platform configuration loading failed")?;

        // Initialize authentication system for CLI
        let authentication = Arc::new(AuthenticationSystem::new_cli(&config.auth_config).await
            .context("CLI authentication initialization failed")?);

        // Initialize isolation manager for CLI services
        let isolation = Arc::new(IsolationManager::new_cli(&config.isolation_config).await
            .context("CLI isolation manager initialization failed")?);

        // Initialize command shell
        let shell = Arc::new(CommandShell::initialize(&config.shell_config, &isolation).await
            .context("Command shell initialization failed")?);

        // Initialize service manager
        let services = Arc::new(ServiceManager::initialize(&config.service_config, &isolation).await
            .context("Service manager initialization failed")?);

        info!("CIBOS-CLI platform initialization completed");

        Ok(Self {
            shell,
            services,
            authentication,
            isolation,
            config,
        })
    }

    /// Start CLI platform and enter interactive shell
    pub async fn run(&self) -> AnyhowResult<()> {
        info!("Starting CIBOS-CLI interactive shell");

        // Start platform services
        self.services.start_all_services().await
            .context("Failed to start CLI platform services")?;

        // Enter interactive shell loop
        self.shell.run_interactive_loop().await
            .context("Interactive shell execution failed")?;

        Ok(())
    }

    /// Authenticate user and establish CLI session
    pub async fn authenticate_user(&self) -> AnyhowResult<UserSession> {
        info!("Starting CLI user authentication");

        // Detect USB key devices
        let usb_devices = self.authentication.detect_usb_key_devices().await
            .context("USB key device detection failed")?;

        if usb_devices.is_empty() {
            return Err(anyhow::anyhow!("No USB authentication devices detected"));
        }

        // Authenticate with detected USB key
        let auth_result = self.authentication.authenticate_usb_key(&usb_devices[0]).await
            .context("USB key authentication failed")?;

        // Create isolated user session
        let user_session = UserSession::create(auth_result.profile_id, &self.isolation).await
            .context("User session creation failed")?;

        info!("CLI user authentication successful");
        Ok(user_session)
    }
}

#[derive(Debug)]
pub struct UserSession {
    pub session_id: uuid::Uuid,
    pub profile_id: uuid::Uuid,
    pub isolation_boundary: uuid::Uuid,
    pub session_start: chrono::DateTime<chrono::Utc>,
}

impl UserSession {
    async fn create(profile_id: uuid::Uuid, isolation: &IsolationManager) -> AnyhowResult<Self> {
        let session_id = uuid::Uuid::new_v4();
        let isolation_boundary = isolation.create_session_boundary(session_id).await?;

        Ok(Self {
            session_id,
            profile_id,
            isolation_boundary,
            session_start: chrono::Utc::now(),
        })
    }
}

// =============================================================================
// PUBLIC CLI PLATFORM INTERFACE EXPORTS
// =============================================================================

// CLI platform runtime exports
pub use crate::shell::{CommandShell, ShellEnvironment, CommandExecutor};
pub use crate::services::{ServiceManager, MonitoringService, PackageManagerService};
pub use crate::tools::{CLIInstaller, ConfigurationManager, DiagnosticsTools};

// Command system exports
pub use crate::commands::{BuiltinCommands, SystemCommands, CommandParser, CommandResult};

// Configuration exports
pub use crate::config::{CLIPlatformConfiguration, ShellConfiguration, ServiceConfiguration};

// Shared type re-exports for CLI integration
pub use shared::types::hardware::ServerCapabilities;
pub use shared::types::isolation::CLIIsolationLevel;
pub use shared::types::authentication::CLIAuthenticationMethod;
pub use shared::types::profiles::CLIProfile;

/// Module declarations for phone application components
pub mod calling;
pub mod messaging;
pub mod contacts;
pub mod ui;
