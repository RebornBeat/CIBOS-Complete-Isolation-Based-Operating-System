// =============================================================================
// CIBOS CLI PLATFORM - cibos/platform-cli/src/main.rs
// Command Line Platform Executable Entry Point
// =============================================================================

// External runtime dependencies
use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder as LogBuilder;
use tokio::{runtime::Runtime as TokioRuntime, signal};
use clap::{Arg, Command, ArgMatches};
use std::process;

// CIBOS CLI platform library imports
use cibos_platform_cli::{CLIPlatformRuntime, CommandShell, ServiceManager};
use cibos_platform_cli::shell::{ShellEnvironment, CommandExecutor, ShellHistory};
use cibos_platform_cli::services::{CLIService, MonitoringService, PackageManagerService};
use cibos_platform_cli::tools::{CLIInstaller, ConfigurationManager, DiagnosticsTools};

// Kernel integration imports
use cibos_kernel::{KernelRuntime, ProcessManager, IsolationManager};
use cibos_kernel::security::authentication::{AuthenticationSystem, CLIAuthenticator};
use cibos_kernel::security::profiles::{ProfileManager, CLIProfileManager};

// Configuration imports
use shared::types::config::{CLIConfiguration, ServerConfiguration, PlatformConfiguration};
use shared::types::hardware::{CLIHardwareConfiguration, ServerHardwareConfiguration};
use shared::types::authentication::{CLIAuthenticationConfiguration, ServerAuthenticationConfiguration};
use shared::types::profiles::{CLIProfile, ServerProfile};
use shared::types::error::{CLIPlatformError, ServerPlatformError, HardwareError};

// Signal handling
use tokio::signal::unix::{signal, SignalKind};

/// Entry point for CIBOS-CLI platform
#[tokio::main]
async fn main() -> AnyhowResult<()> {
    // Initialize logging for CLI platform
    LogBuilder::from_default_env()
        .filter_level(LevelFilter::Info)
        .init();

    info!("CIBOS-CLI platform {} starting", env!("CARGO_PKG_VERSION"));

    // Parse command line arguments
    let cli_args = parse_command_line_arguments();

    // Initialize kernel communication interface
    let kernel_interface = initialize_kernel_interface().await
        .context("Kernel interface initialization failed")?;

    // Initialize CLI platform runtime
    let cli_platform = CLIPlatformRuntime::initialize(kernel_interface).await
        .context("CLI platform initialization failed")?;

    // Handle specific CLI commands if provided
    if let Some(command) = cli_args.subcommand() {
        return handle_cli_command(&cli_platform, command).await;
    }

    // Enter interactive CLI mode
    run_interactive_cli(&cli_platform).await
        .context("Interactive CLI execution failed")?;

    Ok(())
}

/// Parse command line arguments for CLI platform
fn parse_command_line_arguments() -> ArgMatches {
    Command::new("cibos-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CIBOS Command Line Interface Platform")
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_name("FILE")
                .help("Configuration file path")
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .action(clap::ArgAction::Count)
                .help("Increase logging verbosity")
        )
        .subcommand(
            Command::new("install")
                .about("Install CIBIOS/CIBOS on target system")
                .arg(
                    Arg::new("target")
                        .long("target")
                        .value_name("DEVICE")
                        .required(true)
                        .help("Target device for installation")
                )
        )
        .subcommand(
            Command::new("config")
                .about("Configure system settings")
                .arg(
                    Arg::new("show")
                        .long("show")
                        .action(clap::ArgAction::SetTrue)
                        .help("Display current configuration")
                )
        )
        .subcommand(
            Command::new("diagnostics")
                .about("Run system diagnostics")
                .arg(
                    Arg::new("full")
                        .long("full")
                        .action(clap::ArgAction::SetTrue)
                        .help("Run comprehensive diagnostics")
                )
        )
        .get_matches()
}

/// Initialize kernel communication interface
async fn initialize_kernel_interface() -> AnyhowResult<Arc<KernelRuntime>> {
    info!("Establishing communication with CIBOS kernel");

    // Connect to kernel IPC interface
    let kernel_channel = cibos_kernel::ipc::connect_to_kernel().await
        .context("Failed to connect to kernel")?;

    // Create kernel runtime interface
    let kernel_runtime = Arc::new(KernelRuntime::from_channel(kernel_channel).await
        .context("Kernel runtime interface creation failed")?);

    info!("Kernel communication interface established");
    Ok(kernel_runtime)
}

/// Handle specific CLI commands without interactive mode
async fn handle_cli_command(
    platform: &CLIPlatformRuntime,
    command: (&str, &ArgMatches)
) -> AnyhowResult<()> {
    match command.0 {
        "install" => {
            let target = command.1.get_one::<String>("target").unwrap();
            info!("Running CIBIOS/CIBOS installation on target: {}", target);
            
            let installer = CLIInstaller::new(platform).await?;
            installer.install_to_target(target).await
                .context("Installation failed")?;
            
            info!("Installation completed successfully");
        }

        "config" => {
            if command.1.get_flag("show") {
                let config_manager = ConfigurationManager::new(platform).await?;
                config_manager.display_current_configuration().await?;
            }
        }

        "diagnostics" => {
            let full_diagnostics = command.1.get_flag("full");
            let diagnostics = DiagnosticsTools::new(platform).await?;
            
            if full_diagnostics {
                diagnostics.run_comprehensive_diagnostics().await?;
            } else {
                diagnostics.run_basic_diagnostics().await?;
            }
        }

        _ => {
            return Err(anyhow::anyhow!("Unknown command: {}", command.0));
        }
    }

    Ok(())
}

/// Run interactive CLI mode with command shell
async fn run_interactive_cli(platform: &CLIPlatformRuntime) -> AnyhowResult<()> {
    info!("Starting interactive CLI mode");

    // Authenticate user for CLI session
    let user_session = platform.authenticate_user().await
        .context("CLI user authentication failed")?;

    info!("CLI session established for profile: {}", user_session.profile_id);

    // Initialize command shell for authenticated user
    let shell = CommandShell::new_for_session(&user_session, platform).await
        .context("Command shell initialization failed")?;

    // Enter interactive command loop
    shell.run_interactive_loop().await
        .context("Interactive command loop failed")?;

    info!("CLI session ended");
    Ok(())
}

// =============================================================================
// PUBLIC CLI PLATFORM INTERFACE EXPORTS
// =============================================================================

// CLI platform runtime exports
pub use crate::shell::{CommandShell, ShellEnvironment, CommandExecutor, ShellHistory};
pub use crate::services::{ServiceManager, SSHService, MonitoringService, PackageManagerService};
pub use crate::tools::{CLIInstaller, ConfigurationManager, DiagnosticsTools, BackupTools};
pub use crate::commands::{BuiltinCommands, SystemCommands, CommandParser, CommandResult};
pub use crate::config::{CLIPlatformConfiguration, ShellConfiguration, ServiceConfiguration};

// Shared type re-exports for CLI platform integration
pub use shared::types::hardware::ServerCapabilities;
pub use shared::types::isolation::CLIIsolationLevel;
pub use shared::types::authentication::CLIAuthenticationMethod;
pub use shared::types::profiles::CLIProfile;

/// Module declarations for build system components
pub mod config;
pub mod compilation;
pub mod verification;
pub mod packaging;
pub mod targets;
