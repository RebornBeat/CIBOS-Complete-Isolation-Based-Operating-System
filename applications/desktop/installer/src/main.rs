// =============================================================================
// DESKTOP INSTALLER APPLICATION - cibos/applications/desktop/installer/src/main.rs
// Installer Application Executable Entry Point
// =============================================================================

// External runtime dependencies
use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder as LogBuilder;
use tokio::runtime::Runtime as TokioRuntime;
use clap::{Arg, Command, ArgMatches};
use winit::event_loop::EventLoop;

// CIBOS installer library imports
use cibos_installer::{InstallerApplication, InstallationWizard, FirmwareFlasher};
use cibos_installer::ui::{InstallerWindow, WizardNavigation, ProgressWindow};
use cibos_installer::firmware_flash::{FlashingEngine, HardwareFlasher, VerificationEngine};
use cibos_installer::verification::{SystemVerifier, ComponentVerifier, IntegrityChecker};

// CIBOS platform integration
use cibos_platform_gui::{GUIApplication, WindowManager, ApplicationManager};
use cibos_platform_gui::framework::application::{GUIApplicationRunner, ApplicationConfiguration};

// Kernel communication
use cibos_kernel::core::ipc::{ApplicationChannel, SystemServiceInterface};
use cibos_kernel::security::authorization::{AdminPermissions, SystemModification};

// Hardware integration
use cibios::{HardwareAbstraction, FirmwareConfiguration};

// Configuration imports
use shared::types::config::{InstallerConfiguration, FlashingConfiguration, VerificationConfiguration};
use shared::types::hardware::{TargetHardware, FlashingTarget, VerificationTarget};
use shared::types::authentication::{InstallerCredentials, AdminAuthentication};
use shared::types::error::{InstallerError, ApplicationError, FlashingError};

/// Entry point for CIBOS installer application
fn main() -> AnyhowResult<()> {
    // Initialize logging for installer application
    LogBuilder::from_default_env()
        .filter_level(LevelFilter::Info)
        .init();

    info!("CIBOS Installer Application {} starting", env!("CARGO_PKG_VERSION"));

    // Parse installer command line arguments
    let cli_args = parse_installer_arguments();

    // Create async runtime for installer operation
    let runtime = TokioRuntime::new()
        .context("Failed to create installer async runtime")?;

    // Run installer main logic
    runtime.block_on(installer_async_main(cli_args))
        .context("Installer execution failed")?;

    info!("CIBOS installer completed successfully");
    Ok(())
}

/// Parse installer application command line arguments
fn parse_installer_arguments() -> ArgMatches {
    Command::new("cibos-installer")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CIBIOS/CIBOS Installation Suite")
        .arg(
            Arg::new("target")
                .long("target")
                .short('t')
                .value_name("DEVICE")
                .help("Target device for installation")
        )
        .arg(
            Arg::new("gui")
                .long("gui")
                .action(clap::ArgAction::SetTrue)
                .help("Run graphical installer interface")
        )
        .arg(
            Arg::new("backup")
                .long("backup")
                .action(clap::ArgAction::SetTrue)
                .help("Create backup of existing firmware")
        )
        .arg(
            Arg::new("verify")
                .long("verify")
                .action(clap::ArgAction::SetTrue)
                .help("Verify installation after completion")
        )
        .get_matches()
}

/// Main installer logic coordination
async fn installer_async_main(args: ArgMatches) -> AnyhowResult<()> {
    info!("Starting installer main logic");

    // Connect to CIBOS kernel for system access
    let kernel_channel = connect_to_kernel().await
        .context("Kernel connection for installer failed")?;

    // Initialize installer application
    let mut installer = InstallerApplication::initialize(kernel_channel).await
        .context("Installer application initialization failed")?;

    // Check if GUI mode was requested
    if args.get_flag("gui") {
        run_gui_installer(&mut installer, args).await
    } else {
        run_cli_installer(&mut installer, args).await
    }
}

/// Run graphical installer interface
async fn run_gui_installer(installer: &mut InstallerApplication, args: ArgMatches) -> AnyhowResult<()> {
    info!("Starting graphical installer interface");

    // Create GUI event loop
    let event_loop = EventLoop::new()
        .context("Failed to create installer event loop")?;

    // Run installation process with GUI
    installer.run_installation().await
        .context("GUI installation process failed")?;

    Ok(())
}

/// Run command line installer interface
async fn run_cli_installer(installer: &mut InstallerApplication, args: ArgMatches) -> AnyhowResult<()> {
    info!("Starting command line installer interface");

    // Extract target device from arguments
    let target_device = args.get_one::<String>("target")
        .ok_or_else(|| anyhow::anyhow!("Target device must be specified for CLI installation"))?;

    // Configure installation options
    let backup_enabled = args.get_flag("backup");
    let verification_enabled = args.get_flag("verify");

    // Run CLI installation process
    let install_config = InstallationConfiguration {
        target_device: target_device.clone(),
        backup_existing: backup_enabled,
        verify_installation: verification_enabled,
        create_recovery: true,
    };

    let result = installer.run_cli_installation(&install_config).await
        .context("CLI installation process failed")?;

    if result.firmware_installed && result.os_installed {
        info!("Installation completed successfully");
    } else {
        return Err(anyhow::anyhow!("Installation failed - check logs for details"));
    }

    Ok(())
}

/// Connect to CIBOS kernel for installer system access
async fn connect_to_kernel() -> AnyhowResult<Arc<SystemServiceChannel>> {
    info!("Connecting installer to CIBOS kernel");

    let kernel_channel = cibos_kernel::ipc::connect_application_to_kernel("cibos-installer").await
        .context("Failed to establish kernel connection for installer")?;

    Ok(Arc::new(kernel_channel))
}
