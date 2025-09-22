// =============================================================================
// CIBOS DESKTOP INSTALLER APPLICATION - cibos/applications/desktop/installer/src/main.rs
// Installer Application Executable Entry Point
// =============================================================================

//! CIBOS Desktop Installer Application Entry Point
//! 
//! This executable provides both GUI and CLI modes for installing
//! CIBIOS firmware and CIBOS operating system with complete verification
//! and hardware compatibility checking.

// External runtime dependencies
use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder as LogBuilder;
use tokio::runtime::Runtime as TokioRuntime;
use clap::{Arg, Command, ArgMatches};
use std::env;

// CIBOS installer library imports
use cibos_installer::{InstallerApplication, InstallationWizard, FirmwareFlasher};
use cibos_installer::{InstallationConfiguration, HardwareConfiguration, InstallationResult};

// Shared imports for installer functionality
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};
use shared::types::error::{InstallerError, ApplicationError, FlashingError};

/// Entry point for CIBOS installer application
#[tokio::main]
async fn main() -> AnyhowResult<()> {
    // Initialize logging for installer application
    LogBuilder::from_default_env()
        .filter_level(LevelFilter::Info)
        .init();

    info!("CIBOS Installer Application {} starting", env!("CARGO_PKG_VERSION"));

    // Parse installer command line arguments
    let cli_args = parse_installer_arguments();

    // Initialize installer application
    let mut installer = InstallerApplication::initialize().await
        .context("Installer application initialization failed")?;

    // Determine execution mode based on arguments
    if cli_args.get_flag("gui") {
        run_gui_installer(&mut installer, cli_args).await
    } else {
        run_cli_installer(&mut installer, cli_args).await
    }
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
        .arg(
            Arg::new("platform")
                .long("platform")
                .value_name("PLATFORM")
                .help("Target platform (desktop, mobile, server)")
        )
        .get_matches()
}

/// Run graphical installer interface
async fn run_gui_installer(installer: &mut InstallerApplication, args: ArgMatches) -> AnyhowResult<()> {
    info!("Starting graphical installer interface");

    // Run installation process with GUI
    let installation_result = installer.run_installation().await
        .context("GUI installation process failed")?;

    if installation_result.firmware_installed && installation_result.os_installed {
        info!("GUI installation completed successfully");
    } else {
        return Err(anyhow::anyhow!("GUI installation failed - check logs for details"));
    }

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
    let platform = args.get_one::<String>("platform")
        .map(|p| parse_platform_string(p))
        .unwrap_or(HardwarePlatform::Desktop);

    // Create installation configuration
    let install_config = InstallationConfiguration {
        target_device: target_device.clone(),
        backup_existing: backup_enabled,
        verify_installation: verification_enabled,
        create_recovery: true,
        target_platform: platform,
    };

    info!("CLI installation configuration: target={}, backup={}, verify={}, platform={:?}", 
          target_device, backup_enabled, verification_enabled, platform);

    // Run CLI installation process
    let result = installer.run_installation().await
        .context("CLI installation process failed")?;

    if result.firmware_installed && result.os_installed {
        info!("CLI installation completed successfully");
    } else {
        return Err(anyhow::anyhow!("CLI installation failed - check logs for details"));
    }

    Ok(())
}

/// Parse platform string to HardwarePlatform enum
fn parse_platform_string(platform_str: &str) -> HardwarePlatform {
    match platform_str.to_lowercase().as_str() {
        "desktop" => HardwarePlatform::Desktop,
        "laptop" => HardwarePlatform::Laptop,
        "mobile" => HardwarePlatform::Mobile,
        "tablet" => HardwarePlatform::Tablet,
        "server" => HardwarePlatform::Server,
        "embedded" => HardwarePlatform::Embedded,
        _ => {
            warn!("Unknown platform '{}', defaulting to Desktop", platform_str);
            HardwarePlatform::Desktop
        }
    }
}

