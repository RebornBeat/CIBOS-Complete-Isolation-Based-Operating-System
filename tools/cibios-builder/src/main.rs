// =============================================================================
// BUILD SYSTEM MAIN - tools/cibios-builder/src/main.rs
// Command-line interface for CIBIOS firmware building
// =============================================================================

//! CIBIOS Builder Command-Line Interface
//! 
//! This executable provides a command-line interface for building CIBIOS
//! firmware across different architectures and platforms. It handles
//! configuration, compilation coordination, and build result reporting.

// External runtime dependencies
use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder as LogBuilder;
use clap::{Arg, Command, ArgMatches, Parser};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::env;

// CIBIOS builder library imports
use cibios_builder::{
    CIBIOSBuilder, BuildConfiguration, OptimizationLevel,
    FirmwareBuildResult, BuildMetadata
};

// Shared type imports
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};

/// Command-line arguments for CIBIOS builder
#[derive(Parser, Debug)]
#[command(name = "cibios-builder")]
#[command(about = "CIBIOS Firmware Builder - Cross-platform firmware compilation")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct BuilderArgs {
    /// Target processor architecture
    #[arg(long, value_enum)]
    arch: TargetArchitecture,

    /// Target hardware platform
    #[arg(long, value_enum)]
    platform: TargetPlatform,

    /// Optimization level for compilation
    #[arg(long, value_enum, default_value = "release")]
    optimization: OptimizationMode,

    /// Enable debug symbols in build
    #[arg(long)]
    debug_symbols: bool,

    /// Enable build verification
    #[arg(long, default_value = "true")]
    verify: bool,

    /// Output directory for firmware binary
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Verbose logging output
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Clean build artifacts before building
    #[arg(long)]
    clean: bool,
}

/// Command-line architecture options
#[derive(clap::ValueEnum, Clone, Debug)]
enum TargetArchitecture {
    X86_64,
    AArch64,
    X86,
    RiscV64,
}

/// Command-line platform options
#[derive(clap::ValueEnum, Clone, Debug)]
enum TargetPlatform {
    Desktop,
    Laptop,
    Server,
    Mobile,
    Tablet,
    Embedded,
    SingleBoard,
}

/// Command-line optimization options
#[derive(clap::ValueEnum, Clone, Debug)]
enum OptimizationMode {
    Debug,
    Release,
    MinSize,
}

/// Main entry point for CIBIOS builder CLI
#[tokio::main]
async fn main() -> AnyhowResult<()> {
    // Parse command-line arguments
    let args = BuilderArgs::parse();

    // Initialize logging based on verbosity level
    initialize_logging(args.verbose);

    info!("CIBIOS Builder {} starting", env!("CARGO_PKG_VERSION"));
    info!("Building for architecture: {:?}, platform: {:?}", args.arch, args.platform);

    // Convert command-line arguments to build configuration
    let build_config = create_build_configuration(&args)?;

    // Clean build artifacts if requested
    if args.clean {
        clean_build_artifacts().await
            .context("Failed to clean build artifacts")?;
    }

    // Initialize CIBIOS builder
    let builder = CIBIOSBuilder::new(build_config)
        .context("Failed to initialize CIBIOS builder")?;

    // Execute firmware build
    let build_result = builder.build_firmware().await
        .context("Firmware build failed")?;

    // Handle build results
    handle_build_results(&build_result, &args).await
        .context("Failed to handle build results")?;

    info!("CIBIOS firmware build completed successfully");
    Ok(())
}

/// Initialize logging based on verbosity level
fn initialize_logging(verbosity: u8) {
    let log_level = match verbosity {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    LogBuilder::from_default_env()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();
}

/// Convert command-line arguments to build configuration
fn create_build_configuration(args: &BuilderArgs) -> AnyhowResult<BuildConfiguration> {
    let target_architecture = match args.arch {
        TargetArchitecture::X86_64 => ProcessorArchitecture::X86_64,
        TargetArchitecture::AArch64 => ProcessorArchitecture::AArch64,
        TargetArchitecture::X86 => ProcessorArchitecture::X86,
        TargetArchitecture::RiscV64 => ProcessorArchitecture::RiscV64,
    };

    let target_platform = match args.platform {
        TargetPlatform::Desktop => HardwarePlatform::Desktop,
        TargetPlatform::Laptop => HardwarePlatform::Laptop,
        TargetPlatform::Server => HardwarePlatform::Server,
        TargetPlatform::Mobile => HardwarePlatform::Mobile,
        TargetPlatform::Tablet => HardwarePlatform::Tablet,
        TargetPlatform::Embedded => HardwarePlatform::Embedded,
        TargetPlatform::SingleBoard => HardwarePlatform::SingleBoard,
    };

    let optimization_level = match args.optimization {
        OptimizationMode::Debug => OptimizationLevel::Debug,
        OptimizationMode::Release => OptimizationLevel::Release,
        OptimizationMode::MinSize => OptimizationLevel::MinSize,
    };

    Ok(BuildConfiguration {
        target_architecture,
        target_platform,
        optimization_level,
        debug_symbols: args.debug_symbols,
        verification_enabled: args.verify,
    })
}

/// Clean build artifacts from previous builds
async fn clean_build_artifacts() -> AnyhowResult<()> {
    info!("Cleaning build artifacts");

    let target_dir = PathBuf::from("target");
    if target_dir.exists() {
        tokio::fs::remove_dir_all(&target_dir).await
            .context("Failed to remove target directory")?;
        info!("Removed target directory");
    }

    let cibios_target_dir = PathBuf::from("cibios/target");
    if cibios_target_dir.exists() {
        tokio::fs::remove_dir_all(&cibios_target_dir).await
            .context("Failed to remove CIBIOS target directory")?;
        info!("Removed CIBIOS target directory");
    }

    Ok(())
}

/// Handle build results and output firmware
async fn handle_build_results(
    build_result: &FirmwareBuildResult,
    args: &BuilderArgs
) -> AnyhowResult<()> {
    if build_result.success {
        info!("Firmware build successful!");
        info!("Firmware binary: {:?}", build_result.firmware_path);
        
        // Display build metadata
        display_build_metadata(&build_result.build_metadata);

        // Copy firmware to output directory if specified
        if let Some(output_dir) = &args.output {
            copy_firmware_to_output(&build_result.firmware_path, output_dir).await
                .context("Failed to copy firmware to output directory")?;
        }
    } else {
        error!("Firmware build failed!");
        return Err(anyhow::anyhow!("Build process completed with errors"));
    }

    Ok(())
}

/// Display build metadata information
fn display_build_metadata(metadata: &BuildMetadata) {
    info!("Build Metadata:");
    info!("  Build Time: {}", metadata.build_time.format("%Y-%m-%d %H:%M:%S UTC"));
    info!("  Target Architecture: {:?}", metadata.target_architecture);
    info!("  Target Platform: {:?}", metadata.target_platform);
    info!("  Build Version: {}", metadata.build_version);
    info!("  Verification Hash: {}", metadata.verification_hash);
}

/// Copy firmware binary to specified output directory
async fn copy_firmware_to_output(
    firmware_path: &PathBuf,
    output_dir: &PathBuf
) -> AnyhowResult<()> {
    // Create output directory if it doesn't exist
    tokio::fs::create_dir_all(output_dir).await
        .context("Failed to create output directory")?;

    // Generate output filename
    let firmware_filename = firmware_path.file_name()
        .context("Failed to get firmware filename")?;
    let output_path = output_dir.join(firmware_filename);

    // Copy firmware binary
    tokio::fs::copy(firmware_path, &output_path).await
        .context("Failed to copy firmware binary")?;

    info!("Firmware copied to: {:?}", output_path);
    Ok(())
}

