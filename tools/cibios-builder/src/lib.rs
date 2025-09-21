// =============================================================================
// BUILD SYSTEM AND TOOLS - tools/cibios-builder/src/lib.rs
// CIBIOS Firmware Builder for Cross-Platform Compilation
// =============================================================================

//! CIBIOS Firmware Build System
//! 
//! This crate provides cross-platform compilation and packaging capabilities
//! for CIBIOS firmware across all supported architectures. The build system
//! coordinates Rust compilation, assembly compilation, linking, verification,
//! and packaging to produce deployable firmware images.

// External build system dependencies
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{process::Command, fs, time::Duration};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::env;
use chrono::{DateTime, Utc};

// Internal build system imports
use crate::config::{BuildConfiguration, ArchitectureConfig, PlatformConfig, CompilerConfig};
use crate::compilation::{CompilerCoordinator, ArchitectureCompiler, AssemblyCompiler};
use crate::verification::{BuildVerifier, OutputValidator, SignatureGenerator};
use crate::packaging::{FirmwarePackager, ImageBuilder, DeploymentBuilder};
use crate::targets::{
    X86_64BuildTarget, AArch64BuildTarget, X86BuildTarget, RiscV64BuildTarget
};

// Shared imports for build system
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};
use shared::types::error::{BuildError, CompilationError, PackagingError};

/// Main CIBIOS builder coordinating cross-platform firmware compilation
#[derive(Debug)]
pub struct CIBIOSBuilder {
    build_config: BuildConfiguration,
    compiler_coordinator: CompilerCoordinator,
    build_verifier: BuildVerifier,
    firmware_packager: FirmwarePackager,
}

/// Result of firmware build process
#[derive(Debug)]
pub struct FirmwareBuildResult {
    pub success: bool,
    pub firmware_path: PathBuf,
    pub build_metadata: BuildMetadata,
}

/// Build metadata for tracking and verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMetadata {
    pub build_time: DateTime<Utc>,
    pub target_architecture: ProcessorArchitecture,
    pub target_platform: HardwarePlatform,
    pub verification_hash: String,
    pub build_version: String,
}

/// Compilation result for Rust sources
#[derive(Debug)]
pub struct RustCompilationResult {
    pub object_files: Vec<PathBuf>,
    pub compilation_time: Duration,
    pub target_triple: String,
}

/// Compilation result for assembly sources
#[derive(Debug)]
pub struct AssemblyCompilationResult {
    pub object_files: Vec<PathBuf>,
    pub compilation_time: Duration,
    pub architecture: ProcessorArchitecture,
}

/// Linking result for firmware binary
#[derive(Debug)]
pub struct LinkingResult {
    pub firmware_binary: PathBuf,
    pub symbol_table: PathBuf,
    pub linking_time: Duration,
    pub binary_size: u64,
}

impl CIBIOSBuilder {
    /// Initialize CIBIOS builder with target configuration
    pub fn new(build_config: BuildConfiguration) -> AnyhowResult<Self> {
        info!("Initializing CIBIOS builder for {:?} on {:?}", 
              build_config.target_architecture, build_config.target_platform);

        // Initialize compiler coordination
        let compiler_coordinator = CompilerCoordinator::new(&build_config)
            .context("Compiler coordinator initialization failed")?;

        // Initialize build verification
        let build_verifier = BuildVerifier::new(&build_config)
            .context("Build verifier initialization failed")?;

        // Initialize firmware packaging
        let firmware_packager = FirmwarePackager::new(&build_config)
            .context("Firmware packager initialization failed")?;

        Ok(Self {
            build_config,
            compiler_coordinator,
            build_verifier,
            firmware_packager,
        })
    }

    /// Execute complete CIBIOS firmware build process
    pub async fn build_firmware(&self) -> AnyhowResult<FirmwareBuildResult> {
        info!("Starting CIBIOS firmware build process for {:?}", self.build_config.target_architecture);

        // Step 1: Validate build environment
        self.validate_build_environment().await
            .context("Build environment validation failed")?;

        // Step 2: Compile Rust source code
        let rust_compilation = self.compile_rust_sources().await
            .context("Rust source compilation failed")?;

        // Step 3: Compile architecture-specific assembly
        let asm_compilation = self.compile_assembly_sources().await
            .context("Assembly source compilation failed")?;

        // Step 4: Link compiled components
        let linking_result = self.link_firmware_components(&rust_compilation, &asm_compilation).await
            .context("Firmware component linking failed")?;

        // Step 5: Verify build integrity
        let verification_result = self.build_verifier.verify_build_integrity(&linking_result).await
            .context("Build verification failed")?;

        // Step 6: Package firmware for deployment
        let firmware_package = self.firmware_packager.package_firmware(&linking_result).await
            .context("Firmware packaging failed")?;

        info!("CIBIOS firmware build completed successfully");

        Ok(FirmwareBuildResult {
            success: true,
            firmware_path: firmware_package.output_path,
            build_metadata: BuildMetadata {
                build_time: Utc::now(),
                target_architecture: self.build_config.target_architecture,
                target_platform: self.build_config.target_platform,
                verification_hash: verification_result.build_hash,
                build_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
    }

    /// Validate build environment before compilation
    async fn validate_build_environment(&self) -> AnyhowResult<()> {
        info!("Validating build environment");

        // Check required tools are available
        self.check_required_tools().await
            .context("Required build tools check failed")?;

        // Validate source code availability
        self.validate_source_availability().await
            .context("Source code validation failed")?;

        // Check cross-compilation toolchain
        if self.build_config.requires_cross_compilation() {
            self.validate_cross_compilation_toolchain().await
                .context("Cross-compilation toolchain validation failed")?;
        }

        Ok(())
    }

    /// Check that required build tools are available
    async fn check_required_tools(&self) -> AnyhowResult<()> {
        let required_tools = vec!["rustc", "cargo", "ld"];
        
        for tool in required_tools {
            let output = Command::new("which")
                .arg(tool)
                .output()
                .await
                .context(format!("Failed to check for tool: {}", tool))?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Required build tool not found: {}", tool));
            }
        }

        info!("All required build tools are available");
        Ok(())
    }

    /// Validate source code is available for compilation
    async fn validate_source_availability(&self) -> AnyhowResult<()> {
        let cibios_src_path = PathBuf::from("cibios/src");
        if !cibios_src_path.exists() {
            return Err(anyhow::anyhow!("CIBIOS source directory not found: {:?}", cibios_src_path));
        }

        let main_rs_path = cibios_src_path.join("main.rs");
        if !main_rs_path.exists() {
            return Err(anyhow::anyhow!("CIBIOS main.rs not found: {:?}", main_rs_path));
        }

        info!("Source code validation completed");
        Ok(())
    }

    /// Validate cross-compilation toolchain if needed
    async fn validate_cross_compilation_toolchain(&self) -> AnyhowResult<()> {
        let target_triple = self.get_target_triple();
        
        // Check if target is installed
        let output = Command::new("rustup")
            .args(&["target", "list", "--installed"])
            .output()
            .await
            .context("Failed to list installed Rust targets")?;

        let installed_targets = String::from_utf8(output.stdout)
            .context("Failed to parse rustup output")?;

        if !installed_targets.contains(&target_triple) {
            return Err(anyhow::anyhow!("Target {} not installed. Run: rustup target add {}", target_triple, target_triple));
        }

        info!("Cross-compilation toolchain validated for target: {}", target_triple);
        Ok(())
    }

    /// Get Rust target triple for current architecture
    fn get_target_triple(&self) -> String {
        match self.build_config.target_architecture {
            ProcessorArchitecture::X86_64 => "x86_64-unknown-none".to_string(),
            ProcessorArchitecture::AArch64 => "aarch64-unknown-none".to_string(),
            ProcessorArchitecture::X86 => "i686-unknown-none".to_string(),
            ProcessorArchitecture::RiscV64 => "riscv64gc-unknown-none-elf".to_string(),
        }
    }

    /// Compile Rust sources for target architecture
    async fn compile_rust_sources(&self) -> AnyhowResult<RustCompilationResult> {
        info!("Compiling Rust sources for {:?}", self.build_config.target_architecture);
        
        let start_time = std::time::Instant::now();
        let target_triple = self.get_target_triple();

        // Build cargo command for CIBIOS
        let mut cargo_cmd = Command::new("cargo");
        cargo_cmd
            .args(&["build", "--target", &target_triple])
            .arg("--manifest-path")
            .arg("cibios/Cargo.toml");

        // Add optimization flags based on configuration
        match self.build_config.optimization_level {
            crate::config::OptimizationLevel::Debug => {
                // Debug build - no additional flags needed
            }
            crate::config::OptimizationLevel::Release => {
                cargo_cmd.arg("--release");
            }
            crate::config::OptimizationLevel::MinSize => {
                cargo_cmd.args(&["--release"]);
                // Size optimization would be handled in Cargo.toml
            }
        }

        // Execute compilation
        let output = cargo_cmd
            .output()
            .await
            .context("Failed to execute cargo build")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Rust compilation failed: {}", stderr));
        }

        let compilation_time = start_time.elapsed();

        // Find compiled object files
        let target_dir = PathBuf::from("target").join(&target_triple);
        let build_type = match self.build_config.optimization_level {
            crate::config::OptimizationLevel::Debug => "debug",
            _ => "release",
        };
        
        let object_files = self.find_object_files(&target_dir.join(build_type)).await?;

        info!("Rust compilation completed in {:?}", compilation_time);

        Ok(RustCompilationResult {
            object_files,
            compilation_time,
            target_triple,
        })
    }

    /// Compile architecture-specific assembly sources
    async fn compile_assembly_sources(&self) -> AnyhowResult<AssemblyCompilationResult> {
        info!("Compiling assembly sources for {:?}", self.build_config.target_architecture);
        
        self.compiler_coordinator.compile_architecture_assembly().await
    }

    /// Link compiled components into firmware binary
    async fn link_firmware_components(
        &self,
        rust_result: &RustCompilationResult,
        asm_result: &AssemblyCompilationResult
    ) -> AnyhowResult<LinkingResult> {
        info!("Linking firmware components");
        
        self.compiler_coordinator.link_firmware_binary(rust_result, asm_result).await
    }

    /// Find object files in target directory
    async fn find_object_files(&self, target_dir: &Path) -> AnyhowResult<Vec<PathBuf>> {
        let mut object_files = Vec::new();
        
        if target_dir.exists() {
            let mut entries = fs::read_dir(target_dir).await
                .context("Failed to read target directory")?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if extension == "o" || extension == "obj" {
                        object_files.push(path);
                    }
                }
            }
        }

        Ok(object_files)
    }
}

// =============================================================================
// PUBLIC API EXPORTS
// =============================================================================

// Build system component exports
pub use crate::config::{BuildConfiguration, ArchitectureConfig, PlatformConfig, OptimizationLevel};
pub use crate::compilation::{CompilerCoordinator, ArchitectureCompiler, AssemblyCompiler};
pub use crate::verification::{BuildVerifier, OutputValidator, SignatureGenerator};
pub use crate::packaging::{FirmwarePackager, ImageBuilder, DeploymentBuilder};

// Target architecture exports
pub use crate::targets::{
    X86_64BuildTarget, AArch64BuildTarget, X86BuildTarget, RiscV64BuildTarget
};

// Build result exports
pub use self::{
    FirmwareBuildResult, BuildMetadata, RustCompilationResult, 
    AssemblyCompilationResult, LinkingResult
};

// Shared type re-exports
pub use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};
pub use shared::types::error::{BuildError, CompilationError, PackagingError};

/// Module declarations for build system components
pub mod config;
pub mod compilation;
pub mod verification;
pub mod packaging;
pub mod targets;

