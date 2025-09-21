// =============================================================================
// BUILD CONFIGURATION MODULE - tools/cibios-builder/src/config/mod.rs
// =============================================================================

//! Build configuration management for CIBIOS firmware compilation
//! 
//! This module provides configuration structures and management for
//! controlling the firmware build process across different architectures
//! and platforms.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// Shared type imports
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};

/// Build configuration for CIBIOS firmware compilation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfiguration {
    pub target_architecture: ProcessorArchitecture,
    pub target_platform: HardwarePlatform,
    pub optimization_level: OptimizationLevel,
    pub debug_symbols: bool,
    pub verification_enabled: bool,
}

/// Optimization levels for firmware compilation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OptimizationLevel {
    /// No optimization, full debug information
    Debug,
    /// Full optimization, minimal debug information
    Release,
    /// Size optimization for embedded systems
    MinSize,
}

/// Architecture-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureConfig {
    pub target_triple: String,
    pub linker_script: PathBuf,
    pub assembly_files: Vec<PathBuf>,
    pub compiler_flags: Vec<String>,
    pub linker_flags: Vec<String>,
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    pub memory_layout: MemoryLayoutConfig,
    pub feature_flags: Vec<String>,
    pub platform_specific_code: Vec<PathBuf>,
}

/// Memory layout configuration for target platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLayoutConfig {
    pub ram_start: u64,
    pub ram_size: u64,
    pub flash_start: u64,
    pub flash_size: u64,
}

/// Compiler configuration for different toolchains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerConfig {
    pub rust_compiler: RustCompilerConfig,
    pub assembly_compiler: AssemblyCompilerConfig,
    pub linker: LinkerConfig,
}

/// Rust compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustCompilerConfig {
    pub target_triple: String,
    pub optimization_flags: Vec<String>,
    pub feature_flags: Vec<String>,
    pub custom_flags: Vec<String>,
}

/// Assembly compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyCompilerConfig {
    pub assembler_command: String,
    pub assembler_flags: Vec<String>,
    pub architecture_flags: Vec<String>,
}

/// Linker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerConfig {
    pub linker_command: String,
    pub linker_script: PathBuf,
    pub linker_flags: Vec<String>,
    pub library_paths: Vec<PathBuf>,
}

impl BuildConfiguration {
    /// Create default configuration for specified architecture and platform
    pub fn new(
        architecture: ProcessorArchitecture,
        platform: HardwarePlatform
    ) -> Self {
        Self {
            target_architecture: architecture,
            target_platform: platform,
            optimization_level: OptimizationLevel::Release,
            debug_symbols: false,
            verification_enabled: true,
        }
    }

    /// Check if cross-compilation is required
    pub fn requires_cross_compilation(&self) -> bool {
        let host_arch = env!("TARGET_ARCH");
        let target_arch = match self.target_architecture {
            ProcessorArchitecture::X86_64 => "x86_64",
            ProcessorArchitecture::AArch64 => "aarch64",
            ProcessorArchitecture::X86 => "x86",
            ProcessorArchitecture::RiscV64 => "riscv64",
        };
        
        host_arch != target_arch
    }

    /// Get target triple for Rust compilation
    pub fn get_target_triple(&self) -> String {
        match self.target_architecture {
            ProcessorArchitecture::X86_64 => "x86_64-unknown-none".to_string(),
            ProcessorArchitecture::AArch64 => "aarch64-unknown-none".to_string(),
            ProcessorArchitecture::X86 => "i686-unknown-none".to_string(),
            ProcessorArchitecture::RiscV64 => "riscv64gc-unknown-none-elf".to_string(),
        }
    }

    /// Get architecture-specific configuration
    pub fn get_architecture_config(&self) -> ArchitectureConfig {
        match self.target_architecture {
            ProcessorArchitecture::X86_64 => self.get_x86_64_config(),
            ProcessorArchitecture::AArch64 => self.get_aarch64_config(),
            ProcessorArchitecture::X86 => self.get_x86_config(),
            ProcessorArchitecture::RiscV64 => self.get_riscv64_config(),
        }
    }

    fn get_x86_64_config(&self) -> ArchitectureConfig {
        ArchitectureConfig {
            target_triple: "x86_64-unknown-none".to_string(),
            linker_script: PathBuf::from("cibios/src/arch/x86_64/linker.ld"),
            assembly_files: vec![
                PathBuf::from("cibios/src/arch/x86_64/asm/boot.s"),
                PathBuf::from("cibios/src/arch/x86_64/asm/vt_x.s"),
                PathBuf::from("cibios/src/arch/x86_64/asm/memory.s"),
                PathBuf::from("cibios/src/arch/x86_64/asm/transfer.s"),
            ],
            compiler_flags: vec!["-m64".to_string(), "-march=x86-64".to_string()],
            linker_flags: vec!["-m64".to_string()],
        }
    }

    fn get_aarch64_config(&self) -> ArchitectureConfig {
        ArchitectureConfig {
            target_triple: "aarch64-unknown-none".to_string(),
            linker_script: PathBuf::from("cibios/src/arch/aarch64/linker.ld"),
            assembly_files: vec![
                PathBuf::from("cibios/src/arch/aarch64/asm/boot.s"),
                PathBuf::from("cibios/src/arch/aarch64/asm/trustzone.s"),
                PathBuf::from("cibios/src/arch/aarch64/asm/memory.s"),
                PathBuf::from("cibios/src/arch/aarch64/asm/power.s"),
                PathBuf::from("cibios/src/arch/aarch64/asm/transfer.s"),
            ],
            compiler_flags: vec!["-march=armv8-a".to_string()],
            linker_flags: vec![],
        }
    }

    fn get_x86_config(&self) -> ArchitectureConfig {
        ArchitectureConfig {
            target_triple: "i686-unknown-none".to_string(),
            linker_script: PathBuf::from("cibios/src/arch/x86/linker.ld"),
            assembly_files: vec![
                PathBuf::from("cibios/src/arch/x86/asm/boot.s"),
                PathBuf::from("cibios/src/arch/x86/asm/memory.s"),
                PathBuf::from("cibios/src/arch/x86/asm/transfer.s"),
            ],
            compiler_flags: vec!["-m32".to_string(), "-march=i686".to_string()],
            linker_flags: vec!["-m32".to_string()],
        }
    }

    fn get_riscv64_config(&self) -> ArchitectureConfig {
        ArchitectureConfig {
            target_triple: "riscv64gc-unknown-none-elf".to_string(),
            linker_script: PathBuf::from("cibios/src/arch/riscv64/linker.ld"),
            assembly_files: vec![
                PathBuf::from("cibios/src/arch/riscv64/asm/boot.s"),
                PathBuf::from("cibios/src/arch/riscv64/asm/memory.s"),
                PathBuf::from("cibios/src/arch/riscv64/asm/transfer.s"),
            ],
            compiler_flags: vec!["-march=rv64gc".to_string()],
            linker_flags: vec![],
        }
    }

    /// Get platform-specific configuration
    pub fn get_platform_config(&self) -> PlatformConfig {
        match self.target_platform {
            HardwarePlatform::Desktop | HardwarePlatform::Laptop => self.get_desktop_config(),
            HardwarePlatform::Server => self.get_server_config(),
            HardwarePlatform::Mobile | HardwarePlatform::Tablet => self.get_mobile_config(),
            HardwarePlatform::Embedded | HardwarePlatform::SingleBoard => self.get_embedded_config(),
        }
    }

    fn get_desktop_config(&self) -> PlatformConfig {
        PlatformConfig {
            memory_layout: MemoryLayoutConfig {
                ram_start: 0x100000,    // 1MB
                ram_size: 0x40000000,   // 1GB default
                flash_start: 0xFFFC0000,
                flash_size: 0x40000,    // 256KB
            },
            feature_flags: vec!["desktop".to_string()],
            platform_specific_code: vec![],
        }
    }

    fn get_server_config(&self) -> PlatformConfig {
        PlatformConfig {
            memory_layout: MemoryLayoutConfig {
                ram_start: 0x100000,    // 1MB
                ram_size: 0x100000000,  // 4GB default
                flash_start: 0xFFFC0000,
                flash_size: 0x40000,    // 256KB
            },
            feature_flags: vec!["server".to_string()],
            platform_specific_code: vec![],
        }
    }

    fn get_mobile_config(&self) -> PlatformConfig {
        PlatformConfig {
            memory_layout: MemoryLayoutConfig {
                ram_start: 0x80000000,  // ARM typical
                ram_size: 0x20000000,   // 512MB default
                flash_start: 0x08000000,
                flash_size: 0x200000,   // 2MB
            },
            feature_flags: vec!["mobile".to_string()],
            platform_specific_code: vec![],
        }
    }

    fn get_embedded_config(&self) -> PlatformConfig {
        PlatformConfig {
            memory_layout: MemoryLayoutConfig {
                ram_start: 0x20000000,  // Cortex-M typical
                ram_size: 0x80000,      // 512KB
                flash_start: 0x08000000,
                flash_size: 0x100000,   // 1MB
            },
            feature_flags: vec!["embedded".to_string()],
            platform_specific_code: vec![],
        }
    }
}
