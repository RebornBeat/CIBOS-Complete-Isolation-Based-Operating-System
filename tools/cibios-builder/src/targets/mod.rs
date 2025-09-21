// =============================================================================
// BUILD TARGETS MODULE - tools/cibios-builder/src/targets/mod.rs
// =============================================================================

//! Architecture-specific build targets for CIBIOS firmware
//! 
//! This module provides build target implementations for different
//! processor architectures with architecture-specific optimizations
//! and configurations.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::{BuildConfiguration, ArchitectureConfig};
use shared::types::hardware::ProcessorArchitecture;

/// Build target trait for architecture-specific implementations
pub trait BuildTarget {
    /// Get target architecture
    fn get_architecture(&self) -> ProcessorArchitecture;
    
    /// Get target triple for compilation
    fn get_target_triple(&self) -> String;
    
    /// Get architecture-specific compiler flags
    fn get_compiler_flags(&self) -> Vec<String>;
    
    /// Get architecture-specific linker flags
    fn get_linker_flags(&self) -> Vec<String>;
    
    /// Get assembly files for this target
    fn get_assembly_files(&self) -> Vec<PathBuf>;
    
    /// Get linker script for this target
    fn get_linker_script(&self) -> PathBuf;
}

/// x86_64 build target implementation
#[derive(Debug)]
pub struct X86_64BuildTarget {
    config: BuildConfiguration,
}

/// ARM64 build target implementation
#[derive(Debug)]
pub struct AArch64BuildTarget {
    config: BuildConfiguration,
}

/// x86 32-bit build target implementation
#[derive(Debug)]
pub struct X86BuildTarget {
    config: BuildConfiguration,
}

/// RISC-V 64-bit build target implementation
#[derive(Debug)]
pub struct RiscV64BuildTarget {
    config: BuildConfiguration,
}

impl X86_64BuildTarget {
    /// Create new x86_64 build target
    pub fn new(config: BuildConfiguration) -> Self {
        Self { config }
    }
}

impl BuildTarget for X86_64BuildTarget {
    fn get_architecture(&self) -> ProcessorArchitecture {
        ProcessorArchitecture::X86_64
    }
    
    fn get_target_triple(&self) -> String {
        "x86_64-unknown-none".to_string()
    }
    
    fn get_compiler_flags(&self) -> Vec<String> {
        vec![
            "-m64".to_string(),
            "-march=x86-64".to_string(),
            "-mno-red-zone".to_string(),
            "-mno-mmx".to_string(),
            "-mno-sse".to_string(),
            "-mno-sse2".to_string(),
        ]
    }
    
    fn get_linker_flags(&self) -> Vec<String> {
        vec![
            "-m64".to_string(),
            "-nostdlib".to_string(),
            "-static".to_string(),
        ]
    }
    
    fn get_assembly_files(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("cibios/src/arch/x86_64/asm/boot.s"),
            PathBuf::from("cibios/src/arch/x86_64/asm/vt_x.s"),
            PathBuf::from("cibios/src/arch/x86_64/asm/memory.s"),
            PathBuf::from("cibios/src/arch/x86_64/asm/isolation.s"),
            PathBuf::from("cibios/src/arch/x86_64/asm/transfer.s"),
        ]
    }
    
    fn get_linker_script(&self) -> PathBuf {
        PathBuf::from("cibios/src/arch/x86_64/linker.ld")
    }
}

impl AArch64BuildTarget {
    /// Create new ARM64 build target
    pub fn new(config: BuildConfiguration) -> Self {
        Self { config }
    }
}

impl BuildTarget for AArch64BuildTarget {
    fn get_architecture(&self) -> ProcessorArchitecture {
        ProcessorArchitecture::AArch64
    }
    
    fn get_target_triple(&self) -> String {
        "aarch64-unknown-none".to_string()
    }
    
    fn get_compiler_flags(&self) -> Vec<String> {
        vec![
            "-march=armv8-a".to_string(),
            "-mgeneral-regs-only".to_string(),
            "-mstrict-align".to_string(),
        ]
    }
    
    fn get_linker_flags(&self) -> Vec<String> {
        vec![
            "-nostdlib".to_string(),
            "-static".to_string(),
        ]
    }
    
    fn get_assembly_files(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("cibios/src/arch/aarch64/asm/boot.s"),
            PathBuf::from("cibios/src/arch/aarch64/asm/trustzone.s"),
            PathBuf::from("cibios/src/arch/aarch64/asm/memory.s"),
            PathBuf::from("cibios/src/arch/aarch64/asm/power.s"),
            PathBuf::from("cibios/src/arch/aarch64/asm/transfer.s"),
        ]
    }
    
    fn get_linker_script(&self) -> PathBuf {
        PathBuf::from("cibios/src/arch/aarch64/linker.ld")
    }
}

impl X86BuildTarget {
    /// Create new x86 32-bit build target
    pub fn new(config: BuildConfiguration) -> Self {
        Self { config }
    }
}

impl BuildTarget for X86BuildTarget {
    fn get_architecture(&self) -> ProcessorArchitecture {
        ProcessorArchitecture::X86
    }
    
    fn get_target_triple(&self) -> String {
        "i686-unknown-none".to_string()
    }
    
    fn get_compiler_flags(&self) -> Vec<String> {
        vec![
            "-m32".to_string(),
            "-march=i686".to_string(),
            "-mno-mmx".to_string(),
            "-mno-sse".to_string(),
        ]
    }
    
    fn get_linker_flags(&self) -> Vec<String> {
        vec![
            "-m32".to_string(),
            "-nostdlib".to_string(),
            "-static".to_string(),
        ]
    }
    
    fn get_assembly_files(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("cibios/src/arch/x86/asm/boot.s"),
            PathBuf::from("cibios/src/arch/x86/asm/memory.s"),
            PathBuf::from("cibios/src/arch/x86/asm/transfer.s"),
        ]
    }
    
    fn get_linker_script(&self) -> PathBuf {
        PathBuf::from("cibios/src/arch/x86/linker.ld")
    }
}

impl RiscV64BuildTarget {
    /// Create new RISC-V 64-bit build target
    pub fn new(config: BuildConfiguration) -> Self {
        Self { config }
    }
}

impl BuildTarget for RiscV64BuildTarget {
    fn get_architecture(&self) -> ProcessorArchitecture {
        ProcessorArchitecture::RiscV64
    }
    
    fn get_target_triple(&self) -> String {
        "riscv64gc-unknown-none-elf".to_string()
    }
    
    fn get_compiler_flags(&self) -> Vec<String> {
        vec![
            "-march=rv64gc".to_string(),
            "-mabi=lp64".to_string(),
            "-mcmodel=medany".to_string(),
        ]
    }
    
    fn get_linker_flags(&self) -> Vec<String> {
        vec![
            "-nostdlib".to_string(),
            "-static".to_string(),
        ]
    }
    
    fn get_assembly_files(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("cibios/src/arch/riscv64/asm/boot.s"),
            PathBuf::from("cibios/src/arch/riscv64/asm/memory.s"),
            PathBuf::from("cibios/src/arch/riscv64/asm/transfer.s"),
        ]
    }
    
    fn get_linker_script(&self) -> PathBuf {
        PathBuf::from("cibios/src/arch/riscv64/linker.ld")
    }
}

/// Factory for creating build targets based on architecture
pub fn create_build_target(config: BuildConfiguration) -> Box<dyn BuildTarget> {
    match config.target_architecture {
        ProcessorArchitecture::X86_64 => Box::new(X86_64BuildTarget::new(config)),
        ProcessorArchitecture::AArch64 => Box::new(AArch64BuildTarget::new(config)),
        ProcessorArchitecture::X86 => Box::new(X86BuildTarget::new(config)),
        ProcessorArchitecture::RiscV64 => Box::new(RiscV64BuildTarget::new(config)),
    }
}
