// CIBIOS Builder Module Organization - tools/cibios-builder/src/compilation/mod.rs
pub mod builder_compilation {
    //! Cross-platform compilation coordination for CIBIOS firmware
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{process::Command, time::Duration};
    use std::path::{Path, PathBuf};
    use std::collections::HashMap;
    
    // Compilation component exports
    pub use self::coordinator::{CompilerCoordinator, CompilationConfiguration, CompilationError};
    pub use self::rust_compiler::{RustCompiler, RustConfiguration, RustTarget};
    pub use self::assembly_compiler::{AssemblyCompiler, AssemblyConfiguration, AssemblyTarget};
    pub use self::linker::{Linker, LinkingConfiguration, LinkingResult};
    
    // Compilation module declarations
    pub mod coordinator;
    pub mod rust_compiler;
    pub mod assembly_compiler;
    pub mod linker;
    
    /// Main compiler coordinator managing cross-platform builds
    #[derive(Debug)]
    pub struct CompilerCoordinator {
        pub rust_compiler: RustCompiler,
        pub assembly_compiler: AssemblyCompiler,
        pub linker: Linker,
        pub build_config: CompilationConfiguration,
    }
    
    /// Cross-platform compilation configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompilationConfiguration {
        pub target_architecture: shared::types::hardware::ProcessorArchitecture,
        pub optimization_level: OptimizationLevel,
        pub debug_symbols: bool,
        pub cross_compilation: bool,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum OptimizationLevel {
        Debug,
        Release,
        MinSize,
    }
}
