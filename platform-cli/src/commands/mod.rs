
// =============================================================================
// CLI PLATFORM COMMANDS MODULE - cibos/platform-cli/src/commands/mod.rs
// Built-in Command Implementation and Routing
// =============================================================================

//! CLI Platform Built-in Commands
//! 
//! This module implements built-in commands that are directly integrated
//! into the CLI platform shell. These commands provide essential shell
//! functionality while maintaining isolation boundaries between command
//! execution contexts.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;

// Internal command imports
use crate::config::{CommandConfiguration, ShellConfiguration};

// Kernel integration for command isolation
use cibos_kernel::core::isolation::{IsolationManager, CommandIsolationBoundary};
use cibos_kernel::security::authorization::{ResourceAuthorization, CommandPermissions};

// Shared type imports
use shared::types::isolation::{IsolationLevel, CommandBoundary};
use shared::types::error::{CommandError, IsolationError};

// Command module component exports
pub use self::builtin::{BuiltinCommands, BuiltinCommand, BuiltinRegistry};
pub use self::system::{SystemCommands, SystemCommand, SystemInformation};
pub use self::application::{ApplicationCommands, ApplicationLauncher, ApplicationRegistry};
pub use self::parser::{CommandParser, ParsedCommand, CommandArguments};
pub use self::executor::{CommandExecutor, ExecutionContext, ExecutionResult};

// Command module declarations
pub mod builtin;
pub mod system;
pub mod application;
pub mod parser;
pub mod executor;

/// Command registry tracking all available commands
/// 
/// The registry maintains information about built-in commands, system
/// commands, and application launch commands while ensuring proper
/// isolation boundary assignment for each command type.
#[derive(Debug)]
pub struct CommandRegistry {
    /// Built-in shell commands
    builtin_commands: HashMap<String, BuiltinCommand>,
    
    /// System administration commands
    system_commands: HashMap<String, SystemCommand>,
    
    /// Application launch commands
    application_commands: HashMap<String, ApplicationLauncher>,
}

/// Command execution result providing comprehensive feedback
/// 
/// Results include execution status, output data, timing information,
/// and isolation boundary information for security auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Command execution success status
    pub success: bool,
    
    /// Command exit code (0 for success)
    pub exit_code: i32,
    
    /// Standard output from command execution
    pub stdout: String,
    
    /// Standard error from command execution
    pub stderr: String,
    
    /// Command execution duration
    pub execution_time: std::time::Duration,
    
    /// Isolation boundary used for execution
    pub isolation_boundary: Option<uuid::Uuid>,
}

/// Command execution error with detailed context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    /// Error type classification
    pub error_type: CommandErrorType,
    
    /// Human-readable error message
    pub message: String,
    
    /// Command that caused the error
    pub command: String,
    
    /// Error context information
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandErrorType {
    CommandNotFound,
    PermissionDenied,
    IsolationViolation,
    ExecutionFailed,
    InvalidArguments,
    ResourceUnavailable,
}

impl CommandRegistry {
    /// Initialize command registry with built-in commands
    pub fn initialize() -> Self {
        info!("Initializing CLI platform command registry");

        let mut registry = Self {
            builtin_commands: HashMap::new(),
            system_commands: HashMap::new(),
            application_commands: HashMap::new(),
        };

        // Register built-in shell commands
        registry.register_builtin_commands();
        
        // Register system administration commands
        registry.register_system_commands();
        
        // Register application launch commands
        registry.register_application_commands();

        info!("Command registry initialization completed");
        registry
    }

    /// Register built-in shell commands
    fn register_builtin_commands(&mut self) {
        // Essential shell commands
        self.builtin_commands.insert("help".to_string(), BuiltinCommand::Help);
        self.builtin_commands.insert("exit".to_string(), BuiltinCommand::Exit);
        self.builtin_commands.insert("cd".to_string(), BuiltinCommand::ChangeDirectory);
        self.builtin_commands.insert("pwd".to_string(), BuiltinCommand::PrintWorkingDirectory);
        self.builtin_commands.insert("ls".to_string(), BuiltinCommand::ListDirectory);
        self.builtin_commands.insert("echo".to_string(), BuiltinCommand::Echo);
        self.builtin_commands.insert("env".to_string(), BuiltinCommand::Environment);
        self.builtin_commands.insert("history".to_string(), BuiltinCommand::History);
        
        // File operations
        self.builtin_commands.insert("cat".to_string(), BuiltinCommand::DisplayFile);
        self.builtin_commands.insert("cp".to_string(), BuiltinCommand::CopyFile);
        self.builtin_commands.insert("mv".to_string(), BuiltinCommand::MoveFile);
        self.builtin_commands.insert("rm".to_string(), BuiltinCommand::RemoveFile);
        self.builtin_commands.insert("mkdir".to_string(), BuiltinCommand::MakeDirectory);
        self.builtin_commands.insert("rmdir".to_string(), BuiltinCommand::RemoveDirectory);
    }

    /// Register system administration commands
    fn register_system_commands(&mut self) {
        // System information commands
        self.system_commands.insert("ps".to_string(), SystemCommand::ProcessList);
        self.system_commands.insert("top".to_string(), SystemCommand::ProcessMonitor);
        self.system_commands.insert("df".to_string(), SystemCommand::DiskUsage);
        self.system_commands.insert("free".to_string(), SystemCommand::MemoryUsage);
        self.system_commands.insert("uptime".to_string(), SystemCommand::SystemUptime);
        
        // Service management commands
        self.system_commands.insert("systemctl".to_string(), SystemCommand::ServiceControl);
        self.system_commands.insert("service".to_string(), SystemCommand::ServiceManager);
        
        // Network commands
        self.system_commands.insert("ping".to_string(), SystemCommand::NetworkPing);
        self.system_commands.insert("netstat".to_string(), SystemCommand::NetworkStatus);
    }

    /// Register application launch commands
    fn register_application_commands(&mut self) {
        // Platform tool applications
        self.application_commands.insert("installer".to_string(), 
            ApplicationLauncher::new("cibos-installer", "System installation tool"));
        self.application_commands.insert("config-manager".to_string(), 
            ApplicationLauncher::new("cibos-config", "Configuration management"));
        self.application_commands.insert("diagnostics".to_string(), 
            ApplicationLauncher::new("cibos-diagnostics", "System diagnostics"));
    }

    /// Find command in registry
    pub fn find_command(&self, command_name: &str) -> Option<CommandType> {
        if let Some(builtin) = self.builtin_commands.get(command_name) {
            Some(CommandType::Builtin(builtin.clone()))
        } else if let Some(system) = self.system_commands.get(command_name) {
            Some(CommandType::System(system.clone()))
        } else if let Some(app) = self.application_commands.get(command_name) {
            Some(CommandType::Application(app.clone()))
        } else {
            None
        }
    }
}

/// Command type enumeration for routing execution
#[derive(Debug, Clone)]
pub enum CommandType {
    Builtin(BuiltinCommand),
    System(SystemCommand),
    Application(ApplicationLauncher),
}
