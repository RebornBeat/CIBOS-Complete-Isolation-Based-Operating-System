// CLI Platform Module Organization - cibos/platform-cli/src/shell/mod.rs
pub mod shell {
    //! Command shell implementation for CLI platform
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, sync::Mutex};
    use std::sync::Arc;
    use std::collections::VecDeque;
    
    // Shell component exports
    pub use self::executor::{CommandExecutor, ExecutionResult, ExecutionError};
    pub use self::parser::{CommandParser, ParsedCommand, CommandArguments};
    pub use self::environment::{ShellEnvironment, EnvironmentVariable, ShellConfiguration};
    pub use self::history::{ShellHistory, CommandHistory, HistoryEntry};
    
    // Shell module declarations
    pub mod executor;
    pub mod parser;
    pub mod environment;
    pub mod history;
    
    /// Main command shell coordinating user interaction
    #[derive(Debug)]
    pub struct CommandShell {
        pub executor: CommandExecutor,
        pub parser: CommandParser,
        pub environment: ShellEnvironment,
        pub history: ShellHistory,
    }
    
    /// Shell environment configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShellConfiguration {
        pub prompt_format: String,
        pub history_size: usize,
        pub auto_completion: bool,
        pub command_timeout: std::time::Duration,
    }
}
