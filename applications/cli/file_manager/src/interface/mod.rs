// cibos/applications/cli/file_manager/src/interface/mod.rs
pub mod interface {
    //! Command-line interface components for user interaction
    //!
    //! This module provides comprehensive CLI functionality including
    //! command parsing, interactive shell, command history, and
    //! formatted output display for file operations.

    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader, stdin, stdout}, sync::Mutex};
    use crossterm::{
        event::{Event, EventStream, KeyCode, KeyEvent},
        terminal::{enable_raw_mode, disable_raw_mode},
        execute, cursor, terminal, style::{Color, SetForegroundColor, ResetColor}
    };
    use std::sync::Arc;
    use std::collections::VecDeque;
    use chrono::{DateTime, Utc};

    // Component exports for CLI interface
    pub use self::shell::{InteractiveShell, ShellEnvironment, ShellConfiguration};
    pub use self::parser::{CommandParser, ParsedCommand, CommandParsingError};
    pub use self::history::{CommandHistory, HistoryEntry, HistoryManager};
    pub use self::display::{OutputFormatter, DisplayManager, OutputTheme};
    pub use self::input::{InputManager, InputEvent, InputConfiguration};

    // Internal interface modules
    pub mod shell;
    pub mod parser;
    pub mod history;
    pub mod display;
    pub mod input;

    /// Main CLI interface coordinating all user interaction
    #[derive(Debug)]
    pub struct CLIInterface {
        pub interactive_shell: Arc<InteractiveShell>,
        pub command_parser: Arc<CommandParser>,
        pub command_history: Arc<CommandHistory>,
        pub output_formatter: Arc<OutputFormatter>,
        pub input_manager: Arc<InputManager>,
    }

    /// Command processor for handling parsed commands
    #[derive(Debug)]
    pub struct CommandProcessor {
        pub current_directory: Arc<Mutex<PathBuf>>,
        pub command_aliases: HashMap<String, String>,
        pub command_completions: CommandCompletionEngine,
    }

    /// Parsed command structure with validation
    #[derive(Debug, Clone)]
    pub struct ParsedCommand {
        pub command_type: super::CLICommandType,
        pub arguments: Vec<String>,
        pub options: HashMap<String, String>,
        pub parsed_at: DateTime<Utc>,
    }

    #[derive(Debug)]
    pub struct CommandCompletionEngine {
        pub available_commands: Vec<String>,
        pub file_path_completer: FilePathCompleter,
    }

    #[derive(Debug)]
    pub struct FilePathCompleter {
        pub current_directory: PathBuf,
        pub completion_cache: HashMap<PathBuf, Vec<String>>,
    }
}

