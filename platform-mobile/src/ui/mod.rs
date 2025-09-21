// Mobile UI Module Organization - cibos/platform-mobile/src/ui/mod.rs
pub mod mobile_ui {
    //! Mobile user interface components for the platform runtime
    //! 
    //! These components provide the mobile platform's user interface framework,
    //! including home screen, status bar, notification system, and virtual keyboard.
    //! Applications connect to these services through IPC, not direct imports.
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use uuid::Uuid;
    use std::sync::Arc;
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};
    
    // Mobile UI component exports for platform services
    pub use self::launcher::{MobileLauncher, LauncherConfiguration, HomeScreen};
    pub use self::status_bar::{StatusBar, StatusBarConfiguration, SystemStatus};
    pub use self::notifications::{NotificationSystem, NotificationConfiguration, NotificationManager};
    pub use self::keyboard::{VirtualKeyboard, KeyboardConfiguration, InputMethod};
    pub use self::theme::{MobileTheme, ThemeConfiguration, ColorScheme};
    
    // Module declarations for UI components
    pub mod launcher;
    pub mod status_bar;
    pub mod notifications;
    pub mod keyboard;
    pub mod theme;
    
    /// Mobile launcher providing home screen and application launching interface
    #[derive(Debug)]
    pub struct MobileLauncher {
        pub home_screen: HomeScreen,
        pub app_drawer: ApplicationDrawer,
        pub quick_settings: QuickSettings,
        pub theme_manager: Arc<MobileTheme>,
    }
    
    #[derive(Debug)]
    pub struct HomeScreen {
        pub wallpaper: WallpaperConfiguration,
        pub widgets: Vec<HomeScreenWidget>,
        pub app_shortcuts: Vec<AppShortcut>,
    }
    
    #[derive(Debug)]
    pub struct ApplicationDrawer {
        pub available_apps: Vec<ApplicationEntry>,
        pub app_categories: HashMap<String, Vec<ApplicationEntry>>,
    }
    
    #[derive(Debug, Clone)]
    pub struct ApplicationEntry {
        pub app_name: String,
        pub executable_path: String,  // Path to executable, not module
        pub icon_path: String,
        pub launch_command: String,
    }
    
    #[derive(Debug)]
    pub struct QuickSettings {
        pub wifi_toggle: bool,
        pub cellular_toggle: bool,
        pub bluetooth_toggle: bool,
        pub airplane_mode: bool,
    }
    
    #[derive(Debug, Clone)]
    pub struct WallpaperConfiguration {
        pub image_path: String,
        pub scaling_mode: ScalingMode,
    }
    
    #[derive(Debug, Clone)]
    pub enum ScalingMode {
        Stretch,
        Fit,
        Fill,
        Center,
    }
    
    #[derive(Debug, Clone)]
    pub struct HomeScreenWidget {
        pub widget_type: WidgetType,
        pub position: WidgetPosition,
        pub size: WidgetSize,
    }
    
    #[derive(Debug, Clone)]
    pub enum WidgetType {
        Clock,
        Weather,
        Calendar,
        QuickActions,
    }
    
    #[derive(Debug, Clone)]
    pub struct WidgetPosition {
        pub x: f32,
        pub y: f32,
    }
    
    #[derive(Debug, Clone)]
    pub struct WidgetSize {
        pub width: f32,
        pub height: f32,
    }
    
    #[derive(Debug, Clone)]
    pub struct AppShortcut {
        pub app_name: String,
        pub position: WidgetPosition,
        pub icon_path: String,
    }
}
