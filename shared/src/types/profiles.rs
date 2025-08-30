// SHARED TYPES IMPLEMENTATIONS - shared/src/types/profiles.rs
pub mod profiles {
    //! User profile system types and definitions
    
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    
    /// User profile with complete isolation configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UserProfile {
        pub profile_id: Uuid,
        pub profile_name: String,
        pub authentication: super::authentication::AuthenticationMethod,
        pub isolation_config: super::isolation::IsolationConfiguration,
        pub profile_type: ProfileType,
        pub created_at: DateTime<Utc>,
        pub last_accessed: DateTime<Utc>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ProfileType {
        Desktop(DesktopProfile),
        Mobile(MobileProfile),
        CLI(CLIProfile),
    }
    
    /// Desktop profile configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DesktopProfile {
        pub window_manager_config: WindowManagerConfig,
        pub application_preferences: HashMap<String, ApplicationConfig>,
        pub desktop_theme: DesktopTheme,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WindowManagerConfig {
        pub default_window_size: (u32, u32),
        pub window_decorations: bool,
        pub multi_monitor_setup: bool,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ApplicationConfig {
        pub auto_start: bool,
        pub isolation_level: super::isolation::IsolationLevel,
        pub resource_limits: ResourceLimits,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ResourceLimits {
        pub max_memory_mb: u64,
        pub max_cpu_percentage: u8,
        pub max_storage_mb: u64,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DesktopTheme {
        pub theme_name: String,
        pub dark_mode: bool,
        pub accent_color: String,
    }
    
    /// Mobile profile configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MobileProfile {
        pub touch_sensitivity: f32,
        pub power_management: MobilePowerConfig,
        pub connectivity_preferences: ConnectivityConfig,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MobilePowerConfig {
        pub battery_saver_enabled: bool,
        pub performance_mode: MobilePerformanceMode,
        pub screen_timeout: std::time::Duration,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum MobilePerformanceMode {
        PowerSaver,
        Balanced,
        Performance,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectivityConfig {
        pub wifi_auto_connect: bool,
        pub cellular_data_enabled: bool,
        pub airplane_mode_default: bool,
    }
    
    /// CLI profile configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CLIProfile {
        pub shell_preferences: ShellConfig,
        pub command_history_size: usize,
        pub auto_completion_enabled: bool,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShellConfig {
        pub prompt_format: String,
        pub color_output: bool,
        pub command_timeout: std::time::Duration,
    }
    
    /// Profile configuration for creation and modification
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProfileConfiguration {
        pub profile_name: String,
        pub authentication_config: AuthenticationConfiguration,
        pub isolation_preferences: IsolationPreferences,
        pub platform_config: PlatformSpecificConfig,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticationConfiguration {
        pub method: super::authentication::AuthenticationMethod,
        pub backup_method: Option<super::authentication::AuthenticationMethod>,
        pub timeout_minutes: u32,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IsolationPreferences {
        pub maximum_isolation: bool,
        pub hardware_acceleration: bool,
        pub custom_boundaries: Option<super::isolation::BoundaryConfiguration>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum PlatformSpecificConfig {
        Desktop(DesktopProfile),
        Mobile(MobileProfile), 
        CLI(CLIProfile),
    }
    
    /// Profile capabilities based on authentication and platform
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProfileCapabilities {
        pub can_install_applications: bool,
        pub can_modify_system_config: bool,
        pub can_access_hardware_directly: bool,
        pub can_create_other_profiles: bool,
        pub isolation_override_allowed: bool,
    }
}
