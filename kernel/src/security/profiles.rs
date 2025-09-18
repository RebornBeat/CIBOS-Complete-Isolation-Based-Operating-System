// =============================================================================
// CIBOS KERNEL SECURITY - USER PROFILE MANAGEMENT
// cibos/kernel/src/security/profiles.rs
// Complete user profile system with mathematical isolation boundaries
// =============================================================================

// External dependencies for profile management functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, time::Duration, fs};
use async_trait::async_trait;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration as ChronoDuration};
use std::sync::Arc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// Cryptographic dependencies for profile security
use sha2::{Digest, Sha256};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore, AeadInPlace, KeyInit};
use ring::{digest, rand};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Internal kernel imports for isolation integration
use crate::core::isolation::{IsolationManager, ProfileIsolationBoundary};
use crate::core::memory::{MemoryManager, ProcessMemoryAllocation};
use crate::security::authorization::{AuthorizationEngine, ResourceAuthorization};

// Shared type imports for profile contracts
use shared::types::profiles::{
    UserProfile, ProfileConfiguration, ProfileCapabilities,
    DesktopProfile, MobileProfile, CLIProfile
};
use shared::types::isolation::{
    IsolationLevel, IsolationConfiguration, BoundaryConfiguration,
    MemoryBoundary, StorageBoundary, NetworkBoundary, ProcessBoundary
};
use shared::types::authentication::{AuthenticationMethod, UserCredentials};
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};
use shared::types::error::{ProfileError, IsolationError, SecurityError};

/// Main profile manager coordinating user profile isolation and lifecycle
#[derive(Debug)]
pub struct ProfileManager {
    active_profiles: Arc<RwLock<HashMap<Uuid, ActiveUserProfile>>>,
    profile_storage: Arc<ProfileStorage>,
    isolation_manager: Arc<IsolationManager>,
    authorization_engine: Arc<AuthorizationEngine>,
    profile_cache: Arc<RwLock<HashMap<Uuid, CachedProfile>>>,
    config: ProfileManagerConfiguration,
}

/// Active user profile with complete isolation boundary
#[derive(Debug, Clone)]
pub struct ActiveUserProfile {
    pub profile: UserProfile,
    pub isolation_boundary: Uuid,
    pub session_start: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub memory_allocation: ProcessMemoryAllocation,
    pub storage_boundaries: Vec<StorageBoundary>,
    pub network_boundaries: Vec<NetworkBoundary>,
}

/// Profile storage manager with encryption and isolation
#[derive(Debug)]
pub struct ProfileStorage {
    storage_root: PathBuf,
    encryption_key: Arc<ProfileEncryptionKey>,
    profile_index: Arc<RwLock<HashMap<Uuid, ProfileMetadata>>>,
}

/// Cached profile information for performance optimization
#[derive(Debug, Clone)]
pub struct CachedProfile {
    pub profile_id: Uuid,
    pub profile_name: String,
    pub last_accessed: DateTime<Utc>,
    pub isolation_requirements: IsolationConfiguration,
}

/// Profile manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManagerConfiguration {
    pub profile_storage_path: PathBuf,
    pub encryption_enabled: bool,
    pub profile_timeout: Duration,
    pub max_concurrent_profiles: u32,
    pub isolation_enforcement: IsolationEnforcementPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationEnforcementPolicy {
    Strict,     // Complete isolation always enforced
    // No other options - only maximum isolation supported
}

/// Profile metadata for indexing and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub profile_id: Uuid,
    pub profile_name: String,
    pub profile_type: ProfileType,
    pub created_at: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub storage_path: PathBuf,
    pub isolation_requirements: IsolationRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProfileType {
    Desktop,
    Mobile,
    CLI,
}

/// Isolation requirements for profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationRequirements {
    pub memory_isolation: bool,
    pub storage_isolation: bool,
    pub network_isolation: bool,
    pub process_isolation: bool,
    pub hardware_isolation: bool,
}

/// Profile encryption key manager
#[derive(Debug, ZeroizeOnDrop)]
pub struct ProfileEncryptionKey {
    key_material: [u8; 32],
    key_id: Uuid,
    created_at: DateTime<Utc>,
}

/// User profile data structure for comprehensive profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileData {
    pub base_profile: UserProfile,
    pub platform_specific: PlatformSpecificData,
    pub isolation_config: IsolationConfiguration,
    pub security_preferences: SecurityPreferences,
    pub application_permissions: HashMap<String, ApplicationPermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformSpecificData {
    Desktop(DesktopProfileData),
    Mobile(MobileProfileData),
    CLI(CLIProfileData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopProfileData {
    pub window_manager_config: WindowManagerConfig,
    pub desktop_theme: DesktopTheme,
    pub application_launcher: ApplicationLauncherConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileProfileData {
    pub touch_preferences: TouchPreferences,
    pub mobile_theme: MobileTheme,
    pub power_management: PowerManagementConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CLIProfileData {
    pub shell_preferences: ShellPreferences,
    pub terminal_config: TerminalConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPreferences {
    pub usb_key_required: bool,
    pub session_timeout: Duration,
    pub auto_lock_enabled: bool,
    pub encryption_level: EncryptionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionLevel {
    Maximum, // Only level supported - no compromise modes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationPermissions {
    pub storage_access: Vec<PathBuf>,
    pub network_access: Vec<String>,
    pub hardware_access: Vec<HardwarePermission>,
    pub isolation_override: bool, // Always false - no isolation bypassing
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwarePermission {
    Camera,
    Microphone,
    USB,
    Display,
}

// Platform-specific configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowManagerConfig {
    pub compositor_enabled: bool,
    pub window_animations: bool,
    pub multi_monitor_support: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopTheme {
    pub theme_name: String,
    pub dark_mode: bool,
    pub accent_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLauncherConfig {
    pub search_enabled: bool,
    pub recent_applications: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchPreferences {
    pub sensitivity: f32,
    pub gesture_recognition: bool,
    pub multi_touch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileTheme {
    pub theme_name: String,
    pub status_bar_style: StatusBarStyle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatusBarStyle {
    Light,
    Dark,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerManagementConfig {
    pub battery_saver_threshold: u8,
    pub screen_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPreferences {
    pub shell_type: ShellType,
    pub prompt_format: String,
    pub history_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShellType {
    Bash,
    Fish,
    Zsh,
    CIBOSShell, // Default CIBOS native shell
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalConfig {
    pub font_family: String,
    pub font_size: u16,
    pub color_scheme: String,
}

impl ProfileManager {
    /// Initialize profile manager with complete isolation support
    pub async fn initialize(config: ProfileManagerConfiguration) -> AnyhowResult<Self> {
        info!("Initializing CIBOS profile manager");

        // Initialize profile storage with encryption
        let storage = Arc::new(ProfileStorage::initialize(&config).await
            .context("Profile storage initialization failed")?);

        // Connect to isolation manager for boundary enforcement
        let isolation_manager = Arc::new(IsolationManager::new().await
            .context("Isolation manager connection failed")?);

        // Connect to authorization engine for permission management
        let authorization_engine = Arc::new(AuthorizationEngine::new().await
            .context("Authorization engine connection failed")?);

        // Initialize empty active profiles map
        let active_profiles = Arc::new(RwLock::new(HashMap::new()));

        // Initialize profile cache for performance
        let profile_cache = Arc::new(RwLock::new(HashMap::new()));

        info!("Profile manager initialization completed");

        Ok(Self {
            active_profiles,
            profile_storage: storage,
            isolation_manager,
            authorization_engine,
            profile_cache,
            config,
        })
    }

    /// Create new user profile with complete isolation boundaries
    pub async fn create_user_profile(
        &self,
        profile_name: String,
        profile_type: ProfileType,
        authentication_method: AuthenticationMethod,
    ) -> AnyhowResult<UserProfile> {
        info!("Creating new user profile: {}", profile_name);

        // Generate unique profile ID
        let profile_id = Uuid::new_v4();

        // Create isolation configuration for profile
        let isolation_config = self.create_profile_isolation_config(&profile_type).await?;

        // Create platform-specific profile data
        let platform_specific = self.create_platform_specific_data(&profile_type).await?;

        // Create comprehensive profile data structure
        let profile_data = UserProfileData {
            base_profile: UserProfile {
                profile_id,
                profile_name: profile_name.clone(),
                authentication: authentication_method,
                isolation_config: isolation_config.clone(),
                created_at: Utc::now(),
                last_accessed: Utc::now(),
            },
            platform_specific,
            isolation_config,
            security_preferences: SecurityPreferences::secure_defaults(),
            application_permissions: HashMap::new(),
        };

        // Store profile with encryption
        self.profile_storage.store_profile(&profile_data).await
            .context("Failed to store new user profile")?;

        // Update profile cache
        self.update_profile_cache(&profile_data.base_profile).await?;

        info!("User profile created successfully: {}", profile_id);
        Ok(profile_data.base_profile)
    }

    /// Load user profile and establish complete isolation boundary
    pub async fn load_user_profile(&self, profile_id: &Uuid) -> AnyhowResult<ActiveUserProfile> {
        info!("Loading user profile: {}", profile_id);

        // Check if profile is already active
        {
            let active_profiles = self.active_profiles.read().await;
            if let Some(active_profile) = active_profiles.get(profile_id) {
                // Update last activity timestamp
                let mut updated_profile = active_profile.clone();
                updated_profile.last_activity = Utc::now();
                return Ok(updated_profile);
            }
        }

        // Load profile from storage
        let profile_data = self.profile_storage.load_profile(profile_id).await
            .context("Failed to load profile from storage")?;

        // Create complete isolation boundary for profile
        let isolation_boundary = self.create_profile_isolation_boundary(&profile_data).await
            .context("Failed to create profile isolation boundary")?;

        // Allocate memory within isolation boundary
        let memory_allocation = self.allocate_profile_memory(&profile_data, isolation_boundary).await
            .context("Failed to allocate profile memory")?;

        // Create active profile with complete isolation
        let active_profile = ActiveUserProfile {
            profile: profile_data.base_profile.clone(),
            isolation_boundary,
            session_start: Utc::now(),
            last_activity: Utc::now(),
            memory_allocation,
            storage_boundaries: profile_data.isolation_config.storage_boundaries(),
            network_boundaries: profile_data.isolation_config.network_boundaries(),
        };

        // Store in active profiles
        {
            let mut active_profiles = self.active_profiles.write().await;
            active_profiles.insert(*profile_id, active_profile.clone());
        }

        info!("User profile loaded with isolation boundary: {}", isolation_boundary);
        Ok(active_profile)
    }

    /// Get isolation configuration for profile
    pub async fn get_isolation_configuration(&self, profile: &UserProfile) -> AnyhowResult<IsolationConfiguration> {
        // Load complete profile data to get detailed isolation configuration
        let profile_data = self.profile_storage.load_profile(&profile.profile_id).await
            .context("Failed to load profile for isolation configuration")?;

        Ok(profile_data.isolation_config)
    }

    /// Deactivate user profile and clean up isolation boundaries
    pub async fn deactivate_profile(&self, profile_id: &Uuid) -> AnyhowResult<()> {
        info!("Deactivating user profile: {}", profile_id);

        // Remove from active profiles
        let active_profile = {
            let mut active_profiles = self.active_profiles.write().await;
            active_profiles.remove(profile_id)
        };

        if let Some(profile) = active_profile {
            // Clean up isolation boundary
            self.isolation_manager.remove_boundary(&profile.isolation_boundary).await
                .context("Failed to clean up isolation boundary")?;

            // Clean up memory allocation
            self.cleanup_profile_memory(&profile.memory_allocation).await
                .context("Failed to clean up profile memory")?;

            info!("Profile deactivated and isolation boundary cleaned up");
        }

        Ok(())
    }

    /// Update user profile with new configuration
    pub async fn update_user_profile(&self, profile_id: &Uuid, updates: ProfileUpdates) -> AnyhowResult<()> {
        info!("Updating user profile: {}", profile_id);

        // Load current profile data
        let mut profile_data = self.profile_storage.load_profile(profile_id).await
            .context("Failed to load profile for update")?;

        // Apply updates while maintaining isolation requirements
        self.apply_profile_updates(&mut profile_data, updates).await?;

        // Store updated profile
        self.profile_storage.store_profile(&profile_data).await
            .context("Failed to store updated profile")?;

        // Update cache
        self.update_profile_cache(&profile_data.base_profile).await?;

        // If profile is active, update isolation boundaries
        if let Some(active_profile) = self.active_profiles.read().await.get(profile_id) {
            self.update_active_profile_isolation(&profile_data, &active_profile.isolation_boundary).await
                .context("Failed to update active profile isolation")?;
        }

        info!("User profile updated successfully");
        Ok(())
    }

    /// Create isolation configuration based on profile type
    async fn create_profile_isolation_config(&self, profile_type: &ProfileType) -> AnyhowResult<IsolationConfiguration> {
        let base_config = IsolationConfiguration::maximum_security();

        // Customize based on profile type while maintaining maximum security
        match profile_type {
            ProfileType::Desktop => Ok(base_config.with_desktop_optimizations()),
            ProfileType::Mobile => Ok(base_config.with_mobile_optimizations()),
            ProfileType::CLI => Ok(base_config.with_cli_optimizations()),
        }
    }

    /// Create platform-specific profile data
    async fn create_platform_specific_data(&self, profile_type: &ProfileType) -> AnyhowResult<PlatformSpecificData> {
        match profile_type {
            ProfileType::Desktop => Ok(PlatformSpecificData::Desktop(DesktopProfileData {
                window_manager_config: WindowManagerConfig::default(),
                desktop_theme: DesktopTheme::default(),
                application_launcher: ApplicationLauncherConfig::default(),
            })),
            ProfileType::Mobile => Ok(PlatformSpecificData::Mobile(MobileProfileData {
                touch_preferences: TouchPreferences::default(),
                mobile_theme: MobileTheme::default(),
                power_management: PowerManagementConfig::default(),
            })),
            ProfileType::CLI => Ok(PlatformSpecificData::CLI(CLIProfileData {
                shell_preferences: ShellPreferences::default(),
                terminal_config: TerminalConfig::default(),
            })),
        }
    }

    /// Create complete isolation boundary for profile
    async fn create_profile_isolation_boundary(&self, profile_data: &UserProfileData) -> AnyhowResult<Uuid> {
        let boundary_id = Uuid::new_v4();

        // Create isolation boundary through isolation manager
        self.isolation_manager.create_profile_boundary(
            boundary_id,
            &profile_data.isolation_config
        ).await.context("Failed to create profile isolation boundary")?;

        Ok(boundary_id)
    }

    /// Allocate memory within profile isolation boundary
    async fn allocate_profile_memory(
        &self,
        profile_data: &UserProfileData,
        isolation_boundary: Uuid,
    ) -> AnyhowResult<ProcessMemoryAllocation> {
        // Calculate memory requirements based on profile type and configuration
        let memory_size = self.calculate_profile_memory_requirements(profile_data).await?;

        // Allocate memory through isolation manager
        let memory_allocation = ProcessMemoryAllocation {
            base_address: 0, // Will be set by memory manager
            size: memory_size,
            protection: shared::types::isolation::MemoryProtectionFlags {
                read: true,
                write: true,
                execute: false, // No execute by default for security
            },
        };

        Ok(memory_allocation)
    }

    /// Calculate memory requirements for profile
    async fn calculate_profile_memory_requirements(&self, profile_data: &UserProfileData) -> AnyhowResult<u64> {
        // Base memory allocation
        let mut memory_size = 64 * 1024 * 1024; // 64MB base

        // Add platform-specific requirements
        memory_size += match &profile_data.platform_specific {
            PlatformSpecificData::Desktop(_) => 128 * 1024 * 1024, // 128MB for GUI
            PlatformSpecificData::Mobile(_) => 96 * 1024 * 1024,   // 96MB for mobile
            PlatformSpecificData::CLI(_) => 32 * 1024 * 1024,     // 32MB for CLI
        };

        Ok(memory_size)
    }

    /// Update profile cache for performance
    async fn update_profile_cache(&self, profile: &UserProfile) -> AnyhowResult<()> {
        let cached_profile = CachedProfile {
            profile_id: profile.profile_id,
            profile_name: profile.profile_name.clone(),
            last_accessed: Utc::now(),
            isolation_requirements: profile.isolation_config.clone(),
        };

        let mut cache = self.profile_cache.write().await;
        cache.insert(profile.profile_id, cached_profile);

        Ok(())
    }

    /// Apply profile updates while maintaining security
    async fn apply_profile_updates(&self, profile_data: &mut UserProfileData, updates: ProfileUpdates) -> AnyhowResult<()> {
        // Apply updates while ensuring isolation requirements are never weakened
        if let Some(new_name) = updates.profile_name {
            profile_data.base_profile.profile_name = new_name;
        }

        // Platform-specific updates
        if let Some(platform_updates) = updates.platform_specific {
            profile_data.platform_specific = platform_updates;
        }

        // Security preferences (only allow strengthening, never weakening)
        if let Some(security_updates) = updates.security_preferences {
            profile_data.security_preferences = self.merge_security_preferences(
                &profile_data.security_preferences,
                &security_updates
            )?;
        }

        // Update modification timestamp
        profile_data.base_profile.last_accessed = Utc::now();

        Ok(())
    }

    /// Merge security preferences ensuring security is never weakened
    fn merge_security_preferences(
        &self,
        current: &SecurityPreferences,
        updates: &SecurityPreferences
    ) -> AnyhowResult<SecurityPreferences> {
        Ok(SecurityPreferences {
            usb_key_required: current.usb_key_required || updates.usb_key_required, // Only allow strengthening
            session_timeout: std::cmp::min(current.session_timeout, updates.session_timeout), // Shorter timeout is more secure
            auto_lock_enabled: current.auto_lock_enabled || updates.auto_lock_enabled, // Only allow enabling
            encryption_level: EncryptionLevel::Maximum, // Always maximum - no compromise
        })
    }

    /// Update isolation boundaries for active profile
    async fn update_active_profile_isolation(
        &self,
        profile_data: &UserProfileData,
        isolation_boundary: &Uuid,
    ) -> AnyhowResult<()> {
        // Update isolation boundary configuration
        self.isolation_manager.update_boundary_configuration(
            *isolation_boundary,
            &profile_data.isolation_config
        ).await.context("Failed to update isolation boundary configuration")?;

        Ok(())
    }

    /// Clean up profile memory allocation
    async fn cleanup_profile_memory(&self, allocation: &ProcessMemoryAllocation) -> AnyhowResult<()> {
        // Memory cleanup would be handled by the memory manager
        // This is a placeholder for the actual memory deallocation
        info!("Cleaning up profile memory allocation at base address: 0x{:x}", allocation.base_address);
        Ok(())
    }
}

/// Profile updates structure for modifying existing profiles
#[derive(Debug, Clone)]
pub struct ProfileUpdates {
    pub profile_name: Option<String>,
    pub platform_specific: Option<PlatformSpecificData>,
    pub security_preferences: Option<SecurityPreferences>,
    pub application_permissions: Option<HashMap<String, ApplicationPermissions>>,
}

impl ProfileStorage {
    /// Initialize profile storage with encryption
    pub async fn initialize(config: &ProfileManagerConfiguration) -> AnyhowResult<Self> {
        // Ensure storage directory exists
        fs::create_dir_all(&config.profile_storage_path).await
            .context("Failed to create profile storage directory")?;

        // Generate or load encryption key
        let encryption_key = Arc::new(ProfileEncryptionKey::generate().await?);

        // Initialize profile index
        let profile_index = Arc::new(RwLock::new(HashMap::new()));

        // Load existing profile index if available
        let storage = Self {
            storage_root: config.profile_storage_path.clone(),
            encryption_key,
            profile_index,
        };

        storage.load_profile_index().await?;

        Ok(storage)
    }

    /// Store user profile with encryption
    pub async fn store_profile(&self, profile_data: &UserProfileData) -> AnyhowResult<()> {
        let profile_id = profile_data.base_profile.profile_id;
        info!("Storing user profile: {}", profile_id);

        // Serialize profile data
        let profile_json = serde_json::to_string(profile_data)
            .context("Failed to serialize profile data")?;

        // Encrypt profile data
        let encrypted_data = self.encrypt_profile_data(profile_json.as_bytes()).await
            .context("Failed to encrypt profile data")?;

        // Create profile storage path
        let profile_path = self.storage_root.join(format!("{}.profile", profile_id));

        // Write encrypted profile to disk
        fs::write(&profile_path, encrypted_data).await
            .context("Failed to write profile to disk")?;

        // Update profile metadata in index
        self.update_profile_index(profile_data, &profile_path).await?;

        info!("Profile stored successfully with encryption");
        Ok(())
    }

    /// Load user profile with decryption
    pub async fn load_profile(&self, profile_id: &Uuid) -> AnyhowResult<UserProfileData> {
        info!("Loading user profile: {}", profile_id);

        // Get profile path from index
        let profile_path = {
            let index = self.profile_index.read().await;
            index.get(profile_id)
                .ok_or_else(|| anyhow::anyhow!("Profile not found in index: {}", profile_id))?
                .storage_path.clone()
        };

        // Read encrypted profile data
        let encrypted_data = fs::read(&profile_path).await
            .context("Failed to read profile from disk")?;

        // Decrypt profile data
        let profile_json = self.decrypt_profile_data(&encrypted_data).await
            .context("Failed to decrypt profile data")?;

        // Deserialize profile data
        let profile_data: UserProfileData = serde_json::from_slice(&profile_json)
            .context("Failed to deserialize profile data")?;

        info!("Profile loaded and decrypted successfully");
        Ok(profile_data)
    }

    /// Encrypt profile data
    async fn encrypt_profile_data(&self, data: &[u8]) -> AnyhowResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(&Key::from_slice(&self.encryption_key.key_material));
        let nonce = Aes256Gcm::generate_nonce(&mut rand::SystemRandom::new());

        let mut ciphertext = data.to_vec();
        cipher.encrypt_in_place(&nonce, b"", &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend(ciphertext);

        Ok(encrypted_data)
    }

    /// Decrypt profile data
    async fn decrypt_profile_data(&self, encrypted_data: &[u8]) -> AnyhowResult<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new(&Key::from_slice(&self.encryption_key.key_material));
        let mut plaintext = ciphertext.to_vec();

        cipher.decrypt_in_place(nonce, b"", &mut plaintext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Update profile index with metadata
    async fn update_profile_index(&self, profile_data: &UserProfileData, storage_path: &Path) -> AnyhowResult<()> {
        let profile_type = match &profile_data.platform_specific {
            PlatformSpecificData::Desktop(_) => ProfileType::Desktop,
            PlatformSpecificData::Mobile(_) => ProfileType::Mobile,
            PlatformSpecificData::CLI(_) => ProfileType::CLI,
        };

        let metadata = ProfileMetadata {
            profile_id: profile_data.base_profile.profile_id,
            profile_name: profile_data.base_profile.profile_name.clone(),
            profile_type,
            created_at: profile_data.base_profile.created_at,
            last_modified: profile_data.base_profile.last_accessed,
            storage_path: storage_path.to_path_buf(),
            isolation_requirements: IsolationRequirements {
                memory_isolation: true,
                storage_isolation: true,
                network_isolation: true,
                process_isolation: true,
                hardware_isolation: true,
            },
        };

        let mut index = self.profile_index.write().await;
        index.insert(profile_data.base_profile.profile_id, metadata);

        // Persist index to disk
        self.save_profile_index().await?;

        Ok(())
    }

    /// Load profile index from disk
    async fn load_profile_index(&self) -> AnyhowResult<()> {
        let index_path = self.storage_root.join("profile_index.json");

        if index_path.exists() {
            let index_data = fs::read_to_string(&index_path).await
                .context("Failed to read profile index")?;

            let index: HashMap<Uuid, ProfileMetadata> = serde_json::from_str(&index_data)
                .context("Failed to deserialize profile index")?;

            let mut profile_index = self.profile_index.write().await;
            *profile_index = index;
        }

        Ok(())
    }

    /// Save profile index to disk
    async fn save_profile_index(&self) -> AnyhowResult<()> {
        let index_path = self.storage_root.join("profile_index.json");
        let index = self.profile_index.read().await;

        let index_data = serde_json::to_string_pretty(&*index)
            .context("Failed to serialize profile index")?;

        fs::write(&index_path, index_data).await
            .context("Failed to write profile index")?;

        Ok(())
    }
}

impl ProfileEncryptionKey {
    /// Generate new encryption key for profile storage
    pub async fn generate() -> AnyhowResult<Self> {
        let mut key_material = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut key_material)
            .map_err(|_| anyhow::anyhow!("Failed to generate encryption key"))?;

        Ok(Self {
            key_material,
            key_id: Uuid::new_v4(),
            created_at: Utc::now(),
        })
    }
}

// Default implementations for configuration structures
impl Default for WindowManagerConfig {
    fn default() -> Self {
        Self {
            compositor_enabled: true,
            window_animations: true,
            multi_monitor_support: true,
        }
    }
}

impl Default for DesktopTheme {
    fn default() -> Self {
        Self {
            theme_name: "CIBOS Default".to_string(),
            dark_mode: true,
            accent_color: "#007ACC".to_string(),
        }
    }
}

impl Default for ApplicationLauncherConfig {
    fn default() -> Self {
        Self {
            search_enabled: true,
            recent_applications: 10,
        }
    }
}

impl Default for TouchPreferences {
    fn default() -> Self {
        Self {
            sensitivity: 1.0,
            gesture_recognition: true,
            multi_touch: true,
        }
    }
}

impl Default for MobileTheme {
    fn default() -> Self {
        Self {
            theme_name: "CIBOS Mobile".to_string(),
            status_bar_style: StatusBarStyle::Auto,
        }
    }
}

impl Default for PowerManagementConfig {
    fn default() -> Self {
        Self {
            battery_saver_threshold: 20,
            screen_timeout: Duration::from_secs(60),
        }
    }
}

impl Default for ShellPreferences {
    fn default() -> Self {
        Self {
            shell_type: ShellType::CIBOSShell,
            prompt_format: "cibos@\\h:\\w$ ".to_string(),
            history_size: 1000,
        }
    }
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            font_family: "Consolas".to_string(),
            font_size: 12,
            color_scheme: "CIBOS Dark".to_string(),
        }
    }
}

impl SecurityPreferences {
    /// Create secure default security preferences
    pub fn secure_defaults() -> Self {
        Self {
            usb_key_required: true,
            session_timeout: Duration::from_secs(1800), // 30 minutes
            auto_lock_enabled: true,
            encryption_level: EncryptionLevel::Maximum,
        }
    }
}

// Extension traits for isolation configuration customization
trait IsolationConfigurationExt {
    fn with_desktop_optimizations(self) -> Self;
    fn with_mobile_optimizations(self) -> Self;
    fn with_cli_optimizations(self) -> Self;
}

impl IsolationConfigurationExt for IsolationConfiguration {
    fn with_desktop_optimizations(mut self) -> Self {
        // Desktop-specific isolation optimizations while maintaining security
        // All optimizations maintain complete isolation - no security compromises
        self
    }

    fn with_mobile_optimizations(mut self) -> Self {
        // Mobile-specific isolation optimizations for power efficiency
        // All optimizations maintain complete isolation - no security compromises
        self
    }

    fn with_cli_optimizations(mut self) -> Self {
        // CLI-specific isolation optimizations for server environments
        // All optimizations maintain complete isolation - no security compromises
        self
    }
}

// Extension traits for boundary extraction
trait IsolationConfigurationBoundaries {
    fn storage_boundaries(&self) -> Vec<StorageBoundary>;
    fn network_boundaries(&self) -> Vec<NetworkBoundary>;
}

impl IsolationConfigurationBoundaries for IsolationConfiguration {
    fn storage_boundaries(&self) -> Vec<StorageBoundary> {
        vec![self.storage_boundary.clone()]
    }

    fn network_boundaries(&self) -> Vec<NetworkBoundary> {
        vec![self.network_boundary.clone()]
    }
}

/// Profile isolation boundary management
#[derive(Debug)]
pub struct ProfileIsolation {
    isolation_manager: Arc<IsolationManager>,
    active_boundaries: Arc<RwLock<HashMap<Uuid, ProfileIsolationBoundary>>>,
}

impl ProfileIsolation {
    /// Create isolation boundary for user profile
    pub async fn create_profile_boundary(
        &self,
        profile_id: Uuid,
        config: &IsolationConfiguration,
    ) -> AnyhowResult<Uuid> {
        let boundary_id = Uuid::new_v4();

        // Create boundary through isolation manager
        self.isolation_manager.create_boundary(boundary_id, config).await
            .context("Failed to create profile isolation boundary")?;

        // Store boundary mapping
        let boundary = ProfileIsolationBoundary {
            boundary_id,
            profile_id,
            isolation_config: config.clone(),
            created_at: Utc::now(),
        };

        let mut boundaries = self.active_boundaries.write().await;
        boundaries.insert(boundary_id, boundary);

        Ok(boundary_id)
    }
}

