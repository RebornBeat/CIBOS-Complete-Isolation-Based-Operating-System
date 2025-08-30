// GUI Platform Module Organization - cibos/platform-gui/src/window_manager/mod.rs
pub mod window_manager {
    //! Window management system for GUI platform
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use winit::{event_loop::EventLoop, window::{Window, WindowBuilder}};
    use wgpu::{Device, Queue, Surface, SurfaceConfiguration};
    use std::sync::Arc;
    use std::collections::HashMap;
    use uuid::Uuid;
    
    // Window manager component exports
    pub use self::compositor::{Compositor, CompositorConfiguration, RenderingEngine};
    pub use self::window::{WindowManager, WindowHandle, WindowConfiguration};
    pub use self::input::{InputManager, InputEvent, InputConfiguration};
    pub use self::desktop::{DesktopEnvironment, DesktopConfiguration, DesktopTheme};
    
    // Window manager module declarations
    pub mod compositor;
    pub mod window;
    pub mod input;
    pub mod desktop;
    
    /// Main window manager coordinating GUI operations
    #[derive(Debug)]
    pub struct WindowManager {
        pub compositor: Compositor,
        pub windows: Arc<std::sync::RwLock<HashMap<Uuid, WindowHandle>>>,
        pub input_manager: InputManager,
        pub desktop: DesktopEnvironment,
    }
    
    /// Window configuration for GUI applications
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WindowConfiguration {
        pub title: String,
        pub width: u32,
        pub height: u32,
        pub resizable: bool,
        pub decorations: bool,
    }
}
