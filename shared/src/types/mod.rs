// =============================================================================
// SHARED FOUNDATION MODULE ORGANIZATION - shared/src/types/mod.rs
// Complete type system organization for the entire isolation system
// =============================================================================

//! Type definitions and shared structures for the Complete Isolation System
//! 
//! This module provides all the fundamental types used across CIBIOS firmware,
//! CIBOS kernel, platform variants, and applications. These types define the
//! contracts and interfaces that enable mathematical isolation guarantees.

// Re-export all type categories for easy access
pub use self::hardware::*;
pub use self::isolation::*;
pub use self::authentication::*;
pub use self::profiles::*;
pub use self::error::*;
pub use self::config::*;

// Module declarations for type categories
pub mod hardware;
pub mod isolation;
pub mod authentication;
pub mod profiles;
pub mod error;
pub mod config;
