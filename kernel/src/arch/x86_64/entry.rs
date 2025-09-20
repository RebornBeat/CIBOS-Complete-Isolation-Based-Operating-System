// =============================================================================
// CIBOS KERNEL x86_64 ENTRY - cibos/kernel/src/arch/x86_64/entry.rs
// x86_64 Kernel Entry Point Receiving CIBIOS Handoff
// =============================================================================

//! x86_64 kernel entry point
//! 
//! This module handles the transition from CIBIOS firmware to CIBOS kernel
//! on x86_64 architecture. It receives the handoff data from CIBIOS and
//! initializes the kernel runtime with complete isolation enforcement.

use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn};
use std::sync::Arc;

// x86_64 specific imports
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PageTable;
use x86_64::{PhysAddr, VirtAddr};

// Internal kernel imports
use crate::core::{KernelRuntime, KernelConfiguration};
use crate::core::memory::MemoryManager;
use crate::core::isolation::IsolationManager;
use super::X86_64KernelRuntime;

// Shared imports
use shared::protocols::handoff::HandoffData;
use shared::types::hardware::{ProcessorArchitecture, HardwareConfiguration};
use shared::types::error::{KernelError, ArchitectureError};

/// x86_64 kernel entry coordinator
pub struct X86_64KernelEntry;

impl X86_64KernelEntry {
    /// Receive handoff from CIBIOS and initialize x86_64 kernel
    pub async fn receive_cibios_handoff(handoff_data: HandoffData) -> AnyhowResult<Arc<KernelRuntime>> {
        info!("x86_64 kernel receiving CIBIOS handoff");

        // Validate handoff data for x86_64
        Self::validate_x86_64_handoff(&handoff_data)
            .context("x86_64 handoff validation failed")?;

        // Initialize x86_64 kernel runtime
        let x86_64_runtime = X86_64KernelRuntime::initialize(handoff_data.clone()).await
            .context("x86_64 kernel runtime initialization failed")?;

        // Create generic kernel runtime with x86_64 backend
        let kernel_config = KernelConfiguration::from_handoff(&handoff_data)
            .context("Kernel configuration creation failed")?;

        let kernel_runtime = Arc::new(KernelRuntime::initialize_x86_64(
            kernel_config,
            Arc::new(x86_64_runtime)
        ).await.context("Generic kernel runtime initialization failed")?);

        // Start x86_64 kernel services
        kernel_runtime.start_kernel_services().await
            .context("Failed to start kernel services")?;

        info!("x86_64 kernel successfully initialized and running");
        Ok(kernel_runtime)
    }

    /// Validate that handoff data is suitable for x86_64
    fn validate_x86_64_handoff(handoff_data: &HandoffData) -> AnyhowResult<()> {
        // Verify processor architecture
        if handoff_data.hardware_config.architecture != ProcessorArchitecture::X86_64 {
            return Err(anyhow::anyhow!("Handoff data is not for x86_64 architecture"));
        }

        // Verify memory layout
        if handoff_data.hardware_config.memory_layout.total_memory < 0x40000000 { // 1GB minimum
            return Err(anyhow::anyhow!("Insufficient memory for x86_64 kernel"));
        }

        // Verify essential verification chain
        if handoff_data.verification_chain.is_empty() {
            return Err(anyhow::anyhow!("Verification chain is empty"));
        }

        // Verify isolation boundaries are configured
        if handoff_data.isolation_boundaries.memory_boundary.size == 0 {
            return Err(anyhow::anyhow!("Memory isolation boundaries not configured"));
        }

        info!("x86_64 handoff validation completed successfully");
        Ok(())
    }
}

/// Entry point function called by CIBIOS assembly transfer code
#[no_mangle]
pub extern "C" fn receive_cibios_handoff(handoff_data_ptr: *const HandoffData) -> ! {
    // Convert raw pointer to safe HandoffData
    let handoff_data = unsafe {
        if handoff_data_ptr.is_null() {
            panic!("CIBIOS handoff data pointer is null");
        }
        (*handoff_data_ptr).clone()
    };

    info!("x86_64 kernel entry point called by CIBIOS");

    // Create async runtime for kernel operation
    let runtime = tokio::runtime::Runtime::new()
        .expect("Failed to create kernel async runtime");

    // Initialize kernel from handoff
    let kernel_result = runtime.block_on(async {
        X86_64KernelEntry::receive_cibios_handoff(handoff_data).await
    });

    match kernel_result {
        Ok(kernel_runtime) => {
            info!("Kernel initialization successful - entering main kernel loop");
            
            // Enter main kernel loop
            runtime.block_on(async {
                kernel_runtime.run_main_loop().await
            }).expect("Kernel main loop failed");
        }
        Err(e) => {
            error!("Kernel initialization failed: {}", e);
            panic!("Kernel initialization failed: {}", e);
        }
    }

    // Kernel should never exit
    unreachable!("Kernel main loop should never exit");
}
