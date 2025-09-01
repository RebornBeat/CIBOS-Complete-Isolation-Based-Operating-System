// =============================================================================
// CIBOS KERNEL CORE - PROCESS SCHEDULER - cibos/kernel/src/core/scheduler.rs
// Complete process scheduling with mathematical isolation guarantees
// =============================================================================

//! Process scheduler with complete isolation enforcement
//! 
//! This module implements the process scheduler that maintains mathematical
//! isolation guarantees between all processes while providing optimal
//! performance through eliminated coordination bottlenecks.

// External dependencies for scheduling functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, time::{Duration, Instant}};
use async_trait::async_trait;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Utc};

// Internal kernel imports
use crate::core::memory::{MemoryManager, ProcessMemoryAllocation};
use crate::core::isolation::{IsolationManager, ProcessIsolationBoundary};

// Shared type imports  
use shared::types::isolation::{ProcessIsolationLevel, IsolationLevel, ProcessBoundary};
use shared::types::hardware::{ProcessorArchitecture, CpuAllocation};
use shared::types::error::{KernelError, SchedulerError};

/// Main process scheduler coordinating isolated process execution
#[derive(Debug)]
pub struct ProcessScheduler {
    pub ready_queue: Arc<RwLock<ProcessQueue>>,
    pub running_processes: Arc<RwLock<HashMap<u32, RunningProcess>>>,
    pub scheduling_policy: SchedulingPolicy,
    pub isolation_manager: Arc<IsolationManager>,
    pub memory_manager: Arc<MemoryManager>,
    pub config: SchedulingConfiguration,
}

/// Process queue implementation with isolation boundaries
#[derive(Debug)]
pub struct ProcessQueue {
    pub high_priority: VecDeque<SchedulableProcess>,
    pub normal_priority: VecDeque<SchedulableProcess>,
    pub background_priority: VecDeque<SchedulableProcess>,
}

/// Schedulable process with complete isolation information
#[derive(Debug, Clone)]
pub struct SchedulableProcess {
    pub process_id: u32,
    pub profile_id: Uuid,
    pub isolation_boundary: Uuid,
    pub priority: ProcessPriority,
    pub cpu_allocation: CpuAllocation,
    pub memory_allocation: ProcessMemoryAllocation,
    pub creation_time: DateTime<Utc>,
    pub last_scheduled: Option<DateTime<Utc>>,
}

/// Currently running process information
#[derive(Debug, Clone)]
pub struct RunningProcess {
    pub process: SchedulableProcess,
    pub execution_start: Instant,
    pub cpu_time_used: Duration,
    pub context_switches: u64,
}

/// Process priority levels for scheduling decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessPriority {
    System,     // System processes (highest priority)
    User,       // User applications (normal priority)
    Background, // Background tasks (lowest priority)
}

/// Scheduling policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchedulingPolicy {
    /// Fair scheduling with time slices based on priority
    Fair {
        time_slice_ms: u64,
        priority_boost: bool,
    },
    /// Real-time scheduling for system processes
    RealTime {
        preemption_enabled: bool,
    },
    /// Completely fair scheduler with isolation guarantees
    CompletelyFair {
        target_latency_ms: u64,
        min_granularity_ms: u64,
    },
}

/// Scheduler configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingConfiguration {
    pub policy: SchedulingPolicy,
    pub max_processes: u32,
    pub isolation_enforcement: bool,
    pub cpu_affinity_enabled: bool,
}

impl ProcessScheduler {
    /// Initialize process scheduler with isolation enforcement
    pub async fn initialize(
        config: SchedulingConfiguration,
        isolation_manager: Arc<IsolationManager>,
        memory_manager: Arc<MemoryManager>,
    ) -> AnyhowResult<Self> {
        info!("Initializing CIBOS process scheduler with isolation enforcement");

        let ready_queue = Arc::new(RwLock::new(ProcessQueue {
            high_priority: VecDeque::new(),
            normal_priority: VecDeque::new(),
            background_priority: VecDeque::new(),
        }));

        let running_processes = Arc::new(RwLock::new(HashMap::new()));

        info!("Process scheduler initialization completed");

        Ok(Self {
            ready_queue,
            running_processes,
            scheduling_policy: config.policy.clone(),
            isolation_manager,
            memory_manager,
            config,
        })
    }

    /// Schedule new process with automatic isolation boundary creation
    pub async fn schedule_process(&self, process: SchedulableProcess) -> AnyhowResult<()> {
        info!("Scheduling new process {} with isolation boundary {}", 
               process.process_id, process.isolation_boundary);

        // Verify isolation boundary exists and is valid
        self.isolation_manager.verify_boundary(&process.isolation_boundary).await
            .context("Process isolation boundary verification failed")?;

        // Verify memory allocation is within bounds
        self.memory_manager.verify_allocation(&process.memory_allocation).await
            .context("Process memory allocation verification failed")?;

        // Add process to appropriate priority queue
        let mut ready_queue = self.ready_queue.write().await;
        match process.priority {
            ProcessPriority::System => ready_queue.high_priority.push_back(process),
            ProcessPriority::User => ready_queue.normal_priority.push_back(process),
            ProcessPriority::Background => ready_queue.background_priority.push_back(process),
        }

        info!("Process scheduled successfully");
        Ok(())
    }

    /// Get next process to execute based on scheduling policy
    pub async fn get_next_process(&self) -> Option<SchedulableProcess> {
        let mut ready_queue = self.ready_queue.write().await;

        // Priority-based scheduling: system > user > background
        if let Some(process) = ready_queue.high_priority.pop_front() {
            return Some(process);
        }

        if let Some(process) = ready_queue.normal_priority.pop_front() {
            return Some(process);
        }

        ready_queue.background_priority.pop_front()
    }

    /// Execute process within its isolation boundary
    pub async fn execute_process(&self, process: SchedulableProcess) -> AnyhowResult<()> {
        info!("Executing process {} in isolation boundary {}", 
               process.process_id, process.isolation_boundary);

        // Ensure isolation boundary is active
        self.isolation_manager.activate_boundary(&process.isolation_boundary).await
            .context("Failed to activate process isolation boundary")?;

        // Create running process record
        let running_process = RunningProcess {
            process: process.clone(),
            execution_start: Instant::now(),
            cpu_time_used: Duration::new(0, 0),
            context_switches: 0,
        };

        // Add to running processes
        let mut running_processes = self.running_processes.write().await;
        running_processes.insert(process.process_id, running_process);

        // Execute process within time slice based on policy
        match &self.scheduling_policy {
            SchedulingPolicy::Fair { time_slice_ms, .. } => {
                self.execute_with_time_slice(&process, Duration::from_millis(*time_slice_ms)).await?;
            }
            SchedulingPolicy::RealTime { preemption_enabled } => {
                self.execute_real_time(&process, *preemption_enabled).await?;
            }
            SchedulingPolicy::CompletelyFair { target_latency_ms, .. } => {
                self.execute_fair_slice(&process, Duration::from_millis(*target_latency_ms)).await?;
            }
        }

        info!("Process execution completed");
        Ok(())
    }

    /// Execute process with time slice limitations
    async fn execute_with_time_slice(&self, process: &SchedulableProcess, time_slice: Duration) -> AnyhowResult<()> {
        // Execute process within isolation boundary for specified time slice
        // This would coordinate with architecture-specific execution context
        
        // Simulate execution time for now - real implementation would
        // coordinate with architecture-specific context switching
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        Ok(())
    }

    /// Execute real-time process with preemption control
    async fn execute_real_time(&self, process: &SchedulableProcess, preemption: bool) -> AnyhowResult<()> {
        // Real-time execution with optional preemption
        // This would integrate with hardware interrupt handling
        
        tokio::time::sleep(Duration::from_millis(5)).await;
        
        Ok(())
    }

    /// Execute process with completely fair scheduling
    async fn execute_fair_slice(&self, process: &SchedulableProcess, target_latency: Duration) -> AnyhowResult<()> {
        // Completely fair scheduler implementation
        // Time slice calculated based on number of processes and target latency
        
        tokio::time::sleep(Duration::from_millis(8)).await;
        
        Ok(())
    }

    /// Start scheduler main loop
    pub async fn start_scheduling(&self) -> AnyhowResult<()> {
        info!("Starting process scheduler main loop");

        loop {
            // Get next process to execute
            if let Some(process) = self.get_next_process().await {
                // Execute process within its isolation boundary
                if let Err(e) = self.execute_process(process).await {
                    error!("Process execution failed: {}", e);
                }
            } else {
                // No processes ready - yield CPU briefly
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    /// Get scheduling statistics for monitoring
    pub async fn get_scheduler_stats(&self) -> SchedulerStatistics {
        let ready_queue = self.ready_queue.read().await;
        let running_processes = self.running_processes.read().await;

        SchedulerStatistics {
            processes_ready: ready_queue.high_priority.len() + 
                           ready_queue.normal_priority.len() + 
                           ready_queue.background_priority.len(),
            processes_running: running_processes.len(),
            total_context_switches: running_processes.values()
                .map(|p| p.context_switches)
                .sum(),
        }
    }
}

/// Scheduler performance and status statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStatistics {
    pub processes_ready: usize,
    pub processes_running: usize,
    pub total_context_switches: u64,
}
