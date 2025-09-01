// =============================================================================
// CIBOS KERNEL NETWORK - TCP STACK WITH ISOLATION
// cibos/kernel/src/net/tcp.rs
// =============================================================================

//! TCP network stack with complete connection isolation
//! 
//! This module implements the TCP layer that provides isolated network
//! communication. Each application's TCP connections are completely
//! isolated from other applications' network activity.

// External dependencies for TCP functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, net::{TcpListener, TcpStream}, time::Duration};
use async_trait::async_trait;
use uuid::Uuid;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};
use std::collections::HashMap;

// Internal kernel imports
use crate::core::isolation::{IsolationManager, NetworkIsolationBoundary};
use crate::security::{SecurityManager, ResourceAuthorization};
use super::isolation::{NetworkIsolationEnforcement, ConnectionIsolation};

// Shared type imports
use shared::types::isolation::{NetworkBoundary, IsolationLevel};
use shared::types::error::{KernelError, NetworkError, IsolationError};

/// TCP stack providing isolated connections for applications
#[derive(Debug)]
pub struct TCPStack {
    pub connections: Arc<RwLock<HashMap<Uuid, IsolatedTCPConnection>>>,
    pub listeners: Arc<RwLock<HashMap<Uuid, IsolatedTCPListener>>>,
    pub isolation_manager: Arc<TCPIsolationManager>,
    pub traffic_monitor: Arc<TCPTrafficMonitor>,
}

/// Isolated TCP connection that enforces network boundaries
#[derive(Debug)]
pub struct IsolatedTCPConnection {
    pub connection_id: Uuid,
    pub stream: Arc<Mutex<TcpStream>>,
    pub isolation_boundary: Uuid,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub connection_time: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: Arc<Mutex<u64>>,
    pub bytes_received: Arc<Mutex<u64>>,
}

/// Isolated TCP listener that enforces connection boundaries
#[derive(Debug)]
pub struct IsolatedTCPListener {
    pub listener_id: Uuid,
    pub listener: Arc<TcpListener>,
    pub isolation_boundary: Uuid,
    pub local_addr: SocketAddr,
    pub connection_filter: ConnectionFilter,
}

/// TCP isolation manager enforcing connection boundaries
#[derive(Debug)]
pub struct TCPIsolationManager {
    pub connection_boundaries: Arc<RwLock<HashMap<Uuid, TCPBoundary>>>,
    pub connection_authorization: Arc<ConnectionAuthorizer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCPBoundary {
    pub boundary_id: Uuid,
    pub allowed_destinations: Vec<IpAddr>,
    pub allowed_source_ports: Vec<u16>,
    pub max_connections: u32,
    pub traffic_encryption_required: bool,
}

/// Connection filter for incoming TCP connections
#[derive(Debug, Clone)]
pub struct ConnectionFilter {
    pub allowed_sources: Vec<IpAddr>,
    pub require_encryption: bool,
    pub max_connections: u32,
}

/// Connection authorization engine
#[derive(Debug)]
pub struct ConnectionAuthorizer {
    pub authorization_cache: Arc<RwLock<HashMap<(Uuid, SocketAddr), ConnectionAuthResult>>>,
}

#[derive(Debug, Clone)]
struct ConnectionAuthResult {
    pub authorized: bool,
    pub requires_encryption: bool,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

/// TCP traffic monitor for isolation enforcement
#[derive(Debug)]
pub struct TCPTrafficMonitor {
    pub connection_stats: Arc<RwLock<HashMap<Uuid, ConnectionStats>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub connection_id: Uuid,
    pub isolation_boundary: Uuid,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_start: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

impl TCPStack {
    /// Initialize TCP stack with isolation enforcement
    pub async fn initialize(isolation_manager: Arc<IsolationManager>) -> AnyhowResult<Self> {
        info!("Initializing TCP stack with isolation boundaries");

        let connections = Arc::new(RwLock::new(HashMap::new()));
        let listeners = Arc::new(RwLock::new(HashMap::new()));
        let tcp_isolation = TCPIsolationManager::new().await?;
        let traffic_monitor = TCPTrafficMonitor::new().await?;

        Ok(Self {
            connections,
            listeners,
            isolation_manager: Arc::new(tcp_isolation),
            traffic_monitor: Arc::new(traffic_monitor),
        })
    }

    /// Create isolated TCP connection within boundary
    pub async fn create_connection(
        &self,
        target_addr: SocketAddr,
        isolation_boundary: Uuid
    ) -> AnyhowResult<Uuid> {
        info!("Creating TCP connection to {} for boundary {}", target_addr, isolation_boundary);

        // Verify connection is authorized
        let authorized = self.isolation_manager.verify_connection_authorization(&isolation_boundary, &target_addr).await?;
        if !authorized {
            return Err(anyhow::anyhow!("Connection to {} not authorized for boundary {}", target_addr, isolation_boundary));
        }

        // Establish TCP connection
        let stream = TcpStream::connect(target_addr).await
            .context("TCP connection failed")?;

        let local_addr = stream.local_addr().context("Failed to get local address")?;
        let connection_id = Uuid::new_v4();

        let isolated_connection = IsolatedTCPConnection {
            connection_id,
            stream: Arc::new(Mutex::new(stream)),
            isolation_boundary,
            remote_addr: target_addr,
            local_addr,
            connection_time: chrono::Utc::now(),
            bytes_sent: Arc::new(Mutex::new(0)),
            bytes_received: Arc::new(Mutex::new(0)),
        };

        // Register connection
        let mut connections = self.connections.write().await;
        connections.insert(connection_id, isolated_connection);

        // Initialize traffic monitoring
        self.traffic_monitor.initialize_connection_monitoring(connection_id, isolation_boundary).await?;

        info!("TCP connection {} established successfully", connection_id);
        Ok(connection_id)
    }

    /// Create isolated TCP listener within boundary
    pub async fn create_listener(
        &self,
        local_addr: SocketAddr,
        isolation_boundary: Uuid,
        connection_filter: ConnectionFilter
    ) -> AnyhowResult<Uuid> {
        info!("Creating TCP listener on {} for boundary {}", local_addr, isolation_boundary);

        // Create TCP listener
        let listener = TcpListener::bind(local_addr).await
            .context("TCP listener creation failed")?;

        let listener_id = Uuid::new_v4();

        let isolated_listener = IsolatedTCPListener {
            listener_id,
            listener: Arc::new(listener),
            isolation_boundary,
            local_addr,
            connection_filter,
        };

        // Register listener
        let mut listeners = self.listeners.write().await;
        listeners.insert(listener_id, isolated_listener);

        info!("TCP listener {} created successfully", listener_id);
        Ok(listener_id)
    }

    /// Send data through isolated TCP connection
    pub async fn send_data(&self, connection_id: Uuid, data: &[u8]) -> AnyhowResult<()> {
        debug!("Sending {} bytes through TCP connection {}", data.len(), connection_id);

        let connections = self.connections.read().await;
        let connection = connections.get(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("TCP connection {} not found", connection_id))?;

        // Send data through connection
        {
            use tokio::io::AsyncWriteExt;
            let mut stream = connection.stream.lock().await;
            stream.write_all(data).await
                .context("TCP send operation failed")?;
        }

        // Update traffic statistics
        {
            let mut bytes_sent = connection.bytes_sent.lock().await;
            *bytes_sent += data.len() as u64;
        }

        self.traffic_monitor.record_sent_data(connection_id, data.len() as u64).await?;

        Ok(())
    }

    /// Receive data from isolated TCP connection
    pub async fn receive_data(&self, connection_id: Uuid, buffer: &mut [u8]) -> AnyhowResult<usize> {
        debug!("Receiving data from TCP connection {}", connection_id);

        let connections = self.connections.read().await;
        let connection = connections.get(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("TCP connection {} not found", connection_id))?;

        // Receive data from connection
        let bytes_received = {
            use tokio::io::AsyncReadExt;
            let mut stream = connection.stream.lock().await;
            stream.read(buffer).await
                .context("TCP receive operation failed")?
        };

        // Update traffic statistics
        {
            let mut total_received = connection.bytes_received.lock().await;
            *total_received += bytes_received as u64;
        }

        self.traffic_monitor.record_received_data(connection_id, bytes_received as u64).await?;

        Ok(bytes_received)
    }

    /// Close isolated TCP connection
    pub async fn close_connection(&self, connection_id: Uuid) -> AnyhowResult<()> {
        info!("Closing TCP connection {}", connection_id);

        let mut connections = self.connections.write().await;
        let connection = connections.remove(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("TCP connection {} not found", connection_id))?;

        // Close the underlying stream
        drop(connection.stream);

        // Clean up traffic monitoring
        self.traffic_monitor.cleanup_connection_monitoring(connection_id).await?;

        info!("TCP connection {} closed successfully", connection_id);
        Ok(())
    }
}

impl TCPIsolationManager {
    async fn new() -> AnyhowResult<Self> {
        Ok(Self {
            connection_boundaries: Arc::new(RwLock::new(HashMap::new())),
            connection_authorization: Arc::new(ConnectionAuthorizer::new().await?),
        })
    }

    /// Register TCP boundary for isolation enforcement
    async fn register_boundary(&self, boundary_id: Uuid, tcp_boundary: TCPBoundary) -> AnyhowResult<()> {
        info!("Registering TCP boundary: {}", boundary_id);

        let mut boundaries = self.connection_boundaries.write().await;
        boundaries.insert(boundary_id, tcp_boundary);

        Ok(())
    }

    /// Verify connection authorization within isolation boundary
    async fn verify_connection_authorization(&self, boundary_id: &Uuid, target_addr: &SocketAddr) -> AnyhowResult<bool> {
        let boundaries = self.connection_boundaries.read().await;
        let boundary = boundaries.get(boundary_id)
            .ok_or_else(|| anyhow::anyhow!("TCP boundary {} not found", boundary_id))?;

        // Check if destination IP is allowed
        let destination_allowed = boundary.allowed_destinations.is_empty() || 
                                boundary.allowed_destinations.contains(&target_addr.ip());

        Ok(destination_allowed)
    }
}

impl ConnectionAuthorizer {
    async fn new() -> AnyhowResult<Self> {
        Ok(Self {
            authorization_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl TCPTrafficMonitor {
    async fn new() -> AnyhowResult<Self> {
        Ok(Self {
            connection_stats: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Initialize monitoring for new connection
    async fn initialize_connection_monitoring(&self, connection_id: Uuid, isolation_boundary: Uuid) -> AnyhowResult<()> {
        let stats = ConnectionStats {
            connection_id,
            isolation_boundary,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            connection_start: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
        };

        let mut connection_stats = self.connection_stats.write().await;
        connection_stats.insert(connection_id, stats);

        Ok(())
    }

    /// Record sent data statistics
    async fn record_sent_data(&self, connection_id: Uuid, bytes: u64) -> AnyhowResult<()> {
        let mut stats = self.connection_stats.write().await;
        if let Some(connection_stats) = stats.get_mut(&connection_id) {
            connection_stats.bytes_sent += bytes;
            connection_stats.packets_sent += 1;
            connection_stats.last_activity = chrono::Utc::now();
        }
        Ok(())
    }

    /// Record received data statistics
    async fn record_received_data(&self, connection_id: Uuid, bytes: u64) -> AnyhowResult<()> {
        let mut stats = self.connection_stats.write().await;
        if let Some(connection_stats) = stats.get_mut(&connection_id) {
            connection_stats.bytes_received += bytes;
            connection_stats.packets_received += 1;
            connection_stats.last_activity = chrono::Utc::now();
        }
        Ok(())
    }

    /// Clean up monitoring for closed connection
    async fn cleanup_connection_monitoring(&self, connection_id: Uuid) -> AnyhowResult<()> {
        let mut stats = self.connection_stats.write().await;
        stats.remove(&connection_id);
        Ok(())
    }
}
