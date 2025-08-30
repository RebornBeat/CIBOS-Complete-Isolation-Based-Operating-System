// CIBOS KERNEL NETWORK MODULE ORGANIZATION - cibos/kernel/src/net/mod.rs
pub mod kernel_network {
    //! Isolated network stack for CIBOS kernel
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use async_trait::async_trait;
    use uuid::Uuid;
    use std::sync::Arc;
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
    
    // Network component exports
    pub use self::tcp::{TCPStack, IsolatedTCPConnections, TCPIsolationManager};
    pub use self::udp::{UDPStack, IsolatedUDPSockets, UDPIsolationManager};
    pub use self::ip::{IPStack, NetworkIsolation, IPRoutingManager};
    pub use self::isolation::{NetworkIsolationEnforcement, TrafficIsolation};
    
    // Network module declarations
    pub mod tcp;
    pub mod udp;
    pub mod ip;
    pub mod isolation;
    
    /// Network stack with complete traffic isolation
    #[derive(Debug)]
    pub struct NetworkStack {
        pub tcp_stack: Arc<TCPStack>,
        pub udp_stack: Arc<UDPStack>,
        pub ip_stack: Arc<IPStack>,
        pub isolation_enforcement: Arc<NetworkIsolationEnforcement>,
    }
    
    /// Network isolation boundaries for applications
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkIsolationBoundary {
        pub boundary_id: Uuid,
        pub allowed_destinations: Vec<IpAddr>,
        pub allowed_ports: Vec<u16>,
        pub traffic_encryption_required: bool,
    }
}
