use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler};
use anyhow::{Context, Result};
use log::{debug, error, warn};
use ssh2::Session;
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use async_trait::async_trait;

/// Handler for SSH authentication
pub struct SSHHandler;

impl SSHHandler {
    /// Create a new SSH handler
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for SSHHandler {
    fn protocol_type(&self) -> Protocol {
        Protocol::SSH
    }
    
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        _use_ssl: bool, // SSH always uses encryption
        _options: &HashMap<String, String>,
    ) -> Result<AuthResult> {
        // SSH authentication happens in the blocking thread pool
        // because the ssh2 library doesn't support async operations
        let target = target.to_string();
        let credentials = credentials.clone();
        
        let result = tokio::task::spawn_blocking(move || -> Result<AuthResult> {
            debug!("Attempting SSH authentication to {}:{}", target, port);
            
            // Connect to the server
            let tcp = TcpStream::connect(format!("{}:{}", target, port))
                .with_context(|| format!("Failed to connect to {}:{}", target, port))?;
            
            // Set connect timeout
            tcp.set_read_timeout(Some(timeout))?;
            tcp.set_write_timeout(Some(timeout))?;
            
            // Create SSH session
            let mut session = Session::new()
                .with_context(|| "Failed to create SSH session")?;
                
            session.set_timeout(timeout.as_millis() as u32);
            session.set_tcp_stream(tcp);
            session.handshake()
                .with_context(|| "SSH handshake failed")?;
                
            // Try to authenticate
            let result = session.userauth_password(&credentials.username, &credentials.password);
            
            match result {
                Ok(_) => {
                    debug!("SSH authentication successful for user: {}", credentials.username);
                    Ok(AuthResult {
                        success: true,
                        error: None,
                        info: Some(format!("Successfully authenticated as {}", credentials.username)),
                    })
                },
                Err(e) => {
                    debug!("SSH authentication failed for user: {}: {}", credentials.username, e);
                    Ok(AuthResult {
                        success: false,
                        error: Some(e.to_string()),
                        info: None,
                    })
                }
            }
        }).await
            .with_context(|| "SSH authentication task failed")?;
            
        Ok(result?)
    }
} 