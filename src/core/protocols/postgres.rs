use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler};
use anyhow::{Context, Result};
use log::{debug, error, warn};
use postgres::{Client, Config, NoTls};
use std::collections::HashMap;
use std::time::Duration;
use async_trait::async_trait;

/// Handler for PostgreSQL authentication
pub struct PostgreSQLHandler;

impl PostgreSQLHandler {
    /// Create a new PostgreSQL handler
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for PostgreSQLHandler {
    fn protocol_type(&self) -> Protocol {
        Protocol::PostgreSQL
    }
    
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        _use_ssl: bool, // TODO: Implement SSL support
        _options: &HashMap<String, String>,
    ) -> Result<AuthResult> {
        // PostgreSQL authentication happens in the blocking thread pool
        // because the postgres crate doesn't support async operations
        let target = target.to_string();
        let credentials = credentials.clone();
        
        let result = tokio::task::spawn_blocking(move || -> Result<AuthResult> {
            debug!("Attempting PostgreSQL authentication to {}:{}", target, port);
            
            // Build connection config
            let mut config = Config::new();
            config
                .host(&target)
                .port(port)
                .user(&credentials.username)
                .password(&credentials.password)
                .connect_timeout(timeout)
                .dbname("postgres"); // Connect to default database
                
            // Try to connect
            match config.connect(NoTls) {
                Ok(mut client) => {
                    // Try a simple query to verify the connection
                    match client.query_one("SELECT 1", &[]) {
                        Ok(_) => {
                            debug!("PostgreSQL authentication successful for user: {}", credentials.username);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                            })
                        },
                        Err(e) => {
                            debug!("PostgreSQL authentication succeeded but query failed for user: {}: {}", credentials.username, e);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {} but query failed: {}", credentials.username, e)),
                            })
                        }
                    }
                },
                Err(e) => {
                    // Check if the error is an authentication error
                    let error_msg = e.to_string();
                    debug!("PostgreSQL authentication failed for user: {}: {}", credentials.username, error_msg);
                    
                    Ok(AuthResult {
                        success: false,
                        error: Some(error_msg),
                        info: None,
                    })
                }
            }
        }).await
            .with_context(|| "PostgreSQL authentication task failed")?;
            
        Ok(result?)
    }
} 