use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler};
use anyhow::{Context, Result};
use log::{debug, error, warn};
use mysql::prelude::*;
use mysql::{Opts, OptsBuilder};
use std::collections::HashMap;
use std::time::Duration;
use async_trait::async_trait;

/// Handler for MySQL authentication
pub struct MySQLHandler;

impl MySQLHandler {
    /// Create a new MySQL handler
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for MySQLHandler {
    fn protocol_type(&self) -> Protocol {
        Protocol::MySQL
    }
    
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        use_ssl: bool,
        _options: &HashMap<String, String>,
    ) -> Result<AuthResult> {
        // MySQL authentication happens in the blocking thread pool
        // because the mysql crate doesn't support async operations
        let target = target.to_string();
        let credentials = credentials.clone();
        let use_ssl = use_ssl; // Pass to closure
        
        let result = tokio::task::spawn_blocking(move || -> Result<AuthResult> {
            debug!("Attempting MySQL authentication to {}:{}", target, port);
            
            // Build connection options
            let url = format!("mysql://{}:{}@{}:{}/mysql", 
                credentials.username, credentials.password, target, port);
                
            let mut builder = OptsBuilder::from_opts(Opts::from_url(&url)
                .with_context(|| format!("Failed to parse MySQL URL: {}", url))?);
                
            builder = builder
                .tcp_connect_timeout(Some(timeout));
                
            if use_ssl {
                builder = builder.ssl_opts(Some(mysql::SslOpts::default()));
            }
                
            // Try to connect
            match mysql::Conn::new(builder) {
                Ok(mut conn) => {
                    // Try a simple query to verify the connection
                    match conn.query_first::<String, _>("SELECT 'connected'") {
                        Ok(Some(_)) => {
                            debug!("MySQL authentication successful for user: {}", credentials.username);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                            })
                        },
                        Ok(None) => {
                            debug!("MySQL authentication successful but query failed for user: {}", credentials.username);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {} but query returned no results", credentials.username)),
                            })
                        },
                        Err(e) => {
                            debug!("MySQL authentication succeeded but query failed for user: {}: {}", credentials.username, e);
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
                    debug!("MySQL authentication failed for user: {}: {}", credentials.username, error_msg);
                    
                    Ok(AuthResult {
                        success: false,
                        error: Some(error_msg),
                        info: None,
                    })
                }
            }
        }).await
            .with_context(|| "MySQL authentication task failed")?;
            
        Ok(result?)
    }
} 