use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler};
use anyhow::{Context, Result};
use log::{debug, error, warn};
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;
use async_trait::async_trait;

/// Handler for FTP authentication
pub struct FTPHandler;

impl FTPHandler {
    /// Create a new FTP handler
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for FTPHandler {
    fn protocol_type(&self) -> Protocol {
        Protocol::FTP
    }
    
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        _timeout: Duration,
        _use_ssl: bool, // We'll ignore SSL for now due to missing features
        _options: &HashMap<String, String>,
    ) -> Result<AuthResult> {
        // FTP authentication happens in the blocking thread pool
        // because the FTP library doesn't support async operations
        let target = target.to_string();
        let credentials = credentials.clone();
        
        let result = tokio::task::spawn_blocking(move || -> Result<AuthResult> {
            debug!("Attempting FTP authentication to {}:{}", target, port);
            
            // Connect to the server
            match ftp::FtpStream::connect(format!("{}:{}", target, port)) {
                Ok(mut stream) => {
                    // Try to authenticate
                    match stream.login(&credentials.username, &credentials.password) {
                        Ok(_) => {
                            debug!("FTP authentication successful for user: {}", credentials.username);
                            
                            // If we got this far, authentication succeeded
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                            })
                        },
                        Err(e) => {
                            debug!("FTP authentication failed for user: {}: {}", credentials.username, e);
                            Ok(AuthResult {
                                success: false,
                                error: Some(e.to_string()),
                                info: None,
                            })
                        }
                    }
                },
                Err(e) => {
                    debug!("FTP connection failed: {}", e);
                    Ok(AuthResult {
                        success: false,
                        error: Some(format!("Connection error: {}", e)),
                        info: None,
                    })
                }
            }
        }).await;
        
        match result {
            Ok(result) => result,
            Err(e) => {
                // An error happened with the task
                debug!("FTP authentication task failed: {}", e);
                Ok(AuthResult {
                    success: false,
                    error: Some(format!("Task error: {}", e)),
                    info: None,
                })
            }
        }
    }
} 