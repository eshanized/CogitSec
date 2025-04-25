mod ssh;
mod ftp;
mod http;
mod smtp;
mod mysql;
mod postgres;
mod smb;

use crate::core::credentials::Credentials;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use async_trait::async_trait;

/// Enumeration of supported protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    SSH,
    FTP,
    HTTP,
    HTTPS,
    SMTP,
    SMTPS,
    MySQL,
    PostgreSQL,
    SMB,
    // Add more protocols as needed
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::SSH => write!(f, "SSH"),
            Protocol::FTP => write!(f, "FTP"),
            Protocol::HTTP => write!(f, "HTTP"),
            Protocol::HTTPS => write!(f, "HTTPS"),
            Protocol::SMTP => write!(f, "SMTP"),
            Protocol::SMTPS => write!(f, "SMTPS"),
            Protocol::MySQL => write!(f, "MySQL"),
            Protocol::PostgreSQL => write!(f, "PostgreSQL"),
            Protocol::SMB => write!(f, "SMB"),
        }
    }
}

impl Protocol {
    /// Get the default port for this protocol
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::SSH => 22,
            Protocol::FTP => 21,
            Protocol::HTTP => 80,
            Protocol::HTTPS => 443,
            Protocol::SMTP => 25,
            Protocol::SMTPS => 465,
            Protocol::MySQL => 3306,
            Protocol::PostgreSQL => 5432,
            Protocol::SMB => 445,
        }
    }
    
    /// Get whether this protocol uses SSL/TLS by default
    pub fn uses_ssl_by_default(&self) -> bool {
        matches!(
            self,
            Protocol::HTTPS | Protocol::SMTPS
        )
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Whether authentication was successful
    pub success: bool,
    
    /// Error message (if any)
    pub error: Option<String>,
    
    /// Additional information
    pub info: Option<String>,
}

/// Trait for protocol handlers
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Get the protocol type
    fn protocol_type(&self) -> Protocol;
    
    /// Authenticate with the target using the provided credentials
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        use_ssl: bool,
        options: &std::collections::HashMap<String, String>,
    ) -> Result<AuthResult>;
}

/// Factory for creating protocol handlers
pub struct ProtocolFactory;

impl ProtocolFactory {
    /// Create a new protocol handler for the given protocol
    pub fn create_handler(protocol: Protocol) -> Box<dyn ProtocolHandler> {
        match protocol {
            Protocol::SSH => Box::new(ssh::SSHHandler::new()),
            Protocol::FTP => Box::new(ftp::FTPHandler::new()),
            Protocol::HTTP | Protocol::HTTPS => Box::new(http::HTTPHandler::new()),
            Protocol::SMTP | Protocol::SMTPS => Box::new(smtp::SMTPHandler::new()),
            Protocol::MySQL => Box::new(mysql::MySQLHandler::new()),
            Protocol::PostgreSQL => Box::new(postgres::PostgreSQLHandler::new()),
            Protocol::SMB => Box::new(smb::SMBHandler::new()),
        }
    }
} 