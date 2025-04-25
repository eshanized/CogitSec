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
use std::collections::HashMap;

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
    
    /// Get known vulnerabilities for this protocol
    pub fn known_vulnerabilities(&self) -> Vec<&'static str> {
        match self {
            Protocol::SSH => vec!["CVE-2018-10933", "CVE-2016-0777", "CVE-2020-14145"],
            Protocol::FTP => vec!["CVE-2019-5418", "CVE-2010-4221", "Anonymous login"],
            Protocol::HTTP | Protocol::HTTPS => vec!["CVE-2021-44228", "CVE-2017-5638", "SQLi", "XSS", "CSRF"],
            Protocol::SMTP | Protocol::SMTPS => vec!["CVE-2020-7247", "CVE-2019-10149", "Open relay"],
            Protocol::MySQL => vec!["CVE-2021-2307", "CVE-2020-2922", "Default credentials"],
            Protocol::PostgreSQL => vec!["CVE-2019-9193", "CVE-2018-1058", "Weak authentication"],
            Protocol::SMB => vec!["CVE-2020-0796", "CVE-2017-0144", "EternalBlue", "Null session"],
        }
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
    
    /// Session token or identifier (if applicable)
    pub session_token: Option<String>,
    
    /// User permissions/roles detected
    pub permissions: Option<Vec<String>>,
}

/// Vulnerability scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    /// Vulnerability identifier (e.g., CVE number)
    pub id: String,
    
    /// Severity level (Critical, High, Medium, Low, Info)
    pub severity: VulnerabilitySeverity,
    
    /// Description of the vulnerability
    pub description: String,
    
    /// Whether the target is vulnerable
    pub is_vulnerable: bool,
    
    /// Details about the vulnerability finding
    pub details: Option<String>,
    
    /// Remediation steps
    pub remediation: Option<String>,
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Security compliance standards
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStandard {
    PCI_DSS,
    HIPAA,
    GDPR,
    SOC2,
    ISO27001,
    NIST_CSF,
}

/// Connection monitoring data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringData {
    /// Timestamp of the monitoring event
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Type of event
    pub event_type: String,
    
    /// Connection latency in milliseconds
    pub latency_ms: Option<u64>,
    
    /// Data transferred in bytes
    pub bytes_transferred: Option<u64>,
    
    /// Error information if applicable
    pub error: Option<String>,
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
    
    /// Perform a security scan of the target
    async fn security_scan(
        &self,
        target: &str,
        port: u16,
        credentials: Option<&Credentials>,
        timeout: Duration,
        use_ssl: bool,
        options: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<VulnerabilityResult>> {
        // Default implementation returns an empty list
        // Each protocol should implement its own security scanning logic
        Ok(Vec::new())
    }
    
    /// Check if the target complies with specified security standards
    async fn compliance_check(
        &self,
        target: &str,
        port: u16,
        standard: ComplianceStandard,
        credentials: Option<&Credentials>,
        timeout: Duration,
        use_ssl: bool,
    ) -> Result<HashMap<String, bool>> {
        // Default implementation returns an empty map
        // Each protocol should implement its compliance checking logic
        Ok(HashMap::new())
    }
    
    /// Monitor the service for a specified duration
    async fn monitor(
        &self,
        target: &str,
        port: u16,
        duration: Duration,
        interval: Duration,
        credentials: Option<&Credentials>,
        use_ssl: bool,
    ) -> Result<Vec<MonitoringData>> {
        // Default implementation returns an empty list
        // Each protocol should implement its monitoring logic
        Ok(Vec::new())
    }
    
    /// Perform data extraction (if supported by the protocol)
    async fn extract_data(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        query: &str,
        timeout: Duration,
        use_ssl: bool,
    ) -> Result<Vec<HashMap<String, String>>> {
        // Default implementation returns an empty list
        // Protocols that support data extraction should override this
        Ok(Vec::new())
    }
    
    /// Enumerate resources available on the target
    async fn enumerate_resources(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        use_ssl: bool,
    ) -> Result<Vec<String>> {
        // Default implementation returns an empty list
        // Each protocol should implement its own resource enumeration logic
        Ok(Vec::new())
    }
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