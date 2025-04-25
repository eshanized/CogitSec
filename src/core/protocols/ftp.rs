use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler, VulnerabilityResult, VulnerabilitySeverity, ComplianceStandard, MonitoringData};
use anyhow::{Context, Result, anyhow};
use log::{debug, error, warn, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use async_trait::async_trait;
use chrono::Utc;
use tokio::time;

/// Handler for FTP authentication
pub struct FTPHandler;

impl FTPHandler {
    /// Create a new FTP handler
    pub fn new() -> Self {
        Self
    }
    
    /// Check if anonymous login is allowed
    fn check_anonymous_login(&self, target: &str, port: u16) -> Result<bool> {
        let conn_str = format!("{}:{}", target, port);
        match ftp::FtpStream::connect(&conn_str) {
            Ok(mut stream) => {
                let result = stream.login("anonymous", "anonymous@example.com");
                Ok(result.is_ok())
            },
            Err(_) => Ok(false)
        }
    }
    
    /// Check if the FTP server allows listing directories
    fn check_directory_listing(&self, target: &str, port: u16, username: &str, password: &str) -> Result<bool> {
        let conn_str = format!("{}:{}", target, port);
        match ftp::FtpStream::connect(&conn_str) {
            Ok(mut stream) => {
                if stream.login(username, password).is_ok() {
                    let result = stream.list(None);
                    Ok(result.is_ok())
                } else {
                    Ok(false)
                }
            },
            Err(_) => Ok(false)
        }
    }
    
    /// Attempt to get FTP server banner
    fn get_server_banner(&self, target: &str, port: u16) -> Result<String> {
        use std::net::TcpStream;
        use std::io::{BufRead, BufReader};
        
        let conn_str = format!("{}:{}", target, port);
        let stream = TcpStream::connect(conn_str)?;
        let mut reader = BufReader::new(stream);
        let mut banner = String::new();
        
        // Read the initial banner
        reader.read_line(&mut banner)?;
        
        Ok(banner)
    }
    
    /// Check if the FTP server supports secure connections
    fn check_secure_mode(&self, target: &str, port: u16) -> Result<bool> {
        let conn_str = format!("{}:{}", target, port);
        match ftp::FtpStream::connect(&conn_str) {
            Ok(mut stream) => {
                // Try to switch to secure mode
                let result = stream.command("AUTH TLS");
                
                // 234 response means TLS is supported
                Ok(result.is_ok() && result.unwrap_or_default().starts_with("234"))
            },
            Err(_) => Ok(false)
        }
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
                            
                            // Check user permissions by trying some operations
                            let mut permissions = Vec::new();
                            
                            // Check if we can list directories
                            if stream.list(None).is_ok() {
                                permissions.push("list".to_string());
                            }
                            
                            // Check if we can make directories
                            let test_dir = format!("test_dir_{}", Utc::now().timestamp());
                            if stream.mkdir(&test_dir).is_ok() {
                                permissions.push("write".to_string());
                                // Clean up by removing the test directory
                                let _ = stream.rmdir(&test_dir);
                            }
                            
                            // If we got this far, authentication succeeded
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                                session_token: None,
                                permissions: Some(permissions),
                            })
                        },
                        Err(e) => {
                            debug!("FTP authentication failed for user: {}: {}", credentials.username, e);
                            Ok(AuthResult {
                                success: false,
                                error: Some(e.to_string()),
                                info: None,
                                session_token: None,
                                permissions: None,
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
                        session_token: None,
                        permissions: None,
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
                    session_token: None,
                    permissions: None,
                })
            }
        }
    }
    
    async fn security_scan(
        &self,
        target: &str,
        port: u16,
        credentials: Option<&Credentials>,
        timeout: Duration,
        use_ssl: bool,
        _options: &HashMap<String, String>,
    ) -> Result<Vec<VulnerabilityResult>> {
        let target = target.to_string();
        let credentials_clone = credentials.cloned();
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<VulnerabilityResult>> {
            let mut vulnerabilities = Vec::new();
            
            // Check FTP banner for information disclosure
            if let Ok(banner) = self.get_server_banner(&target, port) {
                let banner = banner.trim();
                
                // Check if banner reveals version information
                if banner.contains("FTP") && 
                   (banner.contains("v") || banner.contains("version") || banner.contains(".")) {
                    vulnerabilities.push(VulnerabilityResult {
                        id: "FTP-BANNER-DISCLOSURE".to_string(),
                        severity: VulnerabilitySeverity::Low,
                        description: "FTP banner reveals version information".to_string(),
                        is_vulnerable: true,
                        details: Some(format!("Banner: {}", banner)),
                        remediation: Some("Configure the FTP server to use a generic banner that doesn't reveal version information".to_string()),
                    });
                }
            }
            
            // Check for anonymous access
            if let Ok(anonymous_allowed) = self.check_anonymous_login(&target, port) {
                if anonymous_allowed {
                    vulnerabilities.push(VulnerabilityResult {
                        id: "FTP-ANONYMOUS-ACCESS".to_string(),
                        severity: VulnerabilitySeverity::High,
                        description: "FTP server allows anonymous access".to_string(),
                        is_vulnerable: true,
                        details: Some("Anonymous FTP access is enabled, which may expose sensitive files".to_string()),
                        remediation: Some("Disable anonymous FTP access unless specifically required".to_string()),
                    });
                }
            }
            
            // Check if FTP is running in secure mode
            if !use_ssl {
                if let Ok(secure_supported) = self.check_secure_mode(&target, port) {
                    if !secure_supported {
                        vulnerabilities.push(VulnerabilityResult {
                            id: "FTP-CLEARTEXT".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: "FTP server does not support secure connections".to_string(),
                            is_vulnerable: true,
                            details: Some("Credentials and data are transmitted in cleartext".to_string()),
                            remediation: Some("Configure the FTP server to use FTPS (FTP over TLS/SSL)".to_string()),
                        });
                    }
                }
            }
            
            // If credentials were provided, check directory listing
            if let Some(creds) = &credentials_clone {
                if let Ok(listing_allowed) = self.check_directory_listing(&target, port, &creds.username, &creds.password) {
                    if listing_allowed {
                        // Information only, not a vulnerability
                        vulnerabilities.push(VulnerabilityResult {
                            id: "FTP-DIRECTORY-LISTING".to_string(),
                            severity: VulnerabilitySeverity::Info,
                            description: "FTP server allows directory listing".to_string(),
                            is_vulnerable: false,
                            details: Some("Directory listing is allowed for the authenticated user".to_string()),
                            remediation: None,
                        });
                    }
                }
            }
            
            Ok(vulnerabilities)
        }).await
            .with_context(|| "FTP security scan task failed")?;
            
        Ok(result?)
    }
    
    async fn compliance_check(
        &self,
        target: &str,
        port: u16,
        standard: ComplianceStandard,
        credentials: Option<&Credentials>,
        timeout: Duration,
        use_ssl: bool,
    ) -> Result<HashMap<String, bool>> {
        let target = target.to_string();
        let credentials_clone = credentials.cloned();
        
        let result = tokio::task::spawn_blocking(move || -> Result<HashMap<String, bool>> {
            let mut compliance_results = HashMap::new();
            
            // Check if anonymous access is allowed
            let anonymous_allowed = self.check_anonymous_login(&target, port)?;
            
            // Check if secure mode is supported
            let secure_supported = self.check_secure_mode(&target, port)?;
            
            match standard {
                ComplianceStandard::PCI_DSS => {
                    // PCI DSS Requirement 2.2.2: Enable only necessary services
                    compliance_results.insert("PCI-DSS-Req-2.2.2".to_string(), !anonymous_allowed);
                    
                    // PCI DSS Requirement 4.1: Use strong cryptography and security protocols
                    compliance_results.insert("PCI-DSS-Req-4.1".to_string(), use_ssl || secure_supported);
                    
                    // PCI DSS Requirement 8.2: Proper user authentication
                    compliance_results.insert("PCI-DSS-Req-8.2".to_string(), !anonymous_allowed);
                },
                ComplianceStandard::NIST_CSF => {
                    // NIST Cybersecurity Framework - Protect (PR)
                    compliance_results.insert("PR.AC-1-Access-Control".to_string(), !anonymous_allowed);
                    compliance_results.insert("PR.DS-2-Data-In-Transit".to_string(), use_ssl || secure_supported);
                },
                ComplianceStandard::ISO27001 => {
                    // ISO 27001 - A.9 Access Control
                    compliance_results.insert("A.9.1.2-Access-to-Networks".to_string(), !anonymous_allowed);
                    
                    // ISO 27001 - A.10 Cryptography
                    compliance_results.insert("A.10.1.1-Cryptographic-Controls".to_string(), use_ssl || secure_supported);
                },
                _ => {
                    // Generic security best practices
                    compliance_results.insert("No-Anonymous-Access".to_string(), !anonymous_allowed);
                    compliance_results.insert("Secure-Transport".to_string(), use_ssl || secure_supported);
                }
            }
            
            Ok(compliance_results)
        }).await
            .with_context(|| "FTP compliance check task failed")?;
            
        Ok(result?)
    }
    
    async fn monitor(
        &self,
        target: &str,
        port: u16,
        duration: Duration,
        interval: Duration,
        credentials: Option<&Credentials>,
        _use_ssl: bool,
    ) -> Result<Vec<MonitoringData>> {
        let target = target.to_string();
        let credentials_clone = credentials.cloned();
        
        let mut monitoring_data = Vec::new();
        let end_time = Instant::now() + duration;
        
        while Instant::now() < end_time {
            let target_clone = target.clone();
            let credentials_clone_inner = credentials_clone.clone();
            
            let result = tokio::task::spawn_blocking(move || -> Result<MonitoringData> {
                let now = Utc::now();
                let start = Instant::now();
                
                // Try to connect to the FTP server
                let connection_result = ftp::FtpStream::connect(format!("{}:{}", target_clone, port));
                let latency = start.elapsed().as_millis() as u64;
                
                let mut event_data = MonitoringData {
                    timestamp: now,
                    event_type: "connectivity_check".to_string(),
                    latency_ms: Some(latency),
                    bytes_transferred: None,
                    error: None,
                };
                
                match connection_result {
                    Ok(mut stream) => {
                        // If credentials are provided, try to authenticate
                        if let Some(creds) = &credentials_clone_inner {
                            let auth_start = Instant::now();
                            let auth_result = stream.login(&creds.username, &creds.password);
                            let auth_latency = auth_start.elapsed().as_millis() as u64;
                            
                            if auth_result.is_ok() {
                                event_data.event_type = "authenticated_session".to_string();
                                
                                // Try to get directory listing to check server functionality
                                let list_start = Instant::now();
                                let list_result = stream.list(None);
                                let list_latency = list_start.elapsed().as_millis() as u64;
                                
                                if let Ok(listing) = list_result {
                                    event_data.bytes_transferred = Some(listing.len() as u64);
                                }
                                
                                // Update latency to include auth + listing time
                                event_data.latency_ms = Some(latency + auth_latency + list_latency);
                            } else {
                                event_data.event_type = "authentication_failed".to_string();
                                if let Err(e) = auth_result {
                                    event_data.error = Some(e.to_string());
                                }
                                
                                // Update latency to include auth attempt time
                                event_data.latency_ms = Some(latency + auth_latency);
                            }
                        }
                    },
                    Err(e) => {
                        event_data.event_type = "connection_failed".to_string();
                        event_data.error = Some(e.to_string());
                    }
                }
                
                Ok(event_data)
            }).await
                .with_context(|| "FTP monitoring task failed")?;
                
            monitoring_data.push(result?);
            
            // Wait for the next interval
            time::sleep(interval).await;
        }
        
        Ok(monitoring_data)
    }
    
    async fn enumerate_resources(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        _use_ssl: bool,
    ) -> Result<Vec<String>> {
        let target = target.to_string();
        let credentials = credentials.clone();
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut resources = Vec::new();
            
            // Connect to the server
            let mut stream = ftp::FtpStream::connect(format!("{}:{}", target, port))
                .with_context(|| format!("Failed to connect to FTP server at {}:{}", target, port))?;
            
            // Authenticate
            stream.login(&credentials.username, &credentials.password)
                .with_context(|| format!("Failed to authenticate to FTP server as {}", credentials.username))?;
            
            // Get current directory
            let cwd = stream.pwd()
                .unwrap_or_else(|_| "/".to_string());
            
            resources.push(format!("directory:{}", cwd));
            
            // List directories
            if let Ok(list) = stream.list(None) {
                // Simple parsing of directory listing
                for line in list.split('\n') {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    if parts.len() >= 9 {
                        // Typically the format is like: "drwxr-xr-x 2 owner group size date time name"
                        let entry_type = if line.starts_with('d') { "directory" } else { "file" };
                        let name = parts[8..].join(" ");
                        
                        if !name.is_empty() && name != "." && name != ".." {
                            resources.push(format!("{}:{}/{}", entry_type, cwd, name));
                        }
                    }
                }
            }
            
            // Try to move to common directories and list their contents
            let common_dirs = vec!["/", "/pub", "/incoming", "/upload", "/download", "/data"];
            
            for dir in common_dirs {
                if stream.cwd(dir).is_ok() {
                    resources.push(format!("directory:{}", dir));
                    
                    if let Ok(list) = stream.list(None) {
                        for line in list.split('\n') {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            
                            if parts.len() >= 9 {
                                let entry_type = if line.starts_with('d') { "directory" } else { "file" };
                                let name = parts[8..].join(" ");
                                
                                if !name.is_empty() && name != "." && name != ".." {
                                    resources.push(format!("{}:{}/{}", entry_type, dir, name));
                                }
                            }
                        }
                    }
                    
                    // Return to original directory
                    let _ = stream.cwd(&cwd);
                }
            }
            
            // Get server features
            if let Ok(features) = stream.feat() {
                for feature in features.split('\n') {
                    let feature = feature.trim();
                    if !feature.is_empty() {
                        resources.push(format!("feature:{}", feature));
                    }
                }
            }
            
            Ok(resources)
        }).await
            .with_context(|| "FTP enumerate resources task failed")?;
            
        Ok(result?)
    }
    
    async fn extract_data(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        query: &str,
        timeout: Duration,
        _use_ssl: bool,
    ) -> Result<Vec<HashMap<String, String>>> {
        let target = target.to_string();
        let credentials = credentials.clone();
        let query = query.to_string();
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<HashMap<String, String>>> {
            let mut data = Vec::new();
            
            // Connect to the server
            let mut stream = ftp::FtpStream::connect(format!("{}:{}", target, port))
                .with_context(|| format!("Failed to connect to FTP server at {}:{}", target, port))?;
            
            // Authenticate
            stream.login(&credentials.username, &credentials.password)
                .with_context(|| format!("Failed to authenticate to FTP server as {}", credentials.username))?;
            
            // Parse the query - for FTP this could be a path to a file or a directory
            if query.ends_with('/') || query.is_empty() {
                // This is a directory listing request
                let path = if query.is_empty() { None } else { Some(query.as_str()) };
                
                if let Ok(list) = stream.list(path) {
                    for line in list.split('\n') {
                        if line.trim().is_empty() {
                            continue;
                        }
                        
                        let mut entry = HashMap::new();
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        
                        if parts.len() >= 9 {
                            entry.insert("permissions".to_string(), parts[0].to_string());
                            entry.insert("owner".to_string(), parts[2].to_string());
                            entry.insert("group".to_string(), parts[3].to_string());
                            entry.insert("size".to_string(), parts[4].to_string());
                            entry.insert("date".to_string(), format!("{} {}", parts[5], parts[6]));
                            entry.insert("time".to_string(), parts[7].to_string());
                            entry.insert("name".to_string(), parts[8..].join(" "));
                            entry.insert("type".to_string(), 
                                        if line.starts_with('d') { "directory".to_string() } 
                                        else { "file".to_string() });
                            
                            data.push(entry);
                        } else {
                            // For non-standard listings, just include the raw line
                            entry.insert("raw".to_string(), line.to_string());
                            data.push(entry);
                        }
                    }
                } else {
                    return Err(anyhow!("Failed to list directory: {}", query));
                }
            } else {
                // This is a file download request
                let mut buffer = Vec::new();
                
                // Try to download the file
                match stream.retr(&query, |reader| {
                    let bytes_read = reader.read_to_end(&mut buffer)?;
                    Ok(bytes_read)
                }) {
                    Ok(_) => {
                        let file_content = String::from_utf8_lossy(&buffer).to_string();
                        
                        // If the file appears to be text, try to parse it based on format
                        if !file_content.contains('\0') {
                            if query.ends_with(".csv") || file_content.contains(',') && file_content.contains('\n') {
                                // Simple CSV parsing
                                let lines: Vec<&str> = file_content.lines().collect();
                                if !lines.is_empty() {
                                    let headers: Vec<&str> = lines[0].split(',').collect();
                                    
                                    for line_idx in 1..lines.len() {
                                        let values: Vec<&str> = lines[line_idx].split(',').collect();
                                        let mut row = HashMap::new();
                                        
                                        for (i, value) in values.iter().enumerate() {
                                            let header = if i < headers.len() {
                                                headers[i].to_string()
                                            } else {
                                                format!("Column{}", i + 1)
                                            };
                                            
                                            row.insert(header, value.to_string());
                                        }
                                        
                                        data.push(row);
                                    }
                                }
                            } else {
                                // Just store as raw content
                                let mut entry = HashMap::new();
                                entry.insert("filename".to_string(), query.clone());
                                entry.insert("content".to_string(), file_content);
                                entry.insert("size".to_string(), buffer.len().to_string());
                                data.push(entry);
                            }
                        } else {
                            // Binary file, just record metadata
                            let mut entry = HashMap::new();
                            entry.insert("filename".to_string(), query.clone());
                            entry.insert("content_type".to_string(), "binary".to_string());
                            entry.insert("size".to_string(), buffer.len().to_string());
                            data.push(entry);
                        }
                    },
                    Err(e) => {
                        return Err(anyhow!("Failed to download file {}: {}", query, e));
                    }
                }
            }
            
            Ok(data)
        }).await
            .with_context(|| "FTP extract data task failed")?;
            
        Ok(result?)
    }
} 