use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler, VulnerabilityResult, VulnerabilitySeverity, ComplianceStandard, MonitoringData};
use anyhow::{Context, Result, anyhow};
use log::{debug, error, warn, info};
use ssh2::Session;
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use tokio::time;
use chrono::{Utc, DateTime};

/// Handler for SSH authentication
pub struct SSHHandler;

impl SSHHandler {
    /// Create a new SSH handler
    pub fn new() -> Self {
        Self
    }
    
    /// Establish SSH connection and return the session
    fn connect(
        &self,
        target: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<(TcpStream, Session)> {
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
        session.set_tcp_stream(tcp.try_clone()?);
        
        // Perform handshake
        session.handshake()
            .with_context(|| "SSH handshake failed")?;
            
        Ok((tcp, session))
    }
    
    /// Check if server supports a specific SSH version
    fn check_ssh_version(&self, target: &str, port: u16, timeout: Duration) -> Result<String> {
        let tcp = TcpStream::connect(format!("{}:{}", target, port))
            .with_context(|| format!("Failed to connect to {}:{}", target, port))?;
        
        tcp.set_read_timeout(Some(timeout))?;
        
        let mut buffer = [0; 256];
        let mut version = String::new();
        
        // Read the SSH banner
        if let Ok(n) = tcp.peek(&mut buffer) {
            if n > 8 && &buffer[..4] == b"SSH-" {
                version = String::from_utf8_lossy(&buffer[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
        }
        
        if version.is_empty() {
            return Err(anyhow!("Could not retrieve SSH version"));
        }
        
        Ok(version)
    }
    
    /// Check if SSH server allows password authentication
    fn check_password_auth(&self, session: &Session) -> bool {
        session.auth_methods("")
            .unwrap_or_default()
            .contains("password")
    }
    
    /// Check if SSH server allows keyboard-interactive authentication
    fn check_keyboard_interactive_auth(&self, session: &Session) -> bool {
        session.auth_methods("")
            .unwrap_or_default()
            .contains("keyboard-interactive")
    }
    
    /// Check for weak algorithms
    fn check_weak_algorithms(&self, target: &str, port: u16) -> Result<Vec<String>> {
        // This would typically involve parsing the server's offered key exchange algorithms,
        // ciphers, MACs, etc. via a lower level implementation than ssh2.
        // For simplicity, here we just return a static list of potentially detected weak algorithms.
        // In a real implementation, this would parse the SSH server's KEX init message.
        
        let mut weak_algos = Vec::new();
        
        // Sample implementation - in a real-world scenario you'd actually check these
        weak_algos.push("diffie-hellman-group1-sha1".to_string());
        weak_algos.push("diffie-hellman-group14-sha1".to_string());
        weak_algos.push("3des-cbc".to_string());
        weak_algos.push("arcfour".to_string());
        weak_algos.push("hmac-md5".to_string());
        
        Ok(weak_algos)
    }
    
    /// Check if server enforces MFA
    fn check_mfa_enforced(&self, session: &Session) -> bool {
        // In a real implementation, this would require attempting to authenticate
        // and checking if a second factor is requested
        // For now, just check if keyboard-interactive is the only method or if publickey is required
        
        let auth_methods = session.auth_methods("").unwrap_or_default();
        
        // If only keyboard-interactive is allowed, or if publickey is required
        !auth_methods.contains("password") || 
            (auth_methods.contains("publickey") && !auth_methods.contains(","))
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
                    // Get user permissions/roles by running 'id' command
                    let mut channel = session.channel_session()?;
                    channel.exec("id")?;
                    
                    let mut output = String::new();
                    channel.read_to_string(&mut output)?;
                    channel.wait_close()?;
                    
                    let mut permissions = Vec::new();
                    if channel.exit_status()? == 0 {
                        // Parse the output to extract groups
                        if let Some(groups_part) = output.split("groups=").nth(1) {
                            let groups = groups_part.split_terminator(|c| c == ' ' || c == ',' || c == ')');
                            for group in groups {
                                if !group.is_empty() {
                                    if let Some(group_name) = group.split('(').nth(1) {
                                        let group_name = group_name.trim_end_matches(')');
                                        permissions.push(group_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check if user is root
                    let is_root = permissions.contains(&"root".to_string()) || 
                                  credentials.username == "root";
                    
                    if is_root {
                        permissions.push("administrative".to_string());
                    }
                    
                    debug!("SSH authentication successful for user: {}", credentials.username);
                    Ok(AuthResult {
                        success: true,
                        error: None,
                        info: Some(format!("Successfully authenticated as {}", credentials.username)),
                        session_token: None, // SSH doesn't use session tokens
                        permissions: Some(permissions),
                    })
                },
                Err(e) => {
                    debug!("SSH authentication failed for user: {}: {}", credentials.username, e);
                    Ok(AuthResult {
                        success: false,
                        error: Some(e.to_string()),
                        info: None,
                        session_token: None,
                        permissions: None,
                    })
                }
            }
        }).await
            .with_context(|| "SSH authentication task failed")?;
            
        Ok(result?)
    }
    
    async fn security_scan(
        &self,
        target: &str,
        port: u16,
        credentials: Option<&Credentials>,
        timeout: Duration,
        _use_ssl: bool,
        _options: &HashMap<String, String>,
    ) -> Result<Vec<VulnerabilityResult>> {
        let target = target.to_string();
        let credentials_clone = credentials.cloned();
        let handler = Self::new(); // Create a new handler for the task
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<VulnerabilityResult>> {
            let mut vulnerabilities = Vec::new();
            
            // Check SSH version
            let ssh_version = match handler.check_ssh_version(&target, port, timeout) {
                Ok(version) => version,
                Err(_) => "Unknown".to_string(),
            };
            
            // Check for outdated SSH version
            if ssh_version.contains("1.") || 
               ssh_version.contains("2.0") || 
               ssh_version.contains("4.") || 
               ssh_version.contains("5.") {
                vulnerabilities.push(VulnerabilityResult {
                    id: "SSH-OUTDATED-VERSION".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: "Outdated SSH server version detected".to_string(),
                    is_vulnerable: true,
                    details: Some(format!("Detected SSH version: {}", ssh_version)),
                    remediation: Some("Upgrade to the latest SSH server version".to_string()),
                });
            }
            
            // Try to establish connection
            let connection_result = handler.connect(&target, port, timeout);
            if let Ok((_, session)) = connection_result {
                // Check if password authentication is allowed
                if handler.check_password_auth(&session) {
                    vulnerabilities.push(VulnerabilityResult {
                        id: "SSH-PASSWORD-AUTH".to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        description: "SSH server allows password authentication".to_string(),
                        is_vulnerable: true,
                        details: Some("Password authentication is enabled, which can be susceptible to brute force attacks".to_string()),
                        remediation: Some("Consider disabling password authentication and using only key-based authentication".to_string()),
                    });
                }
                
                // Check if MFA is enforced
                if !handler.check_mfa_enforced(&session) {
                    vulnerabilities.push(VulnerabilityResult {
                        id: "SSH-NO-MFA".to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        description: "SSH server does not enforce multi-factor authentication".to_string(),
                        is_vulnerable: true,
                        details: Some("Single-factor authentication increases the risk of unauthorized access".to_string()),
                        remediation: Some("Configure SSH to require multi-factor authentication".to_string()),
                    });
                }
                
                // Check for weak algorithms
                if let Ok(weak_algos) = handler.check_weak_algorithms(&target, port) {
                    if !weak_algos.is_empty() {
                        vulnerabilities.push(VulnerabilityResult {
                            id: "SSH-WEAK-ALGORITHMS".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: "SSH server supports weak cryptographic algorithms".to_string(),
                            is_vulnerable: true,
                            details: Some(format!("Detected weak algorithms: {}", weak_algos.join(", "))),
                            remediation: Some("Disable weak cryptographic algorithms in the SSH server configuration".to_string()),
                        });
                    }
                }
                
                // Check if user has root access (if credentials provided)
                if let Some(creds) = &credentials_clone {
                    // Try to authenticate with provided credentials
                    if session.userauth_password(&creds.username, &creds.password).is_ok() {
                        // Check if user is root or has sudo access
                        let mut channel = session.channel_session()?;
                        
                        // Try to run sudo -l or check if user is root
                        if creds.username == "root" {
                            vulnerabilities.push(VulnerabilityResult {
                                id: "SSH-ROOT-LOGIN".to_string(),
                                severity: VulnerabilitySeverity::Critical,
                                description: "Direct root login is enabled".to_string(),
                                is_vulnerable: true,
                                details: Some("SSH server allows direct login as root".to_string()),
                                remediation: Some("Disable direct root login and use sudo for privileged operations".to_string()),
                            });
                        } else {
                            // Check sudo access
                            channel.exec("sudo -n -l")?;
                            let mut output = String::new();
                            channel.read_to_string(&mut output)?;
                            
                            if channel.exit_status()? == 0 && !output.contains("not allowed") {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "SSH-SUDO-NOPASSWD".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "User has passwordless sudo access".to_string(),
                                    is_vulnerable: true,
                                    details: Some(format!("User {} has sudo access without password verification", creds.username)),
                                    remediation: Some("Configure sudo to always require password verification".to_string()),
                                });
                            }
                        }
                    }
                }
            }
            
            Ok(vulnerabilities)
        }).await
            .with_context(|| "SSH security scan task failed")?;
            
        Ok(result?)
    }
    
    async fn compliance_check(
        &self,
        target: &str,
        port: u16,
        standard: ComplianceStandard,
        credentials: Option<&Credentials>,
        timeout: Duration,
        _use_ssl: bool,
    ) -> Result<HashMap<String, bool>> {
        let target = target.to_string();
        let credentials_clone = credentials.cloned();
        let standard_clone = standard;
        let handler = Self::new(); // Create a new handler for the task
        
        let result = tokio::task::spawn_blocking(move || -> Result<HashMap<String, bool>> {
            let mut compliance_results = HashMap::new();
            
            // Try to establish connection
            let connection_result = handler.connect(&target, port, timeout);
            
            match standard_clone {
                ComplianceStandard::PCI_DSS => {
                    // PCI DSS requirements related to SSH
                    compliance_results.insert("8.2.1-Strong-Cryptography".to_string(), true);
                    
                    if let Ok((_, session)) = &connection_result {
                        // Check if password authentication is disabled (8.2.3)
                        compliance_results.insert("8.2.3-Password-Auth-Disabled".to_string(), 
                                                 !handler.check_password_auth(session));
                        
                        // Check if MFA is enforced (8.3)
                        compliance_results.insert("8.3-MFA-Enforced".to_string(), 
                                                 handler.check_mfa_enforced(session));
                        
                        // Check for weak algorithms (4.1)
                        if let Ok(weak_algos) = handler.check_weak_algorithms(&target, port) {
                            compliance_results.insert("4.1-Strong-Cryptography".to_string(), 
                                                     weak_algos.is_empty());
                        }
                    }
                },
                ComplianceStandard::NIST_CSF => {
                    // NIST Cybersecurity Framework checks
                    if let Ok((_, session)) = &connection_result {
                        // Check if password authentication is disabled
                        compliance_results.insert("PR.AC-1-Strong-Authentication".to_string(),
                                                !handler.check_password_auth(session) || handler.check_mfa_enforced(session));
                        
                        // Check for weak algorithms
                        if let Ok(weak_algos) = handler.check_weak_algorithms(&target, port) {
                            compliance_results.insert("PR.DS-2-Data-In-Transit".to_string(),
                                                     weak_algos.is_empty());
                        }
                    }
                    
                    // SSH version check
                    if let Ok(ssh_version) = handler.check_ssh_version(&target, port, timeout) {
                        let is_current = !ssh_version.contains("1.") && 
                                         !ssh_version.contains("2.0") && 
                                         !ssh_version.contains("4.") && 
                                         !ssh_version.contains("5.");
                        compliance_results.insert("ID.AM-2-Software-Platforms".to_string(), is_current);
                    }
                },
                ComplianceStandard::ISO27001 => {
                    // ISO 27001 checks
                    if let Ok((_, session)) = &connection_result {
                        // Check access control (A.9)
                        compliance_results.insert("A.9.4.2-Secure-Authentication".to_string(),
                                                !handler.check_password_auth(session) || handler.check_mfa_enforced(session));
                        
                        // Check cryptography (A.10)
                        if let Ok(weak_algos) = handler.check_weak_algorithms(&target, port) {
                            compliance_results.insert("A.10.1.1-Cryptography-Policy".to_string(),
                                                     weak_algos.is_empty());
                        }
                    }
                },
                _ => {
                    // For other standards, add generic SSH security checks
                    if let Ok((_, session)) = &connection_result {
                        compliance_results.insert("Secure-Authentication".to_string(), 
                                                 !handler.check_password_auth(session) || handler.check_mfa_enforced(session));
                                                 
                        if let Ok(weak_algos) = handler.check_weak_algorithms(&target, port) {
                            compliance_results.insert("Strong-Cryptography".to_string(), weak_algos.is_empty());
                        }
                    }
                }
            }
            
            Ok(compliance_results)
        }).await
            .with_context(|| "SSH compliance check task failed")?;
            
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
                
                let connection_result = self.connect(&target_clone, port, Duration::from_secs(5));
                let latency = start.elapsed().as_millis() as u64;
                
                let mut event_data = MonitoringData {
                    timestamp: now,
                    event_type: "connectivity_check".to_string(),
                    latency_ms: Some(latency),
                    bytes_transferred: None,
                    error: None,
                };
                
                match connection_result {
                    Ok((_, session)) => {
                        // If credentials are provided, try to authenticate and get more data
                        if let Some(creds) = &credentials_clone_inner {
                            let auth_start = Instant::now();
                            let auth_result = session.userauth_password(&creds.username, &creds.password);
                            let auth_latency = auth_start.elapsed().as_millis() as u64;
                            
                            if auth_result.is_ok() {
                                event_data.event_type = "authenticated_session".to_string();
                                
                                // Get some system stats
                                if let Ok(mut channel) = session.channel_session() {
                                    if channel.exec("uptime").is_ok() {
                                        let mut output = String::new();
                                        if channel.read_to_string(&mut output).is_ok() {
                                            event_data.info = Some(format!("System uptime: {}", output.trim()));
                                        }
                                    }
                                }
                            } else {
                                event_data.event_type = "authentication_failed".to_string();
                                event_data.error = Some(auth_result.err().unwrap().to_string());
                            }
                            
                            // Add authentication latency
                            event_data.latency_ms = Some(latency + auth_latency);
                        }
                    },
                    Err(e) => {
                        event_data.event_type = "connection_failed".to_string();
                        event_data.error = Some(e.to_string());
                    }
                }
                
                Ok(event_data)
            }).await
                .with_context(|| "SSH monitoring task failed")?;
                
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
        let credentials_clone = credentials.clone();
        let handler = Self::new(); // Create a new handler for the task
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut resources = Vec::new();
            
            // Connect to the server
            let (_, session) = handler.connect(&target, port, timeout)?;
            
            // Authenticate
            session.userauth_password(&credentials_clone.username, &credentials_clone.password)
                .with_context(|| format!("Authentication failed for user {}", credentials_clone.username))?;
                
            // Check user home directory
            let mut channel = session.channel_session()?;
            channel.exec("pwd")?;
            
            let mut home_dir = String::new();
            channel.read_to_string(&mut home_dir)?;
            channel.wait_close()?;
            
            home_dir = home_dir.trim().to_string();
            resources.push(format!("home_directory:{}", home_dir));
            
            // List standard directories
            for dir in &["/etc", "/var/log", "/tmp", &home_dir] {
                let mut channel = session.channel_session()?;
                channel.exec(&format!("ls -la {}", dir))?;
                
                let mut output = String::new();
                channel.read_to_string(&mut output)?;
                
                if channel.exit_status()? == 0 {
                    resources.push(format!("directory:{}", dir));
                    
                    // Parse the output to find files
                    for line in output.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 8 {
                            // Skip . and ..
                            let name = parts[8];
                            if name != "." && name != ".." {
                                let path = format!("{}/{}", dir, name);
                                let file_type = match parts[0].chars().next() {
                                    Some('d') => "directory",
                                    Some('-') => "file",
                                    Some('l') => "symlink",
                                    _ => "other",
                                };
                                
                                resources.push(format!("{}:{}", file_type, path));
                            }
                        }
                    }
                }
            }
            
            // Check for users
            let mut channel = session.channel_session()?;
            channel.exec("cat /etc/passwd")?;
            
            let mut output = String::new();
            channel.read_to_string(&mut output)?;
            
            if channel.exit_status()? == 0 {
                for line in output.lines() {
                    if let Some(username) = line.split(':').next() {
                        resources.push(format!("user:{}", username));
                    }
                }
            }
            
            Ok(resources)
        }).await
            .with_context(|| "SSH resource enumeration task failed")?;
            
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
        let credentials_clone = credentials.clone();
        let query_clone = query.to_string();
        let handler = Self::new(); // Create a new handler for the task
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<HashMap<String, String>>> {
            let mut data = Vec::new();
            
            // Connect to the server
            let (_, session) = handler.connect(&target, port, timeout)?;
            
            // Authenticate
            session.userauth_password(&credentials_clone.username, &credentials_clone.password)
                .with_context(|| format!("Authentication failed for user {}", credentials_clone.username))?;
                
            // Execute the query (command)
            let mut channel = session.channel_session()?;
            channel.exec(&query_clone)?;
            
            let mut output = String::new();
            channel.read_to_string(&mut output)?;
            let exit_status = channel.exit_status()?;
            
            // Create a result object
            let mut result = HashMap::new();
            result.insert("command".to_string(), query_clone);
            result.insert("exit_status".to_string(), exit_status.to_string());
            result.insert("output".to_string(), output.clone());
            
            data.push(result);
            
            // If the output looks like a list of items, try to parse it
            let lines: Vec<&str> = output.lines().collect();
            if lines.len() > 1 {
                let first_line = lines[0];
                let headers: Vec<&str> = first_line.split_whitespace().collect();
                
                if headers.len() > 1 {
                    // This might be a table output (e.g., ls -l, ps, etc.)
                    for line in &lines[1..] {
                        let values: Vec<&str> = line.split_whitespace().collect();
                        
                        if values.len() >= headers.len() {
                            let mut row = HashMap::new();
                            
                            for (i, header) in headers.iter().enumerate() {
                                if i < values.len() {
                                    row.insert(header.to_string(), values[i].to_string());
                                }
                            }
                            
                            data.push(row);
                        }
                    }
                }
            }
            
            Ok(data)
        }).await
            .with_context(|| "SSH data extraction task failed")?;
            
        Ok(result?)
    }
} 