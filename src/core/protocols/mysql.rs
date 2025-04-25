use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler, VulnerabilityResult, VulnerabilitySeverity, ComplianceStandard, MonitoringData};
use anyhow::{Context, Result, anyhow};
use log::{debug, error, warn, info};
use mysql::prelude::*;
use mysql::{Opts, OptsBuilder, Row, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use tokio::time;
use chrono::Utc;

/// Handler for MySQL authentication
pub struct MySQLHandler;

impl MySQLHandler {
    /// Create a new MySQL handler
    pub fn new() -> Self {
        Self
    }
    
    /// Create a connection to MySQL
    fn connect(&self, target: &str, port: u16, username: &str, password: &str, timeout: Duration, use_ssl: bool) -> Result<mysql::Conn> {
        // Build connection options
        let url = format!("mysql://{}:{}@{}:{}/mysql", username, password, target, port);
            
        let mut builder = OptsBuilder::from_opts(Opts::from_url(&url)
            .with_context(|| format!("Failed to parse MySQL URL: {}", url))?);
            
        builder = builder
            .tcp_connect_timeout(Some(timeout));
            
        if use_ssl {
            builder = builder.ssl_opts(Some(mysql::SslOpts::default()));
        }
            
        // Try to connect
        let conn = mysql::Conn::new(builder)
            .with_context(|| format!("Failed to connect to MySQL at {}:{}", target, port))?;
            
        Ok(conn)
    }
    
    /// Check for weak user passwords
    fn check_weak_passwords(&self, conn: &mut mysql::Conn) -> Result<Vec<String>> {
        let mut weak_accounts = Vec::new();
        
        // This query works for MySQL 5.7+
        // It tries to identify users with no authentication or weak configuration
        let query = "SELECT user, host FROM mysql.user WHERE authentication_string = '' OR plugin = 'mysql_old_password' OR plugin = 'mysql_native_password'";
        
        let result: Vec<Row> = conn.query(query).unwrap_or_default();
        
        for row in result {
            let user: String = row.get(0).unwrap_or_default();
            let host: String = row.get(1).unwrap_or_default();
            weak_accounts.push(format!("{}@{}", user, host));
        }
        
        Ok(weak_accounts)
    }
    
    /// Check if MySQL is publicly accessible
    fn check_public_access(&self, conn: &mut mysql::Conn) -> Result<bool> {
        // Check for users with wildcard host
        let query = "SELECT COUNT(*) FROM mysql.user WHERE host = '%'";
        let count: i64 = conn.query_first(query).unwrap_or(Some(0)).unwrap_or(0);
        
        Ok(count > 0)
    }
    
    /// Get MySQL version information
    fn get_version(&self, conn: &mut mysql::Conn) -> Result<String> {
        let version: String = conn.query_first("SELECT VERSION()").unwrap_or(Some(String::new())).unwrap_or_default();
        Ok(version)
    }
    
    /// Get user permissions
    fn get_user_permissions(&self, conn: &mut mysql::Conn, username: &str) -> Result<Vec<String>> {
        let mut permissions = Vec::new();
        
        // Check for global privileges
        let query = format!("SHOW GRANTS FOR '{}'", username);
        let result: Vec<Row> = conn.query(&query).unwrap_or_default();
        
        for row in result {
            if let Some(grant_str) = row.get::<String, _>(0) {
                permissions.push(grant_str);
            }
        }
        
        Ok(permissions)
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
                            
                            // Get user permissions
                            let mut permissions_vec = Vec::new();
                            
                            // Try to get grants for the current user
                            if let Ok(perm) = self.get_user_permissions(&mut conn, &credentials.username) {
                                // Check for admin privileges
                                let is_admin = perm.iter().any(|p| 
                                    p.contains("ALL PRIVILEGES") && 
                                    (p.contains("*.*") || p.contains("ON *.* TO")));
                                
                                // Add administrative role if detected
                                if is_admin {
                                    permissions_vec.push("administrative".to_string());
                                }
                                
                                // Check for read/write access
                                let can_read = perm.iter().any(|p| 
                                    p.contains("SELECT") || 
                                    p.contains("ALL PRIVILEGES"));
                                
                                let can_write = perm.iter().any(|p| 
                                    p.contains("INSERT") || 
                                    p.contains("UPDATE") || 
                                    p.contains("DELETE") || 
                                    p.contains("ALL PRIVILEGES"));
                                
                                if can_read {
                                    permissions_vec.push("read".to_string());
                                }
                                if can_write {
                                    permissions_vec.push("write".to_string());
                                }
                            }
                            
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                                session_token: None,
                                permissions: Some(permissions_vec),
                            })
                        },
                        Ok(None) => {
                            debug!("MySQL authentication successful but query failed for user: {}", credentials.username);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {} but query returned no results", credentials.username)),
                                session_token: None,
                                permissions: None,
                            })
                        },
                        Err(e) => {
                            debug!("MySQL authentication succeeded but query failed for user: {}: {}", credentials.username, e);
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {} but query failed: {}", credentials.username, e)),
                                session_token: None,
                                permissions: None,
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
                        session_token: None,
                        permissions: None,
                    })
                }
            }
        }).await
            .with_context(|| "MySQL authentication task failed")?;
            
        Ok(result?)
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
            
            // We need credentials to perform MySQL security checks
            if let Some(creds) = credentials_clone {
                match self.connect(&target, port, &creds.username, &creds.password, timeout, use_ssl) {
                    Ok(mut conn) => {
                        // Check MySQL version
                        if let Ok(version) = self.get_version(&mut conn) {
                            // Check for outdated MySQL version
                            if version.starts_with("5.") && !version.starts_with("5.7") {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "MYSQL-OUTDATED-VERSION".to_string(),
                                    severity: VulnerabilitySeverity::Medium,
                                    description: "Outdated MySQL version detected".to_string(),
                                    is_vulnerable: true,
                                    details: Some(format!("MySQL version: {}", version)),
                                    remediation: Some("Update to MySQL 5.7 or 8.0+".to_string()),
                                });
                            }
                        }
                        
                        // Check for users with weak passwords
                        if let Ok(weak_accounts) = self.check_weak_passwords(&mut conn) {
                            if !weak_accounts.is_empty() {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "MYSQL-WEAK-AUTHENTICATION".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "MySQL accounts with weak authentication detected".to_string(),
                                    is_vulnerable: true,
                                    details: Some(format!("Accounts: {}", weak_accounts.join(", "))),
                                    remediation: Some("Update authentication method and ensure strong passwords for all accounts".to_string()),
                                });
                            }
                        }
                        
                        // Check for public access
                        if let Ok(has_public_access) = self.check_public_access(&mut conn) {
                            if has_public_access {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "MYSQL-PUBLIC-ACCESS".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "MySQL server allows connections from any host".to_string(),
                                    is_vulnerable: true,
                                    details: Some("Users with '%' as host detected".to_string()),
                                    remediation: Some("Restrict MySQL user accounts to specific hosts/networks".to_string()),
                                });
                            }
                        }
                        
                        // Check if SSL is enforced
                        if !use_ssl {
                            vulnerabilities.push(VulnerabilityResult {
                                id: "MYSQL-NO-SSL".to_string(),
                                severity: VulnerabilitySeverity::Medium,
                                description: "MySQL connection is not using SSL/TLS".to_string(),
                                is_vulnerable: true,
                                details: Some("Communications with the database are not encrypted".to_string()),
                                remediation: Some("Configure MySQL to use SSL/TLS and require secure connections".to_string()),
                            });
                        }
                    },
                    Err(e) => {
                        vulnerabilities.push(VulnerabilityResult {
                            id: "MYSQL-CONNECTION-FAILED".to_string(),
                            severity: VulnerabilitySeverity::Info,
                            description: "Could not connect to MySQL server for security scan".to_string(),
                            is_vulnerable: false,
                            details: Some(format!("Connection error: {}", e)),
                            remediation: None,
                        });
                    }
                }
            } else {
                vulnerabilities.push(VulnerabilityResult {
                    id: "MYSQL-NO-CREDENTIALS".to_string(),
                    severity: VulnerabilitySeverity::Info,
                    description: "Could not perform MySQL security scan without credentials".to_string(),
                    is_vulnerable: false,
                    details: Some("Credentials are required for MySQL security scanning".to_string()),
                    remediation: None,
                });
            }
            
            Ok(vulnerabilities)
        }).await
            .with_context(|| "MySQL security scan task failed")?;
            
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
            
            // Default values for when checks can't be performed
            match standard {
                ComplianceStandard::PCI_DSS => {
                    compliance_results.insert("PCI-DSS-Req-2.2.1".to_string(), false);
                    compliance_results.insert("PCI-DSS-Req-4.1".to_string(), false);
                    compliance_results.insert("PCI-DSS-Req-8.2".to_string(), false);
                },
                ComplianceStandard::GDPR => {
                    compliance_results.insert("GDPR-Data-Protection".to_string(), false);
                },
                _ => {
                    compliance_results.insert("Database-Security-Baseline".to_string(), false);
                }
            };
            
            // We need credentials to perform MySQL compliance checks
            if let Some(creds) = credentials_clone {
                if let Ok(mut conn) = self.connect(&target, port, &creds.username, &creds.password, timeout, use_ssl) {
                    let version = self.get_version(&mut conn).unwrap_or_default();
                    let has_weak_accounts = !self.check_weak_passwords(&mut conn).unwrap_or_default().is_empty();
                    let has_public_access = self.check_public_access(&mut conn).unwrap_or(true);
                    
                    match standard {
                        ComplianceStandard::PCI_DSS => {
                            // PCI DSS Requirement 2.2.1: Change vendor defaults
                            compliance_results.insert("PCI-DSS-Req-2.2.1".to_string(), !has_weak_accounts);
                            
                            // PCI DSS Requirement 4.1: Use strong cryptography and security protocols
                            compliance_results.insert("PCI-DSS-Req-4.1".to_string(), use_ssl);
                            
                            // PCI DSS Requirement 8.2: Strong authentication
                            compliance_results.insert("PCI-DSS-Req-8.2".to_string(), !has_weak_accounts);
                            
                            // PCI DSS Requirement 1.3: Network security
                            compliance_results.insert("PCI-DSS-Req-1.3".to_string(), !has_public_access);
                        },
                        ComplianceStandard::GDPR => {
                            // GDPR Article 32: Security of processing
                            let data_protection = !has_weak_accounts && use_ssl && !has_public_access;
                            compliance_results.insert("GDPR-Data-Protection".to_string(), data_protection);
                            
                            // GDPR Article 25: Data protection by design
                            compliance_results.insert("GDPR-Data-Protection-By-Design".to_string(), use_ssl);
                        },
                        _ => {
                            // General database security baseline
                            let secure = !has_weak_accounts && !has_public_access && use_ssl;
                            compliance_results.insert("Database-Security-Baseline".to_string(), secure);
                            
                            // Current version
                            let supported_version = version.starts_with("8.") || version.starts_with("5.7");
                            compliance_results.insert("Current-Version".to_string(), supported_version);
                        }
                    }
                }
            }
            
            Ok(compliance_results)
        }).await
            .with_context(|| "MySQL compliance check task failed")?;
            
        Ok(result?)
    }
    
    async fn monitor(
        &self,
        target: &str,
        port: u16,
        duration: Duration,
        interval: Duration,
        credentials: Option<&Credentials>,
        use_ssl: bool,
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
                
                let mut event_data = MonitoringData {
                    timestamp: now,
                    event_type: "connectivity_check".to_string(),
                    latency_ms: None,
                    bytes_transferred: None,
                    error: None,
                };
                
                if let Some(creds) = credentials_clone_inner {
                    // Try to connect and run a test query
                    match self.connect(&target_clone, port, &creds.username, &creds.password, Duration::from_secs(5), use_ssl) {
                        Ok(mut conn) => {
                            let query_start = Instant::now();
                            
                            // Run a simple status query
                            match conn.query_first::<i64, _>("SELECT COUNT(*) FROM information_schema.processlist") {
                                Ok(Some(count)) => {
                                    let query_time = query_start.elapsed().as_millis() as u64;
                                    let total_time = start.elapsed().as_millis() as u64;
                                    
                                    event_data.event_type = "query_success".to_string();
                                    event_data.latency_ms = Some(total_time);
                                    event_data.bytes_transferred = Some(8); // Size of i64
                                    event_data.info = Some(format!("Active connections: {}", count));
                                },
                                Ok(None) => {
                                    let total_time = start.elapsed().as_millis() as u64;
                                    event_data.event_type = "query_empty".to_string();
                                    event_data.latency_ms = Some(total_time);
                                },
                                Err(e) => {
                                    let total_time = start.elapsed().as_millis() as u64;
                                    event_data.event_type = "query_failed".to_string();
                                    event_data.latency_ms = Some(total_time);
                                    event_data.error = Some(e.to_string());
                                }
                            }
                        },
                        Err(e) => {
                            let total_time = start.elapsed().as_millis() as u64;
                            event_data.event_type = "connection_failed".to_string();
                            event_data.latency_ms = Some(total_time);
                            event_data.error = Some(e.to_string());
                        }
                    }
                } else {
                    event_data.event_type = "no_credentials".to_string();
                    event_data.error = Some("No credentials provided for MySQL monitoring".to_string());
                }
                
                Ok(event_data)
            }).await
                .with_context(|| "MySQL monitoring task failed")?;
                
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
        use_ssl: bool,
    ) -> Result<Vec<String>> {
        let target = target.to_string();
        let credentials = credentials.clone();
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut resources = Vec::new();
            
            // Connect to the server
            let mut conn = self.connect(&target, port, &credentials.username, &credentials.password, timeout, use_ssl)?;
            
            // Get databases
            let databases: Vec<String> = conn.query("SHOW DATABASES").unwrap_or_default();
            for db in databases {
                resources.push(format!("database:{}", db));
                
                // For each database, get tables
                if let Ok(()) = conn.query_drop(format!("USE {}", db)) {
                    let tables: Vec<String> = conn.query("SHOW TABLES").unwrap_or_default();
                    for table in tables {
                        resources.push(format!("table:{}.{}", db, table));
                    }
                }
            }
            
            // Get users
            let users: Vec<Row> = conn.query("SELECT user, host FROM mysql.user").unwrap_or_default();
            for row in users {
                let user: String = row.get(0).unwrap_or_default();
                let host: String = row.get(1).unwrap_or_default();
                resources.push(format!("user:{}@{}", user, host));
            }
            
            // Get MySQL variables
            let variables: Vec<Row> = conn.query("SHOW VARIABLES LIKE 'version%'").unwrap_or_default();
            for row in variables {
                let name: String = row.get(0).unwrap_or_default();
                let value: String = row.get(1).unwrap_or_default();
                resources.push(format!("variable:{}={}", name, value));
            }
            
            Ok(resources)
        }).await
            .with_context(|| "MySQL enumerate resources task failed")?;
            
        Ok(result?)
    }
    
    async fn extract_data(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        query: &str,
        timeout: Duration,
        use_ssl: bool,
    ) -> Result<Vec<HashMap<String, String>>> {
        let target = target.to_string();
        let credentials = credentials.clone();
        let query = query.to_string();
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<HashMap<String, String>>> {
            // Connect to the server
            let mut conn = self.connect(&target, port, &credentials.username, &credentials.password, timeout, use_ssl)?;
            
            // Run the query and get the results
            let result = conn.query_map(
                query,
                |row: mysql::Row| {
                    let mut map = HashMap::new();
                    
                    for (i, column) in row.columns_ref().iter().enumerate() {
                        let column_name = column.name_str().to_string();
                        let value = match row.get_opt::<Value, usize>(i) {
                            Some(Ok(Value::NULL)) => "NULL".to_string(),
                            Some(Ok(Value::Bytes(bytes))) => String::from_utf8_lossy(&bytes).to_string(),
                            Some(Ok(Value::Int(num))) => num.to_string(),
                            Some(Ok(Value::UInt(num))) => num.to_string(),
                            Some(Ok(Value::Float(num))) => num.to_string(),
                            Some(Ok(Value::Double(num))) => num.to_string(),
                            Some(Ok(Value::Date(..))) | Some(Ok(Value::Time(..))) => row.get::<String, usize>(i).unwrap_or_default(),
                            _ => "".to_string(),
                        };
                        
                        map.insert(column_name, value);
                    }
                    
                    map
                },
            );
            
            match result {
                Ok(data) => Ok(data),
                Err(e) => Err(anyhow!("Query failed: {}", e))
            }
        }).await
            .with_context(|| "MySQL extract data task failed")?;
            
        Ok(result?)
    }
} 