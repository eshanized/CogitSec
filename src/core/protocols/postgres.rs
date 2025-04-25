use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler, VulnerabilityResult, VulnerabilitySeverity, ComplianceStandard, MonitoringData};
use anyhow::{Context, Result, anyhow};
use log::{debug, error, warn, info};
use postgres::{Client, Config, NoTls, SimpleQueryMessage, Row};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use chrono::Utc;
use tokio::time;

/// Handler for PostgreSQL authentication
pub struct PostgreSQLHandler;

impl PostgreSQLHandler {
    /// Create a new PostgreSQL handler
    pub fn new() -> Self {
        Self
    }
    
    /// Connect to PostgreSQL server
    fn connect_postgres(
        &self,
        target: &str,
        port: u16,
        username: &str,
        password: &str,
        database: &str,
        timeout: Duration,
    ) -> Result<Client> {
        // Build connection config
        let mut config = Config::new();
        config
            .host(target)
            .port(port)
            .user(username)
            .password(password)
            .connect_timeout(timeout)
            .dbname(database);
            
        // Try to connect
        let client = config.connect(NoTls)
            .with_context(|| format!("Failed to connect to PostgreSQL at {}:{}", target, port))?;
            
        Ok(client)
    }
    
    /// Get PostgreSQL version
    fn get_version(&self, client: &mut Client) -> Result<String> {
        let row = client.query_one("SELECT version()", &[])
            .with_context(|| "Failed to retrieve PostgreSQL version")?;
        
        let version: String = row.get(0);
        Ok(version)
    }
    
    /// Check user privileges
    fn get_user_privileges(&self, client: &mut Client, username: &str) -> Result<Vec<String>> {
        let mut privileges = Vec::new();
        
        // Check if user is superuser
        let query = format!("SELECT rolsuper FROM pg_roles WHERE rolname = '{}'", username);
        let row = client.query_one(&query, &[])
            .with_context(|| format!("Failed to check if user {} is superuser", username))?;
        
        let is_superuser: bool = row.get(0);
        if is_superuser {
            privileges.push("superuser".to_string());
        }
        
        // Check database-specific privileges
        let rows = client.query("SELECT datname FROM pg_database WHERE datistemplate = false", &[])
            .with_context(|| "Failed to retrieve databases")?;
        
        for row in rows {
            let db_name: String = row.get(0);
            privileges.push(format!("database:{}", db_name));
        }
        
        // Check table-specific privileges
        let rows = client.query(
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema') LIMIT 10", 
            &[]
        ).with_context(|| "Failed to retrieve tables")?;
        
        for row in rows {
            let schema: String = row.get(0);
            let table: String = row.get(1);
            privileges.push(format!("table:{}.{}", schema, table));
        }
        
        Ok(privileges)
    }
    
    /// Check if PostgreSQL has weak password policy
    fn check_weak_password_policy(&self, client: &mut Client) -> Result<bool> {
        // Check for users with NULL passwords or username=password
        let rows = client.query(
            "SELECT usename FROM pg_shadow WHERE passwd IS NULL OR passwd = MD5(CONCAT(usename, usename))",
            &[]
        ).with_context(|| "Failed to check for weak passwords")?;
        
        Ok(!rows.is_empty())
    }
    
    /// Check if PostgreSQL allows public access
    fn check_public_access(&self, client: &mut Client) -> Result<bool> {
        // Check pg_hba.conf for 'all' access
        // This can only be done indirectly since we can't read the file directly
        // We'll look for users with broad access rights
        
        // Check if authentication is set to 'trust' which allows unauthenticated access
        let rows = client.query(
            "SELECT 1 FROM pg_hba_file_rules WHERE auth_method = 'trust'",
            &[]
        );
        
        // If we can query the pg_hba_file_rules view, check the result
        if let Ok(trust_rows) = rows {
            if !trust_rows.is_empty() {
                return Ok(true);
            }
        }
        
        // Check for public roles with login capability
        let rows = client.query(
            "SELECT rolname FROM pg_roles WHERE rolcanlogin = true AND rolname IN ('public', 'postgres')",
            &[]
        ).with_context(|| "Failed to check for public roles with login capability")?;
        
        Ok(!rows.is_empty())
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
                            
                            // Get user privileges
                            let mut permissions = Vec::new();
                            
                            // Check if the user is a superuser
                            if let Ok(privileges) = self.get_user_privileges(&mut client, &credentials.username) {
                                permissions.extend(privileges);
                                
                                // Check for administrative privileges
                                if permissions.contains(&"superuser".to_string()) {
                                    permissions.push("administrative".to_string());
                                }
                            }
                            
                            Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                                session_token: None,
                                permissions: Some(permissions),
                            })
                        },
                        Err(e) => {
                            debug!("PostgreSQL authentication succeeded but query failed for user: {}: {}", credentials.username, e);
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
                    debug!("PostgreSQL authentication failed for user: {}: {}", credentials.username, error_msg);
                    
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
            .with_context(|| "PostgreSQL authentication task failed")?;
            
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
        
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<VulnerabilityResult>> {
            let mut vulnerabilities = Vec::new();
            
            // We need credentials to perform PostgreSQL security checks
            if let Some(creds) = credentials_clone {
                match self.connect_postgres(&target, port, &creds.username, &creds.password, "postgres", timeout) {
                    Ok(mut client) => {
                        // Check PostgreSQL version
                        if let Ok(version) = self.get_version(&mut client) {
                            info!("PostgreSQL version: {}", version);
                            
                            // Check for outdated PostgreSQL version
                            if version.contains("PostgreSQL 9.") || version.contains("PostgreSQL 8.") {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "PG-OUTDATED-VERSION".to_string(),
                                    severity: VulnerabilitySeverity::Medium,
                                    description: "Outdated PostgreSQL version detected".to_string(),
                                    is_vulnerable: true,
                                    details: Some(format!("PostgreSQL version: {}", version)),
                                    remediation: Some("Update to PostgreSQL 10 or newer".to_string()),
                                });
                            }
                        }
                        
                        // Check for weak password policy
                        if let Ok(has_weak_passwords) = self.check_weak_password_policy(&mut client) {
                            if has_weak_passwords {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "PG-WEAK-PASSWORDS".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "PostgreSQL users with weak passwords detected".to_string(),
                                    is_vulnerable: true,
                                    details: Some("Some users have null passwords or passwords equal to their username".to_string()),
                                    remediation: Some("Enforce strong password policy for all PostgreSQL users".to_string()),
                                });
                            }
                        }
                        
                        // Check for public access
                        if let Ok(has_public_access) = self.check_public_access(&mut client) {
                            if has_public_access {
                                vulnerabilities.push(VulnerabilityResult {
                                    id: "PG-PUBLIC-ACCESS".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "PostgreSQL allows public/unauthenticated access".to_string(),
                                    is_vulnerable: true,
                                    details: Some("The PostgreSQL server has 'trust' authentication method or public roles with login capability".to_string()),
                                    remediation: Some("Configure pg_hba.conf to require authentication for all connections".to_string()),
                                });
                            }
                        }
                        
                        // Check for SSL enforcement
                        if !_use_ssl {
                            // Try to check if SSL is required
                            if let Ok(rows) = client.query("SHOW ssl", &[]) {
                                if !rows.is_empty() {
                                    let ssl_on: String = rows[0].get(0);
                                    if ssl_on != "on" {
                                        vulnerabilities.push(VulnerabilityResult {
                                            id: "PG-NO-SSL".to_string(),
                                            severity: VulnerabilitySeverity::Medium,
                                            description: "PostgreSQL not configured to use SSL".to_string(),
                                            is_vulnerable: true,
                                            details: Some("Communications with the database are not encrypted".to_string()),
                                            remediation: Some("Configure PostgreSQL to use SSL and set ssl = on in postgresql.conf".to_string()),
                                        });
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        vulnerabilities.push(VulnerabilityResult {
                            id: "PG-CONNECTION-FAILED".to_string(),
                            severity: VulnerabilitySeverity::Info,
                            description: "Could not connect to PostgreSQL server for security scan".to_string(),
                            is_vulnerable: false,
                            details: Some(format!("Connection error: {}", e)),
                            remediation: None,
                        });
                    }
                }
            } else {
                vulnerabilities.push(VulnerabilityResult {
                    id: "PG-NO-CREDENTIALS".to_string(),
                    severity: VulnerabilitySeverity::Info,
                    description: "Could not perform PostgreSQL security scan without credentials".to_string(),
                    is_vulnerable: false,
                    details: Some("Credentials are required for PostgreSQL security scanning".to_string()),
                    remediation: None,
                });
            }
            
            Ok(vulnerabilities)
        }).await
            .with_context(|| "PostgreSQL security scan task failed")?;
            
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
            
            // We need credentials to perform PostgreSQL compliance checks
            if let Some(creds) = credentials_clone {
                if let Ok(mut client) = self.connect_postgres(&target, port, &creds.username, &creds.password, "postgres", timeout) {
                    let version = self.get_version(&mut client).unwrap_or_default();
                    let has_weak_passwords = self.check_weak_password_policy(&mut client).unwrap_or(true);
                    let has_public_access = self.check_public_access(&mut client).unwrap_or(true);
                    
                    // Check SSL status
                    let ssl_enabled = use_ssl || {
                        if let Ok(rows) = client.query("SHOW ssl", &[]) {
                            if !rows.is_empty() {
                                let ssl_on: String = rows[0].get(0);
                                ssl_on == "on"
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };
                    
                    match standard {
                        ComplianceStandard::PCI_DSS => {
                            // PCI DSS Requirement 2.2.1: Change vendor defaults
                            compliance_results.insert("PCI-DSS-Req-2.2.1".to_string(), !has_weak_passwords);
                            
                            // PCI DSS Requirement 4.1: Use strong cryptography and security protocols
                            compliance_results.insert("PCI-DSS-Req-4.1".to_string(), ssl_enabled);
                            
                            // PCI DSS Requirement 8.2: Strong authentication
                            compliance_results.insert("PCI-DSS-Req-8.2".to_string(), !has_weak_passwords);
                            
                            // PCI DSS Requirement 1.3: Network security
                            compliance_results.insert("PCI-DSS-Req-1.3".to_string(), !has_public_access);
                        },
                        ComplianceStandard::GDPR => {
                            // GDPR Article 32: Security of processing
                            let data_protection = !has_weak_passwords && ssl_enabled && !has_public_access;
                            compliance_results.insert("GDPR-Data-Protection".to_string(), data_protection);
                            
                            // GDPR Article 25: Data protection by design
                            compliance_results.insert("GDPR-Data-Protection-By-Design".to_string(), ssl_enabled && !has_public_access);
                        },
                        _ => {
                            // General database security baseline
                            let secure = !has_weak_passwords && !has_public_access && ssl_enabled;
                            compliance_results.insert("Database-Security-Baseline".to_string(), secure);
                            
                            // Current version
                            let supported_version = !version.contains("PostgreSQL 9.") && !version.contains("PostgreSQL 8.");
                            compliance_results.insert("Current-Version".to_string(), supported_version);
                        }
                    }
                }
            }
            
            Ok(compliance_results)
        }).await
            .with_context(|| "PostgreSQL compliance check task failed")?;
            
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
                    match self.connect_postgres(&target_clone, port, &creds.username, &creds.password, "postgres", Duration::from_secs(5)) {
                        Ok(mut client) => {
                            let query_start = Instant::now();
                            
                            // Run a statistics query to measure database activity
                            match client.query("SELECT count(*) FROM pg_stat_activity", &[]) {
                                Ok(rows) => {
                                    if !rows.is_empty() {
                                        let count: i64 = rows[0].get(0);
                                        let query_time = query_start.elapsed().as_millis() as u64;
                                        let total_time = start.elapsed().as_millis() as u64;
                                        
                                        event_data.event_type = "query_success".to_string();
                                        event_data.latency_ms = Some(total_time);
                                        event_data.bytes_transferred = Some(8); // Size of i64
                                        event_data.info = Some(format!("Active connections: {}", count));
                                    }
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
                    event_data.error = Some("No credentials provided for PostgreSQL monitoring".to_string());
                }
                
                Ok(event_data)
            }).await
                .with_context(|| "PostgreSQL monitoring task failed")?;
                
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
            let mut client = self.connect_postgres(&target, port, &credentials.username, &credentials.password, "postgres", timeout)?;
            
            // Get PostgreSQL version
            if let Ok(version) = self.get_version(&mut client) {
                resources.push(format!("version:{}", version));
            }
            
            // Get databases
            let rows = client.query("SELECT datname FROM pg_database WHERE datistemplate = false", &[])
                .with_context(|| "Failed to retrieve databases")?;
            
            for row in rows {
                let db_name: String = row.get(0);
                resources.push(format!("database:{}", db_name));
                
                // Connect to each database to list schemas and tables
                if let Ok(mut db_client) = self.connect_postgres(&target, port, &credentials.username, &credentials.password, &db_name, timeout) {
                    // Get schemas
                    let schema_rows = db_client.query(
                        "SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema'", 
                        &[]
                    ).unwrap_or_default();
                    
                    for schema_row in schema_rows {
                        let schema_name: String = schema_row.get(0);
                        resources.push(format!("schema:{}.{}", db_name, schema_name));
                        
                        // Get tables in this schema
                        let table_rows = db_client.query(
                            &format!("SELECT tablename FROM pg_tables WHERE schemaname = '{}'", schema_name),
                            &[]
                        ).unwrap_or_default();
                        
                        for table_row in table_rows {
                            let table_name: String = table_row.get(0);
                            resources.push(format!("table:{}.{}.{}", db_name, schema_name, table_name));
                        }
                    }
                }
            }
            
            // Get users/roles
            let rows = client.query("SELECT rolname, rolsuper FROM pg_roles WHERE rolcanlogin = true", &[])
                .with_context(|| "Failed to retrieve users")?;
            
            for row in rows {
                let user_name: String = row.get(0);
                let is_superuser: bool = row.get(1);
                let user_type = if is_superuser { "superuser" } else { "user" };
                resources.push(format!("{}:{}", user_type, user_name));
            }
            
            Ok(resources)
        }).await
            .with_context(|| "PostgreSQL enumerate resources task failed")?;
            
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
            // Check if the query seems to be a database name instead of a SQL query
            let (db_name, sql_query) = if !query.to_lowercase().contains("select") && !query.contains(" ") {
                // This might be a database name - we'll list tables
                (query.clone(), "SELECT table_schema, table_name FROM information_schema.tables ORDER BY table_schema, table_name".to_string())
            } else {
                // This is a SQL query
                ("postgres".to_string(), query.clone())
            };
            
            // Connect to the server with specified database
            let mut client = self.connect_postgres(&target, port, &credentials.username, &credentials.password, &db_name, timeout)?;
            
            // Run the query and collect results
            let rows = client.query(&sql_query, &[])
                .with_context(|| format!("Failed to execute query: {}", sql_query))?;
            
            let mut data = Vec::new();
            
            for row in rows {
                let mut row_data = HashMap::new();
                
                for (i, column) in row.columns().iter().enumerate() {
                    let column_name = column.name();
                    
                    // Get value as string representation
                    let value = match row.try_get::<_, Option<String>>(i) {
                        Ok(Some(val)) => val,
                        Ok(None) => "NULL".to_string(),
                        Err(_) => {
                            // Try other types
                            if let Ok(val) = row.try_get::<_, i32>(i) {
                                val.to_string()
                            } else if let Ok(val) = row.try_get::<_, i64>(i) {
                                val.to_string()
                            } else if let Ok(val) = row.try_get::<_, f64>(i) {
                                val.to_string()
                            } else if let Ok(val) = row.try_get::<_, bool>(i) {
                                val.to_string()
                            } else {
                                "UNKNOWN_TYPE".to_string()
                            }
                        }
                    };
                    
                    row_data.insert(column_name.to_string(), value);
                }
                
                data.push(row_data);
            }
            
            Ok(data)
        }).await
            .with_context(|| "PostgreSQL extract data task failed")?;
            
        Ok(result?)
    }
} 