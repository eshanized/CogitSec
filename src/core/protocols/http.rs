use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler, VulnerabilityResult, VulnerabilitySeverity, ComplianceStandard, MonitoringData};
use anyhow::{Context, Result, anyhow};
use log::{debug, error, warn, info};
use reqwest::{Client, ClientBuilder, StatusCode, Response, header::{HeaderMap, HeaderValue, HeaderName, AUTHORIZATION, USER_AGENT, SERVER}};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use chrono::Utc;
use tokio::time;

/// Handler for HTTP authentication
pub struct HTTPHandler {
    /// The HTTP client
    client: Client,
}

impl HTTPHandler {
    /// Create a new HTTP handler
    pub fn new() -> Self {
        Self {
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }
    
    /// Process form fields from options
    fn get_form_fields(&self, options: &HashMap<String, String>) -> HashMap<String, String> {
        let mut form_fields = HashMap::new();
        
        // Look for form fields in options
        for (key, value) in options.iter() {
            if key.starts_with("form_") {
                let field_name = key.strip_prefix("form_").unwrap();
                form_fields.insert(field_name.to_string(), value.clone());
            }
        }
        
        form_fields
    }
}

#[async_trait]
impl ProtocolHandler for HTTPHandler {
    fn protocol_type(&self) -> Protocol {
        Protocol::HTTP
    }
    
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        credentials: &Credentials,
        timeout: Duration,
        use_ssl: bool,
        options: &HashMap<String, String>,
    ) -> Result<AuthResult> {
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", 
            protocol, 
            target, 
            port,
            options.get("path").unwrap_or(&String::from("/"))
        );
        
        debug!("Attempting HTTP authentication to {}", url);
        
        // Use local variables for string values in unwrap_or method
        let default_auth_method = String::from("basic");
        let auth_method = options.get("auth_method").unwrap_or(&default_auth_method);
        
        // Set timeout
        let client = self.client.clone();
        
        match auth_method.to_lowercase().as_str() {
            "basic" => {
                // Use HTTP Basic authentication
                let response = client
                    .get(&url)
                    .basic_auth(&credentials.username, Some(&credentials.password))
                    .timeout(timeout)
                    .send()
                    .await
                    .with_context(|| format!("Failed to send HTTP request to {}", url))?;
                
                let status = response.status();
                
                if status == StatusCode::OK || status == StatusCode::FOUND {
                    debug!("HTTP Basic authentication successful for user: {}", credentials.username);
                    Ok(AuthResult {
                        success: true,
                        error: None,
                        info: Some(format!("Successfully authenticated as {}", credentials.username)),
                    })
                } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    debug!("HTTP Basic authentication failed for user: {}", credentials.username);
                    Ok(AuthResult {
                        success: false,
                        error: Some(format!("Authentication failed with status: {}", status)),
                        info: None,
                    })
                } else {
                    warn!("HTTP Basic authentication got unexpected status: {}", status);
                    Ok(AuthResult {
                        success: false,
                        error: Some(format!("Unexpected status code: {}", status)),
                        info: None,
                    })
                }
            },
            "form" => {
                // Use form-based authentication
                let default_username_field = String::from("username");
                let username_field = options.get("username_field").unwrap_or(&default_username_field);
                
                let default_password_field = String::from("password");
                let password_field = options.get("password_field").unwrap_or(&default_password_field);
                
                // Get any additional form fields
                let mut form_data = self.get_form_fields(options);
                
                // Add credentials
                form_data.insert(username_field.clone(), credentials.username.clone());
                form_data.insert(password_field.clone(), credentials.password.clone());
                
                // Send form POST
                let response = client
                    .post(&url)
                    .form(&form_data)
                    .timeout(timeout)
                    .send()
                    .await
                    .with_context(|| format!("Failed to send HTTP form request to {}", url))?;
                
                let status = response.status();
                
                // Check for success indicators
                if status == StatusCode::OK || status == StatusCode::FOUND {
                    // Check for failure indicators in the response
                    // This is heuristic-based since form authentication success/failure is application-dependent
                    let body = response.text().await
                        .with_context(|| "Failed to read HTTP response body")?;
                    
                    let success_pattern = options.get("success_pattern");
                    let failure_pattern = options.get("failure_pattern");
                    
                    if let Some(pattern) = failure_pattern {
                        if body.contains(pattern) {
                            debug!("HTTP Form authentication failed for user: {} (matched failure pattern)", credentials.username);
                            return Ok(AuthResult {
                                success: false,
                                error: Some("Authentication failed (matched failure pattern)".to_string()),
                                info: None,
                            });
                        }
                    }
                    
                    if let Some(pattern) = success_pattern {
                        if body.contains(pattern) {
                            debug!("HTTP Form authentication successful for user: {} (matched success pattern)", credentials.username);
                            return Ok(AuthResult {
                                success: true,
                                error: None,
                                info: Some(format!("Successfully authenticated as {}", credentials.username)),
                            });
                        } else {
                            debug!("HTTP Form authentication failed for user: {} (didn't match success pattern)", credentials.username);
                            return Ok(AuthResult {
                                success: false,
                                error: Some("Authentication failed (didn't match success pattern)".to_string()),
                                info: None,
                            });
                        }
                    }
                    
                    // Default to assuming success if we got a 200/302 and no patterns were specified
                    debug!("HTTP Form authentication likely successful for user: {}", credentials.username);
                    Ok(AuthResult {
                        success: true,
                        error: None,
                        info: Some(format!("Likely authenticated as {} (based on status code)", credentials.username)),
                    })
                } else {
                    debug!("HTTP Form authentication failed for user: {} (status code: {})", credentials.username, status);
                    Ok(AuthResult {
                        success: false,
                        error: Some(format!("Authentication failed with status: {}", status)),
                        info: None,
                    })
                }
            },
            _ => {
                error!("Unsupported HTTP authentication method: {}", auth_method);
                Ok(AuthResult {
                    success: false,
                    error: Some(format!("Unsupported authentication method: {}", auth_method)),
                    info: None,
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
        options: &HashMap<String, String>,
    ) -> Result<Vec<VulnerabilityResult>> {
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, target, port);
        let mut vulnerabilities = Vec::new();
        
        // Create a client that ignores certificate errors for scanning purposes
        let client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
        
        // Check for common security headers
        let response = match client.get(&base_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(vec![VulnerabilityResult {
                    id: "HTTP-CONNECTION-FAILED".to_string(),
                    severity: VulnerabilitySeverity::Info,
                    description: "Could not connect to HTTP server".to_string(),
                    is_vulnerable: false,
                    details: Some(format!("Connection error: {}", e)),
                    remediation: None,
                }]);
            }
        };
        
        // Check for missing security headers
        let headers_to_check = [
            ("X-XSS-Protection", "Missing XSS Protection Header", VulnerabilitySeverity::Medium),
            ("X-Content-Type-Options", "Missing Content Type Options Header", VulnerabilitySeverity::Low),
            ("X-Frame-Options", "Missing Frame Options Header", VulnerabilitySeverity::Medium),
            ("Strict-Transport-Security", "Missing HSTS Header", VulnerabilitySeverity::High),
            ("Content-Security-Policy", "Missing Content Security Policy", VulnerabilitySeverity::Medium),
        ];
        
        let headers = response.headers();
        
        for (header, description, severity) in &headers_to_check {
            if !headers.contains_key(*header) {
                vulnerabilities.push(VulnerabilityResult {
                    id: format!("HTTP-MISSING-{}", header),
                    severity: *severity,
                    description: description.to_string(),
                    is_vulnerable: true,
                    details: Some(format!("The {} header is missing which can expose the site to various attacks", header)),
                    remediation: Some(format!("Add the appropriate {} header to the HTTP response", header)),
                });
            }
        }
        
        // Check for server header disclosure
        if let Some(server) = headers.get(SERVER) {
            if let Ok(server_str) = server.to_str() {
                if !server_str.is_empty() {
                    vulnerabilities.push(VulnerabilityResult {
                        id: "HTTP-SERVER-DISCLOSURE".to_string(),
                        severity: VulnerabilitySeverity::Low,
                        description: "Server header discloses version information".to_string(),
                        is_vulnerable: true,
                        details: Some(format!("Server header: {}", server_str)),
                        remediation: Some("Configure the web server to omit or sanitize the Server header".to_string()),
                    });
                }
            }
        }
        
        // Check TLS/SSL if applicable
        if use_ssl || protocol == "https" {
            // Simple check to see if SSL is properly configured
            if let Err(_) = client
                .get(&base_url)
                .send()
                .await
            {
                vulnerabilities.push(VulnerabilityResult {
                    id: "HTTP-SSL-MISCONFIGURATION".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: "SSL/TLS appears to be misconfigured".to_string(),
                    is_vulnerable: true,
                    details: Some("Could not establish a secure connection".to_string()),
                    remediation: Some("Check SSL/TLS configuration and certificates".to_string()),
                });
            }
        } else if port == 80 {
            // Check if HTTPS is available when connecting to HTTP
            let https_url = format!("https://{}:{}", target, 443);
            if client.get(&https_url).send().await.is_ok() {
                vulnerabilities.push(VulnerabilityResult {
                    id: "HTTP-NO-HTTPS-REDIRECT".to_string(),
                    severity: VulnerabilitySeverity::Medium,
                    description: "Site is available over HTTP without HTTPS redirect".to_string(),
                    is_vulnerable: true,
                    details: Some("The site is accessible via both HTTP and HTTPS without redirection".to_string()),
                    remediation: Some("Configure HTTP to redirect to HTTPS".to_string()),
                });
            }
        }
        
        // Check for common vulnerable paths
        let vulnerable_paths = [
            "/admin", "/login", "/wp-admin", "/phpmyadmin", "/.git", "/.env", 
            "/api", "/api/v1", "/console", "/server-status", "/phpinfo.php"
        ];
        
        for path in vulnerable_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status() != StatusCode::NOT_FOUND {
                    vulnerabilities.push(VulnerabilityResult {
                        id: format!("HTTP-SENSITIVE-PATH-{}", path.replace("/", "")),
                        severity: VulnerabilitySeverity::Medium,
                        description: format!("Sensitive path {} is accessible", path),
                        is_vulnerable: true,
                        details: Some(format!("The path {} returned status code {}", path, resp.status())),
                        remediation: Some(format!("Restrict access to {} or remove if not required", path)),
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
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
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, target, port);
        let mut compliance_results = HashMap::new();
        
        // Create a client that ignores certificate errors for scanning purposes
        let client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
            
        // Try to connect to the server
        let response = match client.get(&base_url).send().await {
            Ok(resp) => resp,
            Err(_) => {
                // If connection fails, return non-compliant for everything
                match standard {
                    ComplianceStandard::PCI_DSS => {
                        compliance_results.insert("PCI-DSS-Req-4.1".to_string(), false);
                        compliance_results.insert("PCI-DSS-Req-6.5.4".to_string(), false);
                        compliance_results.insert("PCI-DSS-Req-6.6".to_string(), false);
                    },
                    ComplianceStandard::GDPR => {
                        compliance_results.insert("GDPR-Art-32-Security".to_string(), false);
                    },
                    ComplianceStandard::HIPAA => {
                        compliance_results.insert("HIPAA-Security-Technical-Safeguards".to_string(), false);
                    },
                    _ => {
                        compliance_results.insert("Web-Security-Baseline".to_string(), false);
                    }
                }
                return Ok(compliance_results);
            }
        };
        
        let headers = response.headers();
        
        match standard {
            ComplianceStandard::PCI_DSS => {
                // PCI-DSS Requirement 4.1: Strong cryptography and security protocols
                compliance_results.insert("PCI-DSS-Req-4.1".to_string(), 
                    protocol == "https" && headers.contains_key("Strict-Transport-Security"));
                
                // PCI-DSS Requirement 6.5.4: Insecure communications
                compliance_results.insert("PCI-DSS-Req-6.5.4".to_string(), 
                    protocol == "https" && headers.contains_key("Content-Security-Policy"));
                
                // PCI-DSS Requirement 6.6: Web application security
                let has_security_headers = headers.contains_key("X-XSS-Protection") && 
                                          headers.contains_key("X-Content-Type-Options") &&
                                          headers.contains_key("X-Frame-Options");
                compliance_results.insert("PCI-DSS-Req-6.6".to_string(), has_security_headers);
            },
            ComplianceStandard::GDPR => {
                // GDPR Article 32: Security of processing
                let has_secure_transport = protocol == "https" && headers.contains_key("Strict-Transport-Security");
                let has_security_headers = headers.contains_key("Content-Security-Policy") &&
                                          headers.contains_key("X-Content-Type-Options");
                                          
                compliance_results.insert("GDPR-Art-32-Security".to_string(), 
                    has_secure_transport && has_security_headers);
            },
            ComplianceStandard::HIPAA => {
                // HIPAA Technical Safeguards
                let has_secure_transport = protocol == "https";
                let has_security_headers = headers.contains_key("Strict-Transport-Security") &&
                                          headers.contains_key("X-XSS-Protection") &&
                                          headers.contains_key("X-Content-Type-Options");
                                          
                compliance_results.insert("HIPAA-Security-Technical-Safeguards".to_string(),
                    has_secure_transport && has_security_headers);
            },
            _ => {
                // Generic web security baseline
                let has_secure_transport = protocol == "https";
                let has_security_headers = headers.contains_key("Content-Security-Policy") ||
                                          (headers.contains_key("X-XSS-Protection") && 
                                           headers.contains_key("X-Content-Type-Options") &&
                                           headers.contains_key("X-Frame-Options"));
                
                compliance_results.insert("Web-Security-Baseline".to_string(),
                    has_secure_transport && has_security_headers);
            }
        }
        
        Ok(compliance_results)
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
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, target, port);
        let mut monitoring_data = Vec::new();
        
        let end_time = Instant::now() + duration;
        
        while Instant::now() < end_time {
            let now = Utc::now();
            let start = Instant::now();
            
            let client = ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .build()?;
                
            let result = client.get(&base_url).send().await;
            let latency = start.elapsed().as_millis() as u64;
            
            let mut event_data = MonitoringData {
                timestamp: now,
                event_type: "http_request".to_string(),
                latency_ms: Some(latency),
                bytes_transferred: None,
                error: None,
            };
            
            match result {
                Ok(response) => {
                    // Get the response size if available
                    if let Some(content_length) = response.content_length() {
                        event_data.bytes_transferred = Some(content_length);
                    }
                    
                    // Store status code in event type
                    event_data.event_type = format!("http_status_{}", response.status().as_u16());
                    
                    // If response was not successful, add error details
                    if !response.status().is_success() {
                        event_data.error = Some(format!("HTTP status code: {}", response.status()));
                    }
                },
                Err(e) => {
                    event_data.event_type = "http_connection_failed".to_string();
                    event_data.error = Some(e.to_string());
                }
            }
            
            monitoring_data.push(event_data);
            
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
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, target, port);
        let mut resources = Vec::new();
        
        let client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
            
        // Common paths to check
        let paths_to_check = [
            "/", "/robots.txt", "/sitemap.xml", "/api", "/admin", "/login", 
            "/wp-content", "/assets", "/images", "/css", "/js", "/docs"
        ];
        
        for path in paths_to_check {
            let url = format!("{}{}", base_url, path);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    resources.push(format!("url:{}{}", base_url, path));
                }
            }
        }
        
        // Try to authenticate if credentials are provided
        if credentials.username.contains('@') {
            // Likely a web application login, not API credentials
            // For demonstration, just add this as information
            resources.push(format!("email:{}", credentials.username));
        } else {
            resources.push(format!("username:{}", credentials.username));
        }
        
        // Extract links from the main page
        if let Ok(resp) = client.get(&base_url).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    // Very basic link extraction with a simple regex-like approach
                    let text_lower = text.to_lowercase();
                    for pattern in ["href=\"/", "href=\"http", "src=\"/", "src=\"http"] {
                        let mut pos = 0;
                        while let Some(idx) = text_lower[pos..].find(pattern) {
                            pos += idx + pattern.len();
                            
                            // Extract until the closing quote
                            if let Some(end_idx) = text_lower[pos..].find("\"") {
                                let url = &text[pos..pos+end_idx];
                                if url.starts_with("http") {
                                    resources.push(format!("url:{}", url));
                                } else if url.starts_with("/") {
                                    resources.push(format!("url:{}{}", base_url, url));
                                }
                                pos += end_idx;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Deduplicate
        resources.sort();
        resources.dedup();
        
        Ok(resources)
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
        let protocol = if use_ssl || port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, target, port);
        
        let client = ClientBuilder::new()
            .timeout(timeout)
            .build()?;
            
        // Determine if this is a path or a full URL
        let url = if query.starts_with("http") {
            query.to_string()
        } else {
            format!("{}{}", base_url, query)
        };
        
        // Create a client and set auth if needed
        let request = client.get(&url);
        
        // Check if basic auth should be used
        let request = request.basic_auth(&credentials.username, Some(&credentials.password));
        
        // Send the request
        let response = request.send().await
            .with_context(|| format!("Failed to send HTTP request to {}", url))?;
            
        if !response.status().is_success() {
            return Err(anyhow!("HTTP request failed with status: {}", response.status()));
        }
        
        // Try to parse as JSON
        if let Ok(json) = response.json::<serde_json::Value>().await {
            match json {
                serde_json::Value::Array(items) => {
                    let mut result = Vec::new();
                    
                    for item in items {
                        if let serde_json::Value::Object(obj) = item {
                            let mut row = HashMap::new();
                            
                            for (key, value) in obj {
                                row.insert(key, value.to_string());
                            }
                            
                            result.push(row);
                        }
                    }
                    
                    Ok(result)
                },
                serde_json::Value::Object(obj) => {
                    let mut row = HashMap::new();
                    
                    for (key, value) in obj {
                        row.insert(key, value.to_string());
                    }
                    
                    Ok(vec![row])
                },
                _ => {
                    Err(anyhow!("Response is not a JSON object or array"))
                }
            }
        } else {
            // Not JSON, return as plain text
            let text = response.text().await?;
            let mut row = HashMap::new();
            row.insert("content".to_string(), text);
            Ok(vec![row])
        }
    }
} 