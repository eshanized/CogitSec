use crate::core::credentials::Credentials;
use crate::core::protocols::{AuthResult, Protocol, ProtocolHandler};
use anyhow::{Context, Result};
use log::{debug, error, warn};
use reqwest::{Client, ClientBuilder, StatusCode};
use std::collections::HashMap;
use std::time::Duration;
use async_trait::async_trait;

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
} 