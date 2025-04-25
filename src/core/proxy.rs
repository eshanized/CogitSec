use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Type of proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyType {
    /// HTTP proxy
    HTTP,
    
    /// SOCKS4 proxy
    SOCKS4,
    
    /// SOCKS5 proxy
    SOCKS5,
    
    /// TOR proxy
    TOR,
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyType::HTTP => write!(f, "HTTP"),
            ProxyType::SOCKS4 => write!(f, "SOCKS4"),
            ProxyType::SOCKS5 => write!(f, "SOCKS5"),
            ProxyType::TOR => write!(f, "TOR"),
        }
    }
}

/// Represents a proxy server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    /// Type of proxy
    pub proxy_type: ProxyType,
    
    /// Host of the proxy server
    pub host: String,
    
    /// Port of the proxy server
    pub port: u16,
    
    /// Username for authentication (if required)
    pub username: Option<String>,
    
    /// Password for authentication (if required)
    pub password: Option<String>,
}

impl Proxy {
    /// Create a new proxy
    pub fn new(
        proxy_type: ProxyType,
        host: impl Into<String>,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            proxy_type,
            host: host.into(),
            port,
            username,
            password,
        }
    }
    
    /// Create a new HTTP proxy
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self::new(ProxyType::HTTP, host, port, None, None)
    }
    
    /// Create a new SOCKS5 proxy
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self::new(ProxyType::SOCKS5, host, port, None, None)
    }
    
    /// Create a new TOR proxy
    pub fn tor(port: u16) -> Self {
        Self::new(ProxyType::TOR, "127.0.0.1", port, None, None)
    }
    
    /// Set authentication credentials
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
    
    /// Convert to a URL string
    pub fn to_url(&self) -> String {
        let scheme = match self.proxy_type {
            ProxyType::HTTP => "http",
            ProxyType::SOCKS4 => "socks4",
            ProxyType::SOCKS5 => "socks5",
            ProxyType::TOR => "socks5",
        };
        
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            format!("{}://{}:{}@{}:{}", scheme, username, password, self.host, self.port)
        } else {
            format!("{}://{}:{}", scheme, self.host, self.port)
        }
    }
}

/// A chain of proxies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChain {
    /// List of proxies in the chain
    pub proxies: Vec<Proxy>,
}

impl ProxyChain {
    /// Create a new empty proxy chain
    pub fn new() -> Self {
        Self {
            proxies: Vec::new(),
        }
    }
    
    /// Add a proxy to the chain
    pub fn add_proxy(&mut self, proxy: Proxy) {
        self.proxies.push(proxy);
    }
    
    /// Check if the proxy chain is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }
    
    /// Get the number of proxies in the chain
    pub fn len(&self) -> usize {
        self.proxies.len()
    }
} 