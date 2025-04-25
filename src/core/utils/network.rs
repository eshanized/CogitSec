use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Check if a host is reachable
pub fn is_host_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    if let Ok(addrs) = host.parse::<IpAddr>() {
        let socket = SocketAddr::new(addrs, port);
        TcpStream::connect_timeout(&socket, timeout).is_ok()
    } else {
        // Try to resolve the hostname
        match std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port)) {
            Ok(mut addrs) => {
                // Try to connect to each address
                addrs.any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
            }
            Err(_) => false,
        }
    }
}

/// Parse a CIDR range into a vector of IP addresses
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    // Parse the CIDR notation
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR notation: {}", cidr);
    }
    
    let ip = parts[0].parse::<IpAddr>()
        .with_context(|| format!("Invalid IP address: {}", parts[0]))?;
        
    let prefix_len = parts[1].parse::<u8>()
        .with_context(|| format!("Invalid prefix length: {}", parts[1]))?;
        
    match ip {
        IpAddr::V4(ipv4) => parse_ipv4_cidr(ipv4, prefix_len),
        IpAddr::V6(ipv6) => parse_ipv6_cidr(ipv6, prefix_len),
    }
}

/// Parse an IPv4 CIDR range
fn parse_ipv4_cidr(ip: Ipv4Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    if prefix_len > 32 {
        anyhow::bail!("Invalid IPv4 prefix length: {}", prefix_len);
    }
    
    // Calculate the mask
    let mask = (!0u32) << (32 - prefix_len);
    
    // Calculate the start and end IPs
    let ip_u32 = u32::from(ip) & mask;
    let start = ip_u32;
    let end = ip_u32 | (!mask);
    
    // Generate all IPs in the range
    let mut ips = Vec::with_capacity((end - start + 1) as usize);
    for i in start..=end {
        ips.push(IpAddr::V4(Ipv4Addr::from(i)));
    }
    
    Ok(ips)
}

/// Parse an IPv6 CIDR range
fn parse_ipv6_cidr(ip: Ipv6Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    if prefix_len > 128 {
        anyhow::bail!("Invalid IPv6 prefix length: {}", prefix_len);
    }
    
    // For IPv6, we'll limit to small ranges to avoid excessive memory usage
    if prefix_len < 120 {
        anyhow::bail!("IPv6 CIDR prefix must be >= 120 (too many addresses otherwise)");
    }
    
    // Calculate the mask
    let mask = (!0u128) << (128 - prefix_len);
    
    // Calculate the start and end IPs
    let ip_u128 = u128::from(ip) & mask;
    let start = ip_u128;
    let end = ip_u128 | (!mask);
    
    // Generate all IPs in the range
    let mut ips = Vec::with_capacity((end - start + 1) as usize);
    for i in start..=end {
        ips.push(IpAddr::V6(Ipv6Addr::from(i)));
    }
    
    Ok(ips)
}

/// Perform a port scan on a host
pub fn scan_ports(host: &str, port_range: std::ops::Range<u16>, timeout: Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();
    
    for port in port_range {
        if is_host_reachable(host, port, timeout) {
            open_ports.push(port);
        }
    }
    
    open_ports
} 