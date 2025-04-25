use crate::core::attack::{AttackConfig, AttackResult};
use anyhow::{Context, Result};
use chrono::prelude::*;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Format for report export
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// CSV format
    CSV,
    
    /// JSON format
    JSON,
    
    /// Plain text format
    Text,
    
    /// HTML format
    HTML,
}

/// Generate a report from attack results
pub fn generate_report(
    format: ReportFormat,
    config: &AttackConfig,
    results: &[AttackResult],
    path: impl AsRef<Path>,
) -> Result<()> {
    match format {
        ReportFormat::CSV => generate_csv_report(config, results, path),
        ReportFormat::JSON => generate_json_report(config, results, path),
        ReportFormat::Text => generate_text_report(config, results, path),
        ReportFormat::HTML => generate_html_report(config, results, path),
    }
}

/// Generate a CSV report
fn generate_csv_report(
    config: &AttackConfig,
    results: &[AttackResult],
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut file = File::create(path.as_ref())
        .with_context(|| format!("Failed to create report file {:?}", path.as_ref()))?;
        
    // Write header
    writeln!(file, "Target,Port,Protocol,Username,Password,Success,Error,Timestamp")?;
    
    // Write results
    for result in results {
        let error = result.error.as_deref().unwrap_or("").replace(',', ";");
        
        writeln!(
            file,
            "{},{},{},{},{},{},{},{}",
            result.target,
            result.port,
            result.protocol,
            result.username,
            result.password,
            result.success,
            error,
            result.timestamp.to_rfc3339(),
        )?;
    }
    
    Ok(())
}

/// Generate a JSON report
fn generate_json_report(
    config: &AttackConfig,
    results: &[AttackResult],
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut file = File::create(path.as_ref())
        .with_context(|| format!("Failed to create report file {:?}", path.as_ref()))?;
        
    let report = serde_json::json!({
        "target": config.target,
        "port": config.port,
        "protocol": config.protocol,
        "timestamp": Utc::now().to_rfc3339(),
        "results": results,
    });
    
    let json = serde_json::to_string_pretty(&report)?;
    file.write_all(json.as_bytes())?;
    
    Ok(())
}

/// Generate a text report
fn generate_text_report(
    config: &AttackConfig,
    results: &[AttackResult],
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut file = File::create(path.as_ref())
        .with_context(|| format!("Failed to create report file {:?}", path.as_ref()))?;
        
    // Write header
    writeln!(file, "CogitSec Attack Report")?;
    writeln!(file, "======================")?;
    writeln!(file)?;
    writeln!(file, "Target: {}", config.target)?;
    writeln!(file, "Port: {}", config.port)?;
    writeln!(file, "Protocol: {}", config.protocol)?;
    writeln!(file, "Date: {}", Utc::now().to_rfc3339())?;
    writeln!(file)?;
    
    // Write summary
    let successful = results.iter().filter(|r| r.success).count();
    writeln!(file, "Summary:")?;
    writeln!(file, "- Total attempts: {}", results.len())?;
    writeln!(file, "- Successful attempts: {}", successful)?;
    writeln!(file, "- Failed attempts: {}", results.len() - successful)?;
    writeln!(file)?;
    
    // Write successful results
    writeln!(file, "Successful Credentials:")?;
    writeln!(file, "-----------------------")?;
    
    if successful == 0 {
        writeln!(file, "No successful authentications.")?;
    } else {
        for result in results.iter().filter(|r| r.success) {
            writeln!(
                file,
                "Username: {}, Password: {}, Timestamp: {}",
                result.username,
                result.password,
                result.timestamp.to_rfc3339(),
            )?;
        }
    }
    
    writeln!(file)?;
    
    Ok(())
}

/// Generate an HTML report
fn generate_html_report(
    config: &AttackConfig,
    results: &[AttackResult],
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut file = File::create(path.as_ref())
        .with_context(|| format!("Failed to create report file {:?}", path.as_ref()))?;
        
    // Count successful attempts
    let successful = results.iter().filter(|r| r.success).count();
    
    // Generate HTML
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CogitSec Attack Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
        }}
        h1, h2 {{
            color: #333;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .success {{
            color: green;
        }}
        .failure {{
            color: red;
        }}
        .summary {{
            margin: 20px 0;
            padding: 10px;
            background-color: #f9f9f9;
            border-left: 4px solid #ccc;
        }}
    </style>
</head>
<body>
    <h1>CogitSec Attack Report</h1>
    
    <h2>Target Information</h2>
    <table>
        <tr><th>Target</th><td>{target}</td></tr>
        <tr><th>Port</th><td>{port}</td></tr>
        <tr><th>Protocol</th><td>{protocol}</td></tr>
        <tr><th>Date</th><td>{date}</td></tr>
    </table>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total attempts: {total}</p>
        <p>Successful attempts: <span class="success">{successful}</span></p>
        <p>Failed attempts: <span class="failure">{failed}</span></p>
    </div>
    
    <h2>Successful Credentials</h2>
    {successful_table}
    
    <h2>Failed Attempts</h2>
    {failed_table}
</body>
</html>"#,
        target = config.target,
        port = config.port,
        protocol = config.protocol,
        date = Utc::now().to_rfc3339(),
        total = results.len(),
        successful = successful,
        failed = results.len() - successful,
        successful_table = if successful == 0 {
            "<p>No successful authentications.</p>".to_string()
        } else {
            let mut table = String::from(
                "<table>\n<tr><th>Username</th><th>Password</th><th>Timestamp</th></tr>\n"
            );
            
            for result in results.iter().filter(|r| r.success) {
                table.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    result.username,
                    result.password,
                    result.timestamp.to_rfc3339(),
                ));
            }
            
            table.push_str("</table>");
            table
        },
        failed_table = if results.len() - successful == 0 {
            "<p>No failed authentications.</p>".to_string()
        } else {
            let mut table = String::from(
                "<table>\n<tr><th>Username</th><th>Password</th><th>Timestamp</th><th>Error</th></tr>\n"
            );
            
            for result in results.iter().filter(|r| !r.success) {
                table.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    result.username,
                    result.password,
                    result.timestamp.to_rfc3339(),
                    result.error.as_deref().unwrap_or(""),
                ));
            }
            
            table.push_str("</table>");
            table
        },
    );
    
    file.write_all(html.as_bytes())?;
    
    Ok(())
} 