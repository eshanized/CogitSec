use crate::core::attack::{AttackConfig, AttackResult};
use anyhow::{Context, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;

/// Format for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    /// Plain text format
    TXT,
    /// JSON format
    JSON,
    /// CSV format
    CSV,
    /// HTML format
    HTML,
    /// Markdown format
    MD,
}

impl ReportFormat {
    /// Get the file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::TXT => "txt",
            ReportFormat::JSON => "json",
            ReportFormat::CSV => "csv",
            ReportFormat::HTML => "html",
            ReportFormat::MD => "md",
        }
    }
}

/// Report summarizing attack results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Title of the report
    pub title: String,
    
    /// When the report was generated
    pub generated_at: DateTime<Utc>,
    
    /// Results included in the report
    pub results: Vec<AttackResult>,
}

impl Report {
    /// Create a new report
    pub fn new(title: String, results: Vec<AttackResult>) -> Self {
        Self {
            title,
            generated_at: Utc::now(),
            results,
        }
    }
    
    /// Generate a report file
    pub fn generate(&self, path: &Path, format: ReportFormat) -> Result<()> {
        match format {
            ReportFormat::TXT => self.generate_txt(path),
            ReportFormat::JSON => self.generate_json(path),
            ReportFormat::CSV => self.generate_csv(path),
            ReportFormat::HTML => self.generate_html(path),
            ReportFormat::MD => self.generate_md(path),
        }
    }
    
    /// Generate a text report
    fn generate_txt(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("Failed to create report file: {:?}", path))?;
            
        // Write header
        writeln!(file, "=== {} ===", self.title)?;
        writeln!(file, "Generated: {}", self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"))?;
        writeln!(file, "Results: {}", self.results.len())?;
        writeln!(file)?;
        
        // Write summary
        let successful = self.results.iter().filter(|r| r.success).count();
        let failed = self.results.len() - successful;
        
        writeln!(file, "Summary:")?;
        writeln!(file, "- Total attempts: {}", self.results.len())?;
        writeln!(file, "- Successful attempts: {}", successful)?;
        writeln!(file, "- Failed attempts: {}", failed)?;
        writeln!(file)?;
        
        // Group by target
        let mut targets: HashMap<String, Vec<&AttackResult>> = HashMap::new();
        for result in &self.results {
            let key = format!("{}:{} ({})", result.target, result.port, result.protocol);
            targets.entry(key).or_default().push(result);
        }
        
        // Write details
        writeln!(file, "Details:")?;
        for (target, results) in targets {
            writeln!(file, "\n[{}]", target)?;
            
            // Write successful credentials
            let successes: Vec<_> = results.iter().filter(|r| r.success).collect();
            if !successes.is_empty() {
                writeln!(file, "Successful credentials:")?;
                for result in successes {
                    writeln!(file, "- Username: {}, Password: {}", result.username, result.password)?;
                }
            } else {
                writeln!(file, "No successful credentials found.")?;
            }
        }
        
        Ok(())
    }
    
    /// Generate a JSON report
    fn generate_json(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create report file: {:?}", path))?;
            
        serde_json::to_writer_pretty(file, &self)?;
        
        Ok(())
    }
    
    /// Generate a CSV report
    fn generate_csv(&self, path: &Path) -> Result<()> {
        let mut writer = csv::Writer::from_path(path)
            .with_context(|| format!("Failed to create CSV report file: {:?}", path))?;
            
        // Write header
        writer.write_record(&[
            "Target", "Port", "Protocol", "Username", "Password", 
            "Success", "Error", "Timestamp"
        ])?;
        
        // Write results
        for result in &self.results {
            writer.write_record(&[
                &result.target,
                &result.port.to_string(),
                &result.protocol.to_string(),
                &result.username,
                &result.password,
                &result.success.to_string(),
                &result.error.as_deref().unwrap_or(""),
                &result.timestamp.to_rfc3339(),
            ])?;
        }
        
        writer.flush()?;
        
        Ok(())
    }
    
    /// Generate an HTML report
    fn generate_html(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("Failed to create report file: {:?}", path))?;
            
        // Group by target
        let mut targets: HashMap<String, Vec<&AttackResult>> = HashMap::new();
        for result in &self.results {
            let key = format!("{}:{} ({})", result.target, result.port, result.protocol);
            targets.entry(key).or_default().push(result);
        }
        
        // Write header
        write!(file, r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .target {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}
        .target h3 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr.success {{ background-color: #d4edda; }}
        tr.failure {{ background-color: #f8d7da; }}
    </style>
</head>
<body>
    <h1>{}</h1>
    <p>Generated: {}</p>

    <div class="summary">
        <h2>Summary</h2>
        <p>Total attempts: {}</p>
        <p>Successful attempts: {}</p>
        <p>Failed attempts: {}</p>
    </div>
"#, 
            self.title,
            self.title,
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.results.len(),
            self.results.iter().filter(|r| r.success).count(),
            self.results.len() - self.results.iter().filter(|r| r.success).count()
        )?;
        
        // Write targets
        for (target, results) in targets {
            write!(file, r#"
    <div class="target">
        <h3>{}</h3>
"#, 
                target
            )?;
            
            // Write successful credentials
            let successes: Vec<_> = results.iter().filter(|r| r.success).collect();
            if !successes.is_empty() {
                write!(file, r#"
        <h4>Successful credentials ({})</h4>
        <table>
            <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Timestamp</th>
            </tr>
"#, 
                    successes.len()
                )?;
                
                for result in successes {
                    write!(file, r#"
            <tr class="success">
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
"#, 
                        result.username,
                        result.password,
                        result.timestamp.format("%Y-%m-%d %H:%M:%S")
                    )?;
                }
                
                write!(file, r#"
        </table>
"#
                )?;
            } else {
                write!(file, r#"
        <p>No successful credentials found.</p>
"#
                )?;
            }
            
            write!(file, r#"
    </div>
"#
            )?;
        }
        
        // Write footer
        write!(file, r#"
</body>
</html>
"#
        )?;
        
        Ok(())
    }
    
    /// Generate a Markdown report
    fn generate_md(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("Failed to create report file: {:?}", path))?;
            
        // Write header
        writeln!(file, "# {}", self.title)?;
        writeln!(file, "Generated: {}", self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"))?;
        writeln!(file)?;
        
        // Write summary
        let successful = self.results.iter().filter(|r| r.success).count();
        let failed = self.results.len() - successful;
        
        writeln!(file, "## Summary")?;
        writeln!(file, "- Total attempts: {}", self.results.len())?;
        writeln!(file, "- Successful attempts: {}", successful)?;
        writeln!(file, "- Failed attempts: {}", failed)?;
        writeln!(file)?;
        
        // Group by target
        let mut targets: HashMap<String, Vec<&AttackResult>> = HashMap::new();
        for result in &self.results {
            let key = format!("{}:{} ({})", result.target, result.port, result.protocol);
            targets.entry(key).or_default().push(result);
        }
        
        // Write details
        writeln!(file, "## Details")?;
        for (target, results) in targets {
            writeln!(file, "\n### {}", target)?;
            
            // Write successful credentials
            let successes: Vec<_> = results.iter().filter(|r| r.success).collect();
            if !successes.is_empty() {
                writeln!(file, "#### Successful credentials")?;
                writeln!(file, "| Username | Password | Timestamp |")?;
                writeln!(file, "|----------|----------|-----------|")?;
                
                for result in successes {
                    writeln!(
                        file, 
                        "| {} | {} | {} |",
                        result.username,
                        result.password,
                        result.timestamp.format("%Y-%m-%d %H:%M:%S")
                    )?;
                }
            } else {
                writeln!(file, "No successful credentials found.")?;
            }
        }
        
        Ok(())
    }
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