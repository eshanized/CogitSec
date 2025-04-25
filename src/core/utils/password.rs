use anyhow::{Context, Result};
use std::collections::HashSet;
use chrono::Datelike;

/// Apply word mangling rules to a password
pub fn mangle_password(password: &str, rules: &[MangleRule]) -> Vec<String> {
    let mut result = HashSet::new();
    result.insert(password.to_string());
    
    for rule in rules {
        let mut new_passwords = HashSet::new();
        
        for pwd in &result {
            let mangled = apply_rule(pwd, rule);
            new_passwords.extend(mangled);
        }
        
        result.extend(new_passwords);
    }
    
    result.into_iter().collect()
}

/// Apply a single rule to a password
fn apply_rule(password: &str, rule: &MangleRule) -> Vec<String> {
    match rule {
        MangleRule::Capitalize => {
            if let Some(first_char) = password.chars().next() {
                let capitalized = first_char.to_uppercase().collect::<String>() + &password[first_char.len_utf8()..];
                vec![capitalized]
            } else {
                vec![password.to_string()]
            }
        }
        MangleRule::Uppercase => {
            vec![password.to_uppercase()]
        }
        MangleRule::Lowercase => {
            vec![password.to_lowercase()]
        }
        MangleRule::Reverse => {
            vec![password.chars().rev().collect()]
        }
        MangleRule::Append(suffix) => {
            vec![format!("{}{}", password, suffix)]
        }
        MangleRule::Prepend(prefix) => {
            vec![format!("{}{}", prefix, password)]
        }
        MangleRule::Replace(from, to) => {
            vec![password.replace(from, to)]
        }
        MangleRule::DeleteFirst => {
            if password.is_empty() {
                vec![password.to_string()]
            } else {
                let mut chars = password.chars();
                chars.next();
                vec![chars.collect()]
            }
        }
        MangleRule::DeleteLast => {
            if password.is_empty() {
                vec![password.to_string()]
            } else {
                let mut result = password.to_string();
                result.pop();
                vec![result]
            }
        }
        MangleRule::DuplicateWord => {
            vec![format!("{}{}", password, password)]
        }
        MangleRule::Leetspeak => {
            vec![to_leetspeak(password)]
        }
        MangleRule::AppendDigits => {
            let mut result = Vec::with_capacity(10);
            for i in 0..10 {
                result.push(format!("{}{}", password, i));
            }
            result
        }
        MangleRule::AppendYear => {
            let current_year = chrono::Utc::now().year();
            let mut result = Vec::new();
            
            // Add current year and a few years around it
            for year in (current_year - 5)..=(current_year + 1) {
                result.push(format!("{}{}", password, year));
            }
            
            result
        }
        MangleRule::ToggleCase => {
            let toggled = password.chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("");
                
            vec![toggled]
        }
    }
}

/// Convert a string to leetspeak
fn to_leetspeak(text: &str) -> String {
    text.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '4',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '5',
            't' => '7',
            'l' => '1',
            _ => c,
        })
        .collect()
}

/// Parse mangling rules from a string
pub fn parse_rules(rules_text: &str) -> Result<Vec<MangleRule>> {
    let mut rules = Vec::new();
    
    for (i, line) in rules_text.lines().enumerate() {
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Parse the rule
        match parse_rule(line) {
            Ok(rule) => rules.push(rule),
            Err(err) => {
                return Err(anyhow::anyhow!("Error parsing rule on line {}: {}", i + 1, err));
            }
        }
    }
    
    Ok(rules)
}

/// Parse a single rule from a string
fn parse_rule(rule: &str) -> Result<MangleRule> {
    match rule {
        "c" => Ok(MangleRule::Capitalize),
        "u" => Ok(MangleRule::Uppercase),
        "l" => Ok(MangleRule::Lowercase),
        "r" => Ok(MangleRule::Reverse),
        "d" => Ok(MangleRule::DuplicateWord),
        "$" => Ok(MangleRule::AppendDigits),
        "Y" => Ok(MangleRule::AppendYear),
        "t" => Ok(MangleRule::ToggleCase),
        "L" => Ok(MangleRule::Leetspeak),
        "<" => Ok(MangleRule::DeleteFirst),
        ">" => Ok(MangleRule::DeleteLast),
        _ => {
            // Check for complex rules
            if let Some(char) = rule.chars().next() {
                match char {
                    // Append
                    '$' if rule.len() > 1 => {
                        let suffix = &rule[1..];
                        Ok(MangleRule::Append(suffix.to_string()))
                    }
                    // Prepend
                    '^' if rule.len() > 1 => {
                        let prefix = &rule[1..];
                        Ok(MangleRule::Prepend(prefix.to_string()))
                    }
                    // Replace
                    's' if rule.len() > 2 => {
                        let from = rule.chars().nth(1).unwrap().to_string();
                        let to = rule.chars().nth(2).unwrap_or('_').to_string();
                        Ok(MangleRule::Replace(from, to))
                    }
                    _ => {
                        Err(anyhow::anyhow!("Invalid rule: {}", rule))
                    }
                }
            } else {
                Err(anyhow::anyhow!("Empty rule"))
            }
        }
    }
}

/// Mangling rule
#[derive(Debug, Clone)]
pub enum MangleRule {
    /// Capitalize the first letter
    Capitalize,
    
    /// Convert to uppercase
    Uppercase,
    
    /// Convert to lowercase
    Lowercase,
    
    /// Reverse the string
    Reverse,
    
    /// Append a string
    Append(String),
    
    /// Prepend a string
    Prepend(String),
    
    /// Replace characters
    Replace(String, String),
    
    /// Delete the first character
    DeleteFirst,
    
    /// Delete the last character
    DeleteLast,
    
    /// Duplicate the word
    DuplicateWord,
    
    /// Convert to leetspeak
    Leetspeak,
    
    /// Append digits 0-9
    AppendDigits,
    
    /// Append years (current year +/- a few)
    AppendYear,
    
    /// Toggle case of alternate letters
    ToggleCase,
} 