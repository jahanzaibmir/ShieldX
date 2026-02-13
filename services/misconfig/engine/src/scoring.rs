/**
 * Risk Scoring Engine
 */

use crate::models::*;

pub fn calculate_risk_index(summary: &FindingSummary, metadata: &Metadata) -> f32 {
    let mut risk = 0.0;
    
    // Base scoring from findings
    risk += summary.critical as f32 * 10.0;  // Critical = 10 points each
    risk += summary.high as f32 * 5.0;       // High = 5 points each
    risk += summary.medium as f32 * 2.0;     // Medium = 2 points each
    risk += summary.low as f32 * 0.5;        // Low = 0.5 points each
    
    // Firewall multiplier
    if !metadata.firewall_enabled {
        risk *= 1.5;  // 50% increase if no firewall
    }
    
    // Attack surface factor
    if metadata.open_ports > 20 {
        risk += (metadata.open_ports as f32 - 20.0) * 0.3;
    }
    
    // Connection anomaly factor
    if metadata.active_connections > 100 {
        risk += (metadata.active_connections as f32 - 100.0) * 0.1;
    }
    
    // Normalize to 0-10 scale
    let normalized = (risk / 10.0).min(10.0);
    
    // Round to 2 decimal places
    (normalized * 100.0).round() / 100.0
}

pub fn determine_posture(risk_index: f32) -> String {
    match risk_index {
        r if r >= 9.0 => "🔴 CRITICAL - IMMEDIATE ACTION REQUIRED".to_string(),
        r if r >= 7.0 => "🟠 HIGH RISK - URGENT ATTENTION NEEDED".to_string(),
        r if r >= 5.0 => "🟡 ELEVATED RISK - REMEDIATION RECOMMENDED".to_string(),
        r if r >= 3.0 => "🟢 MODERATE RISK - MONITOR CLOSELY".to_string(),
        r if r >= 1.0 => "🔵 LOW RISK - ACCEPTABLE".to_string(),
        _ => "✅ SECURE - GOOD POSTURE".to_string(),
    }
}

pub fn calculate_cvss_base_score(
    attack_vector: &str,
    attack_complexity: &str,
    privileges_required: &str,
    user_interaction: &str,
    scope: &str,
    confidentiality: &str,
    integrity: &str,
    availability: &str,
) -> f32 {
    // Simplified CVSS v3.1 calculation
    let av = match attack_vector {
        "Network" => 0.85,
        "Adjacent" => 0.62,
        "Local" => 0.55,
        "Physical" => 0.2,
        _ => 0.85,
    };
    
    let ac = match attack_complexity {
        "Low" => 0.77,
        "High" => 0.44,
        _ => 0.77,
    };
    
    let pr = match (privileges_required, scope) {
        ("None", _) => 0.85,
        ("Low", "Unchanged") => 0.62,
        ("Low", "Changed") => 0.68,
        ("High", "Unchanged") => 0.27,
        ("High", "Changed") => 0.50,
        _ => 0.85,
    };
    
    let ui = match user_interaction {
        "None" => 0.85,
        "Required" => 0.62,
        _ => 0.85,
    };
    
    let impact = |metric: &str| match metric {
        "High" => 0.56,
        "Low" => 0.22,
        "None" => 0.0,
        _ => 0.56,
    };
    
    let c = impact(confidentiality);
    let i = impact(integrity);
    let a = impact(availability);
    
    let impact_score = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let exploitability = 8.22 * av * ac * pr * ui;
    
    let base_score = if impact_score <= 0.0 {
        0.0
    } else {
        let impact_term = if scope == "Changed" {
            7.52 * (impact_score - 0.029) - 3.25 * (impact_score - 0.02_f32).powi(15)
        } else {
            6.42 * impact_score
        };
        
        (impact_term + exploitability).min(10.0_f32)
    };
    
    (base_score * 10.0).round() / 10.0
}