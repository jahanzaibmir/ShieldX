/**
 * Report Display and Formatting
 */

use crate::models::*;
use colored::Colorize;

pub fn display_report(report: &SecurityReport) {
    println!("\n{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("{}", "                    SECURITY ANALYSIS REPORT                    ".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════\n".cyan());
    
    // Risk Index
    let risk_color = match report.risk_index {
        r if r >= 7.0 => "red",
        r if r >= 5.0 => "yellow",
        r if r >= 3.0 => "blue",
        _ => "green",
    };
    
    println!("{} {}", "Risk Index:".bold(), 
             format!("{:.2}/10.0", report.risk_index).color(risk_color).bold());
    println!("{} {}\n", "Posture:".bold(), report.posture);
    
    // Summary
    println!("{}", "FINDING SUMMARY".bold().underline());
    println!("  {} {} findings", "🔴 Critical:".red().bold(), report.summary.critical);
    println!("  {} {} findings", "🟠 High:    ".yellow().bold(), report.summary.high);
    println!("  {} {} findings", "🟡 Medium:  ".blue().bold(), report.summary.medium);
    println!("  {} {} findings", "🟢 Low:     ".green().bold(), report.summary.low);
    println!("  {} {} findings\n", "ℹ️  Info:    ".white().bold(), report.summary.info);
    
    // Compliance
    println!("{}", "COMPLIANCE STATUS".bold().underline());
    println!("  CIS Benchmark Score:    {:.1}%", report.compliance.cis_score);
    println!("  NIST CSF Score:         {:.1}%", report.compliance.nist_score);
    println!("  PCI-DSS Compliant:      {}", 
             if report.compliance.pci_dss_compliant { "✓ Yes".green() } else { "✗ No".red() });
    
    if !report.compliance.issues.is_empty() {
        println!("\n  {} Compliance Issues:", "⚠️".yellow());
        for issue in &report.compliance.issues {
            println!("    • {}", issue.yellow());
        }
    }
    println!();
    
    // Top Recommendations
    if !report.recommendations.is_empty() {
        println!("{}", "TOP RECOMMENDATIONS".bold().underline());
        for rec in report.recommendations.iter().take(5) {
            println!("\n  {} {}", format!("[Priority {}]", rec.priority).cyan().bold(), rec.action.bold());
            println!("    Rationale: {}", rec.rationale);
            println!("    Impact:    {}", rec.impact.green());
        }
        println!();
    }
    
    // Detailed Findings
    if !report.findings.is_empty() {
        println!("{}", "DETAILED FINDINGS".bold().underline());
        
        // Group by severity
        let critical: Vec<_> = report.findings.iter().filter(|f| f.severity == "CRITICAL").collect();
        let high: Vec<_> = report.findings.iter().filter(|f| f.severity == "HIGH").collect();
        let medium: Vec<_> = report.findings.iter().filter(|f| f.severity == "MEDIUM").collect();
        
        display_findings_group(&critical, "CRITICAL", "red");
        display_findings_group(&high, "HIGH", "yellow");
        display_findings_group(&medium, "MEDIUM", "blue");
    }
    
    // Metadata
    println!("\n{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("Analysis completed in {} ms", report.metadata.analysis_duration_ms);
    println!("Engine Version: {}", report.metadata.engine_version);
    println!("Total Security Checks: {}", report.metadata.total_checks);
    println!("{}", "═══════════════════════════════════════════════════════════════\n".cyan());
}

fn display_findings_group(findings: &[&AnalyzedFinding], severity: &str, color: &str) {
    if findings.is_empty() {
        return;
    }
    
    println!("\n{} {} Severity Findings:", 
             get_severity_icon(severity), 
             severity.color(color).bold());
    
    for finding in findings {
        println!("\n  {} [{}] {}", 
                 "●".color(color), 
                 finding.id.bold(), 
                 finding.title.color(color).bold());
        println!("    Category:     {}", finding.category);
        println!("    Affected:     {}", finding.affected_asset.cyan());
        println!("    CVSS Score:   {}", format_cvss(finding.cvss_score));
        println!("    Description:  {}", finding.description);
        println!("    Reasoning:    {}", finding.reasoning.italic());
        println!("    Remediation:  {}", finding.remediation.green());
    }
}

fn get_severity_icon(severity: &str) -> &str {
    match severity {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        "LOW" => "🟢",
        _ => "ℹ️",
    }
}

fn format_cvss(score: f32) -> colored::ColoredString {
    let score_str = format!("{:.1}", score);
    match score {
        s if s >= 9.0 => score_str.red().bold(),
        s if s >= 7.0 => score_str.red(),
        s if s >= 4.0 => score_str.yellow(),
        _ => score_str.green(),
    }
}

pub fn generate_executive_summary(report: &SecurityReport) -> String {
    format!(
        r#"
EXECUTIVE SUMMARY
=================

Overall Security Posture: {}
Risk Index: {:.2}/10.0

Key Findings:
- {} Critical vulnerabilities requiring immediate attention
- {} High-severity issues needing urgent remediation
- {} Medium-severity concerns to address

Compliance Status:
- CIS Benchmark: {:.1}%
- NIST Framework: {:.1}%
- PCI-DSS: {}

Immediate Actions Required:
{}

This system requires {} to address identified security gaps.
        "#,
        report.posture,
        report.risk_index,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.compliance.cis_score,
        report.compliance.nist_score,
        if report.compliance.pci_dss_compliant { "Compliant" } else { "Non-Compliant" },
        report.recommendations.iter()
            .take(3)
            .map(|r| format!("  • {}", r.action))
            .collect::<Vec<_>>()
            .join("\n"),
        if report.summary.critical > 0 { "IMMEDIATE ACTION" } 
        else if report.summary.high > 0 { "URGENT ATTENTION" }
        else { "timely remediation" }
    )
}
