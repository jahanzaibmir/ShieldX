/**
 * Core Analysis Logic
 */

use crate::models::*;
use crate::scoring;
use std::time::Instant;

pub fn analyze(data: &CollectorData) -> SecurityReport {
    let start = Instant::now();
    
    let mut findings: Vec<AnalyzedFinding> = Vec::new();
    let mut summary = FindingSummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    
    // Analyze firewall status
    if !data.metadata.firewall_enabled {
        let finding = AnalyzedFinding {
            id: "FW-001".to_string(),
            title: "Firewall Disabled".to_string(),
            severity: "CRITICAL".to_string(),
            category: "Network Security".to_string(),
            description: "Windows Firewall is disabled or partially disabled on one or more profiles".to_string(),
            reasoning: "A disabled firewall exposes the system to unauthorized network access, malware propagation, and data exfiltration".to_string(),
            affected_asset: "System-wide".to_string(),
            remediation: "Enable Windows Firewall on all profiles (Domain, Private, Public). Run: netsh advfirewall set allprofiles state on".to_string(),
            cvss_score: 9.1,
            attack_vector: "Network".to_string(),
            exploitability: "High".to_string(),
        };
        summary.critical += 1;
        findings.push(finding);
    }
    
    // Analyze risky ports
    for finding in &data.findings {
        if finding.finding_type == "risky_port" {
            let analyzed = analyze_risky_port(finding);
            match analyzed.severity.as_str() {
                "CRITICAL" => summary.critical += 1,
                "HIGH" => summary.high += 1,
                "MEDIUM" => summary.medium += 1,
                "LOW" => summary.low += 1,
                _ => summary.info += 1,
            }
            findings.push(analyzed);
        }
    }
    
    // Analyze suspicious connections
    let mut suspicious_count = 0;
    for finding in &data.findings {
        if finding.finding_type == "suspicious_connection" {
            suspicious_count += 1;
        }
    }
    
    if suspicious_count > 0 {
        let severity = if suspicious_count > 50 {
            summary.high += 1;
            "HIGH"
        } else if suspicious_count > 20 {
            summary.medium += 1;
            "MEDIUM"
        } else {
            summary.low += 1;
            "LOW"
        };
        
        let finding = AnalyzedFinding {
            id: "NET-002".to_string(),
            title: format!("{} Suspicious Network Connections Detected", suspicious_count),
            severity: severity.to_string(),
            category: "Network Behavior".to_string(),
            description: format!("Detected {} potentially suspicious outbound connections", suspicious_count),
            reasoning: "Multiple connections from system processes to external IPs or unusual high-numbered ports may indicate data exfiltration, malware C2 communication, or compromised processes".to_string(),
            affected_asset: "Network Layer".to_string(),
            remediation: "Review process legitimacy, check for malware, monitor network traffic patterns, implement egress filtering".to_string(),
            cvss_score: if suspicious_count > 50 { 7.8 } else if suspicious_count > 20 { 5.5 } else { 3.2 },
            attack_vector: "Network".to_string(),
            exploitability: "Medium".to_string(),
        };
        findings.push(finding);
    }
    
    // Analyze network interfaces
    for interface in &data.interfaces {
        if interface.is_wireless && interface.is_up {
            // Check for weak WiFi (this would come from C collector in future)
            // For now, add informational finding
            let finding = AnalyzedFinding {
                id: format!("WIFI-{}", interface.name.replace(" ", "-")),
                title: format!("Wireless Interface Active: {}", interface.name),
                severity: "INFO".to_string(),
                category: "Network Configuration".to_string(),
                description: format!("Wireless interface {} ({}) is active", interface.name, interface.ipv4),
                reasoning: "Active wireless interfaces should use WPA3 or at minimum WPA2 encryption with strong passphrases".to_string(),
                affected_asset: interface.name.clone(),
                remediation: "Verify WiFi security: Ensure WPA2/WPA3 is enabled, disable WPS, use strong passphrase (20+ characters)".to_string(),
                cvss_score: 0.0,
                attack_vector: "Adjacent Network".to_string(),
                exploitability: "Low".to_string(),
            };
            summary.info += 1;
            findings.push(finding);
        }
    }
    
    // Check for publicly exposed services
    let public_services: Vec<_> = data.findings.iter()
        .filter(|f| f.binding == "0.0.0.0" && f.finding_type == "risky_port")
        .collect();
    
    if public_services.len() > 3 {
        let finding = AnalyzedFinding {
            id: "NET-003".to_string(),
            title: format!("{} Services Exposed on All Interfaces", public_services.len()),
            severity: "HIGH".to_string(),
            category: "Attack Surface".to_string(),
            description: format!("{} services are listening on 0.0.0.0, making them accessible from any network interface", public_services.len()),
            reasoning: "Services bound to all interfaces (0.0.0.0) increase attack surface. They should be restricted to localhost (127.0.0.1) or specific interfaces when external access is not required".to_string(),
            affected_asset: "Network Services".to_string(),
            remediation: "Review each service: bind to 127.0.0.1 for local-only services, use firewall rules to restrict access, disable unnecessary services".to_string(),
            cvss_score: 7.3,
            attack_vector: "Network".to_string(),
            exploitability: "High".to_string(),
        };
        summary.high += 1;
        findings.push(finding);
    }
    
    // Generate recommendations
    let recommendations = generate_recommendations(&summary, &data.metadata);
    
    // Calculate compliance
    let compliance = calculate_compliance(&summary, &data.metadata);
    
    // Calculate risk index
    let risk_index = scoring::calculate_risk_index(&summary, &data.metadata);
    let posture = scoring::determine_posture(risk_index);
    
    let duration = start.elapsed();
    
    SecurityReport {
        risk_index,
        posture,
        summary,
        findings,
        recommendations,
        compliance,
        metadata: ReportMetadata {
            scan_timestamp: data.timestamp,
            analysis_duration_ms: duration.as_millis(),
            engine_version: "2.0.0".to_string(),
            total_checks: data.findings.len() as u32,
        },
    }
}

fn analyze_risky_port(finding: &CollectorFinding) -> AnalyzedFinding {
    let (severity, cvss, reasoning, remediation) = match finding.port {
        21 => (
            "HIGH",
            7.5,
            "FTP transmits credentials and data in plaintext, allowing network eavesdropping and man-in-the-middle attacks",
            "Disable FTP. Use SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS) instead"
        ),
        23 => (
            "CRITICAL",
            9.8,
            "Telnet sends all data including passwords in cleartext. Trivially exploitable for credential theft and session hijacking",
            "Disable Telnet immediately. Use SSH for remote access"
        ),
        135 => (
            "HIGH",
            8.1,
            "RPC Endpoint Mapper is frequently targeted for remote code execution exploits (e.g., MS03-026, MS08-067). Should not be exposed externally",
            "Restrict RPC access using Windows Firewall. Block port 135 from external networks. Disable RPC if not needed"
        ),
        139 | 445 => (
            "CRITICAL",
            9.0,
            "SMB/NetBIOS is a primary target for ransomware (WannaCry, NotPetya) and lateral movement attacks. Highly dangerous when exposed to internet",
            "Never expose SMB to internet. Use firewall to restrict to local network only. Disable SMBv1. Consider disabling NetBIOS over TCP/IP"
        ),
        3389 => (
            "HIGH",
            8.8,
            "RDP is frequently brute-forced and exploited (BlueKeep CVE-2019-0708). Common ransomware entry point",
            "Use VPN for remote access. Enable Network Level Authentication. Implement account lockout policies. Use non-standard port. Require strong passwords"
        ),
        5900 => (
            "HIGH",
            7.5,
            "VNC often uses weak authentication and unencrypted connections, allowing session hijacking and credential theft",
            "Use VPN tunnel for VNC. Enable strong authentication. Consider using RDP or SSH tunneling instead"
        ),
        _ => (
            "MEDIUM",
            5.0,
            "Port is exposed on all interfaces",
            "Review if this service needs to be publicly accessible. Restrict to localhost or specific IPs using firewall rules"
        ),
    };
    
    let description = format!("Port {} ({}) is listening on {} - Process: {}", 
                           finding.port, finding.service, finding.binding, finding.process);
    let affected_asset = format!("{}:{}", finding.binding, finding.port);
    
    AnalyzedFinding {
        id: format!("PORT-{}", finding.port),
        title: format!("Risky Port {} ({}) Exposed", finding.port, finding.service),
        severity: severity.to_string(),
        category: "Network Exposure".to_string(),
        description,
        reasoning: reasoning.to_string(),
        affected_asset,
        remediation: remediation.to_string(),
        cvss_score: cvss,
        attack_vector: "Network".to_string(),
        exploitability: "High".to_string(),
    }
}

fn generate_recommendations(summary: &FindingSummary, metadata: &Metadata) -> Vec<Recommendation> {
    let mut recs = Vec::new();
    
    if summary.critical > 0 {
        recs.push(Recommendation {
            priority: 1,
            action: "Address Critical Security Issues Immediately".to_string(),
            rationale: format!("{} critical vulnerabilities require urgent attention to prevent system compromise", summary.critical),
            impact: "Prevents active exploitation and potential data breach".to_string(),
        });
    }
    
    if !metadata.firewall_enabled {
        recs.push(Recommendation {
            priority: 1,
            action: "Enable Windows Firewall on All Profiles".to_string(),
            rationale: "Firewall provides essential network-level protection against unauthorized access".to_string(),
            impact: "Blocks most network-based attacks and limits lateral movement".to_string(),
        });
    }
    
    if summary.high > 0 {
        recs.push(Recommendation {
            priority: 2,
            action: "Review and Secure High-Risk Services".to_string(),
            rationale: format!("{} high-severity issues expose critical attack vectors", summary.high),
            impact: "Significantly reduces attack surface and exploitation risk".to_string(),
        });
    }
    
    recs.push(Recommendation {
        priority: 3,
        action: "Implement Network Segmentation".to_string(),
        rationale: "Isolate critical systems from general network traffic".to_string(),
        impact: "Limits blast radius of potential breaches".to_string(),
    });
    
    recs.push(Recommendation {
        priority: 4,
        action: "Enable Comprehensive Logging and Monitoring".to_string(),
        rationale: "Early detection is critical for incident response".to_string(),
        impact: "Enables threat detection and forensic analysis".to_string(),
    });
    
    recs
}

fn calculate_compliance(summary: &FindingSummary, metadata: &Metadata) -> ComplianceStatus {
    let mut issues = Vec::new();
    
    // CIS Benchmark checks
    let mut cis_violations = 0;
    if !metadata.firewall_enabled {
        issues.push("CIS 9.2.1: Firewall must be enabled".to_string());
        cis_violations += 1;
    }
    if summary.critical > 0 {
        issues.push("CIS 1.1: Critical vulnerabilities present".to_string());
        cis_violations += 1;
    }
    
    let cis_score = ((10.0 - cis_violations as f32) / 10.0 * 100.0).max(0.0);
    
    // NIST Cybersecurity Framework
    let nist_violations = summary.critical + summary.high;
    let nist_score = ((20.0 - nist_violations as f32) / 20.0 * 100.0).max(0.0);
    
    // PCI-DSS (simplified check)
    let pci_compliant = metadata.firewall_enabled && summary.critical == 0;
    
    if !pci_compliant {
        issues.push("PCI-DSS 1.1: Firewall must be configured and enabled".to_string());
    }
    
    ComplianceStatus {
        cis_score,
        nist_score,
        pci_dss_compliant: pci_compliant,
        issues,
    }
}