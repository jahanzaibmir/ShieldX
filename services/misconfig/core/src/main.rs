use std::fs;
use serde_json::{json, Value};

fn main() {
    // Load raw probe output
    let raw = fs::read_to_string("raw_probe_output.json")
        .expect("Failed to read raw_probe_output.json");

    let parsed: Value = serde_json::from_str(&raw)
        .expect("Invalid JSON");

    // OWNED fallbacks (this fixes your error)
    let empty_vec: Vec<Value> = Vec::new();

    let firewall = parsed.get("firewall").and_then(|v| v.as_array()).unwrap_or(&empty_vec);
    let ports    = parsed.get("ports").and_then(|v| v.as_array()).unwrap_or(&empty_vec);
    let networks = parsed.get("networks").and_then(|v| v.as_array()).unwrap_or(&empty_vec);
    let admins   = parsed.get("admins").and_then(|v| v.as_array()).unwrap_or(&empty_vec);

    let mut findings = Vec::new();
    let mut risk_score = 0;

    // ===============================
    // CRITICAL: SMB EXPOSURE
    // ===============================
    for p in ports {
        let port = p.get("Port").and_then(|v| v.as_i64()).unwrap_or(0);
        let addr = p.get("Address").and_then(|v| v.as_str()).unwrap_or("");

        if port == 445 && addr != "127.0.0.1" && addr != "::1" {
            findings.push(json!({
                "severity": "CRITICAL",
                "title": "SMB service exposed to network",
                "category": "Network Exposure",
                "confidence": 0.96,
                "details": {
                    "port": 445,
                    "address": addr,
                    "process": p.get("Process")
                },
                "attack_path": [
                    "SMB enumeration",
                    "NTLM relay",
                    "Lateral movement",
                    "Domain compromise"
                ],
                "remediation": [
                    "Block TCP 445 on public interfaces",
                    "Restrict SMB to trusted subnets"
                ]
            }));
            risk_score += 25;
        }
    }

    // ===============================
    // HIGH: RPC PORT BLAST RADIUS
    // ===============================
    let rpc_exposed = ports.iter().filter(|p| {
        let port = p.get("Port").and_then(|v| v.as_i64()).unwrap_or(0);
        let addr = p.get("Address").and_then(|v| v.as_str()).unwrap_or("");
        (49664..=49669).contains(&port) && (addr == "0.0.0.0" || addr == "::")
    }).count();

    if rpc_exposed >= 3 {
        findings.push(json!({
            "severity": "HIGH",
            "title": "RPC dynamic ports exposed",
            "category": "Remote Attack Surface",
            "confidence": 0.91,
            "details": {
                "port_range": "49664-49669",
                "count": rpc_exposed
            },
            "attack_path": [
                "RPC enumeration",
                "Service abuse",
                "Privilege escalation"
            ],
            "remediation": [
                "Restrict RPC ports via firewall",
                "Limit access to internal networks only"
            ]
        }));
        risk_score += 18;
    }

    // ===============================
    // MEDIUM: IPv6 SHADOW ATTACK SURFACE
    // ===============================
    let ipv6_enabled = networks.iter().any(|n| {
        n.get("IPAddress")
            .and_then(|v| v.as_str())
            .map(|ip| ip.contains(":"))
            .unwrap_or(false)
    });

    if ipv6_enabled {
        findings.push(json!({
            "severity": "MEDIUM",
            "title": "IPv6 attack surface detected",
            "category": "Firewall Bypass Risk",
            "confidence": 0.88,
            "details": {
                "ipv6": "enabled"
            },
            "attack_path": [
                "IPv6 exposure",
                "Firewall rule bypass",
                "Hidden service access"
            ],
            "remediation": [
                "Mirror IPv4 firewall rules to IPv6",
                "Disable IPv6 if not required"
            ]
        }));
        risk_score += 12;
    }

    // ===============================
    // MEDIUM: ADMIN PRIVILEGE SPRAWL
    // ===============================
    if admins.len() > 1 {
        findings.push(json!({
            "severity": "MEDIUM",
            "title": "Multiple local administrators detected",
            "category": "Privilege Sprawl",
            "confidence": 0.85,
            "details": {
                "admin_count": admins.len()
            },
            "attack_path": [
                "Credential theft",
                "Privilege abuse",
                "Persistence"
            ],
            "remediation": [
                "Reduce admin accounts",
                "Apply least privilege principle"
            ]
        }));
        risk_score += 10;
    }

    // ===============================
    // CRITICAL: FIREWALL STATUS
    // ===============================
    let firewall_disabled = firewall.iter().any(|f| {
        f.get("Enabled").and_then(|v| v.as_i64()).unwrap_or(1) == 0
    });

    if firewall_disabled {
        findings.push(json!({
            "severity": "CRITICAL",
            "title": "Firewall profile disabled",
            "category": "Host Protection Failure",
            "confidence": 0.99,
            "remediation": [
                "Enable all firewall profiles immediately"
            ]
        }));
        risk_score += 30;
    }

    // ===============================
    // FINAL REPORT
    // ===============================
    let report = json!({
        "meta": {
            "engine": "ShieldX Misconfig Finder",
            "version": "1.0.0",
            "risk_score": risk_score.min(100)
        },
        "summary": {
            "critical": findings.iter().filter(|f| f["severity"] == "CRITICAL").count(),
            "high": findings.iter().filter(|f| f["severity"] == "HIGH").count(),
            "medium": findings.iter().filter(|f| f["severity"] == "MEDIUM").count(),
            "low": findings.iter().filter(|f| f["severity"] == "LOW").count()
        },
        "findings": findings
    });

    fs::write(
        "misconfig_report.json",
        serde_json::to_string_pretty(&report).unwrap()
    ).expect("Failed to write report");

    println!(
        "🔥 Misconfig scan completed — RISK SCORE: {}",
        report["meta"]["risk_score"]
    );
}
