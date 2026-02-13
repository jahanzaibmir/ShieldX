/**
 * Data Models for ShieldX Engine
 */

use serde::{Deserialize, Serialize};

// Input from C Collector
#[derive(Debug, Deserialize)]
pub struct CollectorData {
    pub collector: String,
    pub timestamp: i64,
    pub interfaces: Vec<NetworkInterface>,
    pub findings: Vec<CollectorFinding>,
    pub metadata: Metadata,
}

#[derive(Debug, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub mac: String,
    pub ipv4: String,
    pub ipv6: String,
    pub gateway: String,
    pub is_up: bool,
    pub is_wireless: bool,
}

#[derive(Debug, Deserialize)]
pub struct CollectorFinding {
    #[serde(rename = "type")]
    pub finding_type: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub binding: String,
    pub state: String,
    pub process: String,
    pub pid: i32,
    pub risk_level: String,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub scan_duration_ms: u32,
    pub interfaces_found: u32,
    pub open_ports: u32,
    pub active_connections: u32,
    pub firewall_enabled: bool,
}

// Analysis Output
#[derive(Debug, Serialize)]
pub struct SecurityReport {
    pub risk_index: f32,
    pub posture: String,
    pub summary: FindingSummary,
    pub findings: Vec<AnalyzedFinding>,
    pub recommendations: Vec<Recommendation>,
    pub compliance: ComplianceStatus,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Serialize)]
pub struct FindingSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Serialize)]
pub struct AnalyzedFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub reasoning: String,
    pub affected_asset: String,
    pub remediation: String,
    pub cvss_score: f32,
    pub attack_vector: String,
    pub exploitability: String,
}

#[derive(Debug, Serialize)]
pub struct Recommendation {
    pub priority: u32,
    pub action: String,
    pub rationale: String,
    pub impact: String,
}

#[derive(Debug, Serialize)]
pub struct ComplianceStatus {
    pub cis_score: f32,
    pub nist_score: f32,
    pub pci_dss_compliant: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportMetadata {
    pub scan_timestamp: i64,
    pub analysis_duration_ms: u128,
    pub engine_version: String,
    pub total_checks: u32,
}
