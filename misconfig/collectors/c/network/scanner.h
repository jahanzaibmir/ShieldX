/**
 * scanner.h - Enhanced network scanning and analysis
 */

#ifndef SHIELDX_NETWORK_SCANNER_H
#define SHIELDX_NETWORK_SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include "../core/config.h"

#define MAX_INTERFACES 32
#define MAX_PORTS 65535
#define MAX_PROCESSES 1024

// Network interface information
typedef struct {
    char name[256];
    char description[512];
    char mac_address[18];
    char ipv4_address[16];
    char ipv6_address[64];
    char gateway[16];
    char dns_servers[4][16];
    int dns_count;
    bool is_up;
    bool is_wireless;
    char wifi_ssid[128];
    char wifi_encryption[32];
    int wifi_signal_strength;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} network_interface_t;

// Port scan result
typedef struct {
    uint16_t port;
    char protocol[8];
    char state[16];
    char service[64];
    char binding[16];
    char process_name[256];
    int pid;
    char user[64];
    bool is_encrypted;
    char encryption_type[32];
    char risk_level[16];
} port_info_t;

// Active connection
typedef struct {
    char local_addr[16];
    uint16_t local_port;
    char remote_addr[16];
    uint16_t remote_port;
    char protocol[8];
    char state[16];
    char process_name[256];
    int pid;
    bool is_established;
    bool is_suspicious;
    char geo_location[64];
} connection_t;

// Network finding for risk assessment
typedef struct {
    char type[64];
    uint16_t port;
    char protocol[8];
    char service[64];
    char binding[16];
    char state[16];
    char process_name[256];
    int pid;
    char risk_level[16];
    char description[512];
    char recommendation[512];
} network_finding_t;

// Complete network scan result
typedef struct {
    network_interface_t interfaces[MAX_INTERFACES];
    int interface_count;
    
    port_info_t *open_ports;
    int open_port_count;
    
    connection_t *active_connections;
    int connection_count;
    
    network_finding_t *findings;
    size_t finding_count;
    
    bool firewall_enabled;
    char firewall_status[256];
    
    int scan_duration_ms;
} network_scan_result_t;

// Main scanning functions
network_scan_result_t* scan_network(const config_t *config);
void free_network_results(network_scan_result_t *results);

// Individual scan functions
int enumerate_interfaces(network_interface_t *interfaces, int max_count);
int scan_open_ports(port_info_t **ports, int *count);
int get_active_connections(connection_t **connections, int *count);
int check_firewall_status(char *status, size_t status_len);

// Analysis functions
bool is_port_risky(uint16_t port, const char *binding, const char *service);
bool is_connection_suspicious(const connection_t *conn);
void analyze_network_security(network_scan_result_t *results);

#endif // SHIELDX_NETWORK_SCANNER_H