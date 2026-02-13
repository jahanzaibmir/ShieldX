/**
 * scanner.c - FIXED VERSION with proper firewall detection and port scanning
 */

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scanner.h"
#include "../core/logger.h"

// Known risky ports
static const uint16_t RISKY_PORTS[] = {
    21,    // FTP
    23,    // Telnet
    69,    // TFTP
    135,   // RPC
    139,   // NetBIOS
    445,   // SMB
    1433,  // MSSQL
    3306,  // MySQL
    3389,  // RDP
    5900,  // VNC
};

// Service name mapping
static const struct {
    uint16_t port;
    const char *service;
    bool requires_encryption;
} SERVICE_MAP[] = {
    {20, "ftp-data", false},
    {21, "ftp", false},
    {22, "ssh", true},
    {23, "telnet", false},
    {25, "smtp", false},
    {53, "dns", false},
    {80, "http", false},
    {110, "pop3", false},
    {143, "imap", false},
    {443, "https", true},
    {445, "microsoft-ds", false},
    {465, "smtps", true},
    {587, "smtp-submission", false},
    {993, "imaps", true},
    {995, "pop3s", true},
    {1433, "mssql", false},
    {3306, "mysql", false},
    {3389, "rdp", true},
    {5432, "postgresql", false},
    {5900, "vnc", false},
    {8080, "http-alt", false},
    {8443, "https-alt", true},
};

// Get process name from PID
static bool get_process_name(DWORD pid, char *name, size_t name_len) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                strncpy_s(name, name_len, pe32.szExeFile, _TRUNCATE);
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return false;
}

// Get service name for port
static const char* get_service_name(uint16_t port) {
    for (size_t i = 0; i < sizeof(SERVICE_MAP) / sizeof(SERVICE_MAP[0]); i++) {
        if (SERVICE_MAP[i].port == port) {
            return SERVICE_MAP[i].service;
        }
    }
    return "unknown";
}

// Check if port requires encryption
static bool requires_encryption(uint16_t port) {
    for (size_t i = 0; i < sizeof(SERVICE_MAP) / sizeof(SERVICE_MAP[0]); i++) {
        if (SERVICE_MAP[i].port == port) {
            return SERVICE_MAP[i].requires_encryption;
        }
    }
    return false;
}

// Enumerate network interfaces
int enumerate_interfaces(network_interface_t *interfaces, int max_count) {
    log_debug("Enumerating network interfaces...");
    
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = malloc(buffer_size);
    
    if (GetAdaptersAddresses(AF_UNSPEC, 
                            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                            NULL, adapter_addresses, &buffer_size) != ERROR_SUCCESS) {
        free(adapter_addresses);
        log_error("Failed to get adapter addresses");
        return 0;
    }
    
    int count = 0;
    PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
    
    while (adapter && count < max_count) {
        network_interface_t *iface = &interfaces[count];
        memset(iface, 0, sizeof(network_interface_t));
        
        // Name and description
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, 
                           iface->name, sizeof(iface->name), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, adapter->Description, -1,
                           iface->description, sizeof(iface->description), NULL, NULL);
        
        // MAC address
        if (adapter->PhysicalAddressLength == 6) {
            sprintf_s(iface->mac_address, sizeof(iface->mac_address),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     adapter->PhysicalAddress[0], adapter->PhysicalAddress[1],
                     adapter->PhysicalAddress[2], adapter->PhysicalAddress[3],
                     adapter->PhysicalAddress[4], adapter->PhysicalAddress[5]);
        }
        
        // Status
        iface->is_up = (adapter->OperStatus == IfOperStatusUp);
        iface->is_wireless = (adapter->IfType == IF_TYPE_IEEE80211);
        
        // IP addresses
        PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
        while (unicast) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
                inet_ntop(AF_INET, &addr->sin_addr, iface->ipv4_address, 
                         sizeof(iface->ipv4_address));
            } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
                inet_ntop(AF_INET6, &addr->sin6_addr, iface->ipv6_address,
                         sizeof(iface->ipv6_address));
            }
            unicast = unicast->Next;
        }
        
        // Gateway
        PIP_ADAPTER_GATEWAY_ADDRESS gateway = adapter->FirstGatewayAddress;
        if (gateway && gateway->Address.lpSockaddr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in*)gateway->Address.lpSockaddr;
            inet_ntop(AF_INET, &addr->sin_addr, iface->gateway, sizeof(iface->gateway));
        }
        
        // Statistics
        MIB_IF_ROW2 if_row;
        memset(&if_row, 0, sizeof(MIB_IF_ROW2));
        if_row.InterfaceIndex = adapter->IfIndex;
        if (GetIfEntry2(&if_row) == NO_ERROR) {
            iface->bytes_sent = if_row.OutOctets;
            iface->bytes_received = if_row.InOctets;
        }
        
        count++;
        adapter = adapter->Next;
    }
    
    free(adapter_addresses);
    log_info("Found %d network interfaces", count);
    return count;
}

// Scan for open ports using GetExtendedTcpTable
int scan_open_ports(port_info_t **ports, int *count) {
    log_debug("Scanning open ports...");
    
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    PMIB_TCPTABLE_OWNER_PID tcp_table = malloc(size);
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, 
                           TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tcp_table);
        log_error("Failed to get TCP table");
        return -1;
    }
    
    // Allocate port array
    *ports = calloc(tcp_table->dwNumEntries, sizeof(port_info_t));
    *count = 0;
    
    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];
        
        // Only include listening ports
        if (row->dwState != MIB_TCP_STATE_LISTEN) {
            continue;
        }
        
        port_info_t *port = &(*ports)[*count];
        
        port->port = ntohs((uint16_t)row->dwLocalPort);
        strcpy_s(port->protocol, sizeof(port->protocol), "tcp");
        strcpy_s(port->state, sizeof(port->state), "listening");
        
        // Service name
        const char *service = get_service_name(port->port);
        strcpy_s(port->service, sizeof(port->service), service);
        
        // Binding address
        struct in_addr addr;
        addr.S_un.S_addr = row->dwLocalAddr;
        inet_ntop(AF_INET, &addr, port->binding, sizeof(port->binding));
        
        // Process info
        port->pid = (int)row->dwOwningPid;
        get_process_name(row->dwOwningPid, port->process_name, sizeof(port->process_name));
        
        // Encryption detection
        port->is_encrypted = requires_encryption(port->port);
        if (port->is_encrypted) {
            strcpy_s(port->encryption_type, sizeof(port->encryption_type), "TLS");
        }
        
        // Risk assessment
        if (is_port_risky(port->port, port->binding, port->service)) {
            strcpy_s(port->risk_level, sizeof(port->risk_level), "high");
        } else if (strcmp(port->binding, "0.0.0.0") == 0) {
            strcpy_s(port->risk_level, sizeof(port->risk_level), "medium");
        } else {
            strcpy_s(port->risk_level, sizeof(port->risk_level), "low");
        }
        
        (*count)++;
    }
    
    free(tcp_table);
    log_info("Found %d listening ports", *count);
    return 0;
}

// Get active connections
int get_active_connections(connection_t **connections, int *count) {
    log_debug("Getting active connections...");
    
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    PMIB_TCPTABLE_OWNER_PID tcp_table = malloc(size);
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET,
                           TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tcp_table);
        return -1;
    }
    
    *connections = calloc(tcp_table->dwNumEntries, sizeof(connection_t));
    *count = 0;
    
    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];
        
        // Skip listening ports
        if (row->dwState == MIB_TCP_STATE_LISTEN) {
            continue;
        }
        
        connection_t *conn = &(*connections)[*count];
        
        // Local address
        struct in_addr local_addr;
        local_addr.S_un.S_addr = row->dwLocalAddr;
        inet_ntop(AF_INET, &local_addr, conn->local_addr, sizeof(conn->local_addr));
        conn->local_port = ntohs((uint16_t)row->dwLocalPort);
        
        // Remote address
        struct in_addr remote_addr;
        remote_addr.S_un.S_addr = row->dwRemoteAddr;
        inet_ntop(AF_INET, &remote_addr, conn->remote_addr, sizeof(conn->remote_addr));
        conn->remote_port = ntohs((uint16_t)row->dwRemotePort);
        
        strcpy_s(conn->protocol, sizeof(conn->protocol), "tcp");
        
        // State
        switch (row->dwState) {
            case MIB_TCP_STATE_ESTAB:
                strcpy_s(conn->state, sizeof(conn->state), "established");
                conn->is_established = true;
                break;
            case MIB_TCP_STATE_SYN_SENT:
                strcpy_s(conn->state, sizeof(conn->state), "syn_sent");
                break;
            case MIB_TCP_STATE_SYN_RCVD:
                strcpy_s(conn->state, sizeof(conn->state), "syn_received");
                break;
            case MIB_TCP_STATE_TIME_WAIT:
                strcpy_s(conn->state, sizeof(conn->state), "time_wait");
                break;
            default:
                strcpy_s(conn->state, sizeof(conn->state), "unknown");
        }
        
        // Process info
        conn->pid = (int)row->dwOwningPid;
        get_process_name(row->dwOwningPid, conn->process_name, sizeof(conn->process_name));
        
        // Suspicious connection detection
        conn->is_suspicious = is_connection_suspicious(conn);
        
        (*count)++;
    }
    
    free(tcp_table);
    log_info("Found %d active connections", *count);
    return 0;
}

// *** FIXED FIREWALL DETECTION ***
int check_firewall_status(char *status, size_t status_len) {
    log_debug("Checking firewall status...");
    
    // Use netsh to check firewall status
    FILE *pipe = _popen("netsh advfirewall show allprofiles state", "r");
    if (!pipe) {
        log_error("Failed to execute netsh command");
        strncpy_s(status, status_len, "Unknown", _TRUNCATE);
        return -1;
    }
    
    char buffer[512];
    bool domain_on = false, private_on = false, public_on = false;
    char current_profile[64] = "";
    
    while (fgets(buffer, sizeof(buffer), pipe)) {
        // Trim whitespace
        char *line = buffer;
        while (*line == ' ' || *line == '\t') line++;
        
        // Check which profile we're in
        if (strstr(line, "Domain Profile")) {
            strcpy_s(current_profile, sizeof(current_profile), "domain");
        } else if (strstr(line, "Private Profile")) {
            strcpy_s(current_profile, sizeof(current_profile), "private");
        } else if (strstr(line, "Public Profile")) {
            strcpy_s(current_profile, sizeof(current_profile), "public");
        }
        
        // Check if State is ON for current profile
        if (strstr(line, "State") && strstr(line, "ON")) {
            if (strcmp(current_profile, "domain") == 0) {
                domain_on = true;
                log_debug("Domain Profile firewall: ON");
            } else if (strcmp(current_profile, "private") == 0) {
                private_on = true;
                log_debug("Private Profile firewall: ON");
            } else if (strcmp(current_profile, "public") == 0) {
                public_on = true;
                log_debug("Public Profile firewall: ON");
            }
        }
    }
    
    _pclose(pipe);
    
    // Determine overall status
    if (domain_on && private_on && public_on) {
        strncpy_s(status, status_len, "Enabled (all profiles)", _TRUNCATE);
        log_info("Firewall Status: Enabled on all profiles");
        return 1;  // Fully enabled
    } else if (domain_on || private_on || public_on) {
        snprintf(status, status_len, "Partially enabled (D:%s P:%s Pub:%s)",
                domain_on ? "ON" : "OFF",
                private_on ? "ON" : "OFF",
                public_on ? "ON" : "OFF");
        log_warn("Firewall Status: Partially enabled");
        return 0;  // Partially enabled = NOT fully enabled
    } else {
        strncpy_s(status, status_len, "Disabled", _TRUNCATE);
        log_error("Firewall Status: DISABLED on all profiles!");
        return 0;  // Disabled
    }
}

// *** FIXED PORT RISK ASSESSMENT ***
bool is_port_risky(uint16_t port, const char *binding, const char *service) {
    // First check: Is it in the known risky ports list?
    bool is_known_risky = false;
    for (size_t i = 0; i < sizeof(RISKY_PORTS) / sizeof(RISKY_PORTS[0]); i++) {
        if (port == RISKY_PORTS[i]) {
            is_known_risky = true;
            break;
        }
    }
    
    // If it's a known risky port, it's ALWAYS risky
    if (is_known_risky) {
        log_debug("Port %d is in risky ports list", port);
        return true;
    }
    
    // Additional risk: Unencrypted services on all interfaces
    if (strcmp(binding, "0.0.0.0") == 0 && !requires_encryption(port)) {
        if (strcmp(service, "http") == 0 || strcmp(service, "ftp") == 0 ||
            strcmp(service, "telnet") == 0 || strcmp(service, "smtp") == 0) {
            log_debug("Port %d is unencrypted service on 0.0.0.0", port);
            return true;
        }
    }
    
    return false;
}

// Check if connection is suspicious
bool is_connection_suspicious(const connection_t *conn) {
    // Check for connections to unusual ports
    if (conn->remote_port > 50000 && conn->remote_port < 60000) {
        return true;
    }
    
    // Check for connections from system processes to external IPs
    if (strstr(conn->process_name, "svchost.exe") ||
        strstr(conn->process_name, "System")) {
        // If remote is not local/private IP
        if (strncmp(conn->remote_addr, "192.168.", 8) != 0 &&
            strncmp(conn->remote_addr, "10.", 3) != 0 &&
            strncmp(conn->remote_addr, "172.16.", 7) != 0 &&
            strncmp(conn->remote_addr, "127.", 4) != 0) {
            return true;
        }
    }
    
    return false;
}

// Analyze network security and generate findings
void analyze_network_security(network_scan_result_t *results) {
    log_debug("Analyzing network security...");
    
    size_t finding_capacity = 100;
    results->findings = calloc(finding_capacity, sizeof(network_finding_t));
    results->finding_count = 0;
    
    // Check firewall status
    if (!results->firewall_enabled) {
        network_finding_t *f = &results->findings[results->finding_count++];
        strcpy_s(f->type, sizeof(f->type), "firewall_disabled");
        strcpy_s(f->risk_level, sizeof(f->risk_level), "critical");
        strcpy_s(f->description, sizeof(f->description), 
                "Network firewall is disabled or partially disabled");
        strcpy_s(f->recommendation, sizeof(f->recommendation),
                "Enable Windows Firewall on all network profiles");
        log_warn("CRITICAL: Firewall is not fully enabled!");
    }
    
    // Analyze open ports - ONLY add risky ones to findings
    for (int i = 0; i < results->open_port_count; i++) {
        port_info_t *port = &results->open_ports[i];
        
        // Only create findings for HIGH risk ports
        if (strcmp(port->risk_level, "high") == 0) {
            network_finding_t *f = &results->findings[results->finding_count++];
            strcpy_s(f->type, sizeof(f->type), "risky_port");
            f->port = port->port;
            strcpy_s(f->protocol, sizeof(f->protocol), port->protocol);
            strcpy_s(f->service, sizeof(f->service), port->service);
            strcpy_s(f->binding, sizeof(f->binding), port->binding);
            strcpy_s(f->state, sizeof(f->state), port->state);
            strcpy_s(f->process_name, sizeof(f->process_name), port->process_name);
            f->pid = port->pid;
            strcpy_s(f->risk_level, sizeof(f->risk_level), "high");
            sprintf_s(f->description, sizeof(f->description),
                     "Port %d (%s) is listening on %s", 
                     port->port, port->service, port->binding);
            strcpy_s(f->recommendation, sizeof(f->recommendation),
                    "Consider restricting this service or using a firewall rule");
            log_info("Found risky port: %d (%s) on %s", port->port, port->service, port->binding);
        }
    }
    
    // Analyze suspicious connections
    for (int i = 0; i < results->connection_count; i++) {
        connection_t *conn = &results->active_connections[i];
        
        if (conn->is_suspicious) {
            network_finding_t *f = &results->findings[results->finding_count++];
            strcpy_s(f->type, sizeof(f->type), "suspicious_connection");
            strcpy_s(f->process_name, sizeof(f->process_name), conn->process_name);
            f->pid = conn->pid;
            f->port = conn->remote_port;
            strcpy_s(f->risk_level, sizeof(f->risk_level), "medium");
            sprintf_s(f->description, sizeof(f->description),
                     "Suspicious connection from %s to %s:%d",
                     conn->process_name, conn->remote_addr, conn->remote_port);
            strcpy_s(f->recommendation, sizeof(f->recommendation),
                    "Investigate this connection and verify the process is legitimate");
        }
    }
    
    log_info("Network security analysis complete: %zu findings", results->finding_count);
}

// Main network scan function
network_scan_result_t* scan_network(const config_t *config) {
    log_info("Starting comprehensive network scan...");
    
    // Suppress unused parameter warning
    (void)config;
    
    DWORD start_time = GetTickCount();
    
    network_scan_result_t *results = calloc(1, sizeof(network_scan_result_t));
    
    // Enumerate interfaces
    results->interface_count = enumerate_interfaces(results->interfaces, MAX_INTERFACES);
    
    // Scan ports
    scan_open_ports(&results->open_ports, &results->open_port_count);
    
    // Get connections
    get_active_connections(&results->active_connections, &results->connection_count);
    
    // Check firewall
    results->firewall_enabled = 
        (check_firewall_status(results->firewall_status, 
                              sizeof(results->firewall_status)) > 0);
    
    log_info("Firewall check result: %s (enabled=%d)", 
             results->firewall_status, results->firewall_enabled);
    
    // Analyze security
    analyze_network_security(results);
    
    results->scan_duration_ms = GetTickCount() - start_time;
    
    log_info("Network scan completed in %d ms", results->scan_duration_ms);
    log_info("Summary: %d interfaces, %d ports, %d connections, %zu findings",
             results->interface_count, results->open_port_count, 
             results->connection_count, results->finding_count);
    
    return results;
}

// Free network results
void free_network_results(network_scan_result_t *results) {
    if (!results) return;
    
    free(results->open_ports);
    free(results->active_connections);
    free(results->findings);
    free(results);
}

#endif // _WIN32